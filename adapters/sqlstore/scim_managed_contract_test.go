package sqlstore

import (
	"errors"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/scim"
	"github.com/Plain-Org/plain-auth/schema"
)

// The managed catalog refuses unusable creations, authenticates its tokens
// beside code-defined ones on one handler as managed-bearer principals,
// pages its audit events with another runtime's bounds and attributes each
// event, and exposes no HTTP management route.
func TestSCIMManagedContract(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			ddl, e := schema.Generate(dialect, []string{"scim-managed"})
			must(e)
			s, e := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(e)
			defer s.Close()
			host, e := auth.New(auth.Options{Store: s, Secret: strings.Repeat("x", 32), BaseURL: "https://catalog.test", BasePath: "/identity/custom"})
			must(e)
			observer := &directoryObserver{s, make(chan scim.Principal, 4)}
			h, e := scim.New(host, scim.Options{Store: observer, Connections: []scim.Connection{{Directory: scim.Directory{ID: "code"}, Credentials: []scim.Credential{{ID: "static", Token: "static-token"}}}},
				Managed: &scim.ManagedOptions{CredentialHashSecret: strings.Repeat("managed-local-key-", 3)}})
			must(e)
			catalog := h.Catalog()
			policy := scim.CredentialPolicy{Scopes: []string{scim.UsersRead, scim.UsersWrite}, ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond)}
			invalid := func(e error) bool {
				var se *scim.Error
				return errors.As(e, &se) && se.Status == 400 && se.Type == "invalidValue"
			}
			for _, c := range []struct{ request, actor string }{{"fifteen-chars-1", "owner"}, {"valid-request-0001", ""}} {
				if issued, e := catalog.Create(ctx, "Domain", c.request, c.actor, policy); !invalid(e) || issued.Token != "" {
					t.Fatal("an unusable managed creation was accepted", c, e)
				}
			}
			issued, e := catalog.Create(ctx, "Domain", "valid-request-0001", "owner", policy)
			must(e)
			d := scim.Directory{ID: issued.Connection.ConnectionID, ProvisioningDomainID: "Domain"}
			// The issued connection and credential carry their creation record.
			if c := issued.Connection; c.CreationRequestID != "valid-request-0001" || c.ProvisioningDomainID != "Domain" || c.Status != "active" || c.CreatedBy != "owner" || c.CreatedAt.IsZero() ||
				c.DecommissionStartedAt != nil || c.DecommissionStartedBy != nil || c.DecommissionedAt != nil || c.DecommissionedBy != nil {
				t.Fatal("the issued connection lacks its creation record", c)
			}
			if c := issued.Credential; !slices.Equal(c.Scopes, policy.Scopes) || !c.ExpiresAt.Equal(policy.ExpiresAt) || c.CreatedBy != "owner" || c.Status != "active" || c.RevokedAt != nil {
				t.Fatal("the issued credential lacks its policy or creator", c)
			}
			// A creation request ID is spent across domains.
			if again, e := catalog.Create(ctx, "Other-Domain", "valid-request-0001", "owner", policy); !errors.Is(e, scim.ErrCreationRequestConflict) || again.Token != "" {
				t.Fatal("a spent creation request ID was accepted in another domain", e)
			}
			// Lists name their domain and put the newest connection first.
			if _, e := catalog.List(ctx, ""); !invalid(e) {
				t.Fatal("a list without a domain was accepted", e)
			}
			newer, e := catalog.Create(ctx, "Domain", "valid-request-0002", "owner", policy)
			must(e)
			if list, e := catalog.List(ctx, "Domain"); e != nil || len(list) != 2 || list[0].ConnectionID != newer.Connection.ConnectionID || list[1].ConnectionID != d.ID {
				t.Fatal("the connection list is not newest first", list, e)
			}
			if w := scimRequest(h, "GET", "Users/absent", issued.Token, nil); w.Code != 404 {
				t.Fatal("a managed token was refused", w.Code, w.Body.String())
			}
			if p := <-observer.identity; p.Kind != "managed-bearer" || p.ID != d.ID || p.ProvisioningDomainID != "Domain" || p.CredentialID != issued.Credential.CredentialID ||
				!slices.Equal(p.Scopes, policy.Scopes) || !p.ExpiresAt.Equal(policy.ExpiresAt) {
				t.Fatal("the managed principal lacks its directory, credential, scopes or expiry", p)
			}
			// Code-defined and managed tokens share one handler.
			rotated, e := catalog.Rotate(ctx, d, "operator", policy)
			must(e)
			for _, token := range []string{"static-token", issued.Token, rotated.Token} {
				if w := scimRequest(h, "GET", "Users", token, nil); w.Code != 200 {
					t.Fatal("a token was refused beside the others", w.Code, w.Body.String())
				}
			}
			for len(observer.identity) > 0 {
				<-observer.identity
			}
			// Audit pages take another runtime's bounds and name their actors.
			for _, q := range []scim.EventQuery{{Limit: 101}, {Offset: -1}, {SortDirection: "up"}} {
				if _, e := catalog.Events(ctx, d, q); !invalid(e) {
					t.Fatal("an unusable audit page was accepted", q, e)
				}
			}
			page, e := catalog.Events(ctx, d, scim.EventQuery{})
			must(e)
			if page.Limit != 100 || len(page.Events) == 0 {
				t.Fatal("the default audit page is not 100 events", page.Limit, len(page.Events))
			}
			for _, event := range page.Events {
				switch {
				case event.Type == "connection.created" && (event.ActorID != "owner" || event.CredentialID != nil):
					t.Fatal("the creation event lacks its actor or names a credential", event)
				case strings.HasPrefix(event.Type, "credential.") && event.CredentialID == nil:
					t.Fatal("a credential event does not name its credential", event)
				case strings.Contains(event.Type, "rotat") && event.ActorID != "operator":
					t.Fatal("the rotation event lacks its actor", event)
				}
			}
			// Revocation records its actor; an unknown credential is not found.
			if _, e := catalog.Revoke(ctx, d, "ba_scim_credential_unknown", "admin"); !errors.Is(e, scim.ErrManagedNotFound) {
				t.Fatal("an unknown credential was revoked", e)
			}
			state, e := catalog.Revoke(ctx, d, issued.Credential.CredentialID, "admin")
			must(e)
			for _, c := range state.Credentials {
				if c.CredentialID == issued.Credential.CredentialID && (c.Status != "revoked" || c.RevokedBy == nil || *c.RevokedBy != "admin" || c.RevokedAt == nil) {
					t.Fatal("a revoked credential lacks its actor or time", c)
				}
			}
			// A host with a lower credential cap cannot rotate past it.
			capped, e := scim.New(host, scim.Options{Store: s, Managed: &scim.ManagedOptions{CredentialHashSecret: strings.Repeat("managed-local-key-", 3), MaxActiveCredentials: 1}})
			must(e)
			if r, e := capped.Catalog().Rotate(ctx, scim.Directory{ID: newer.Connection.ConnectionID, ProvisioningDomainID: "Domain"}, "operator", policy); !errors.Is(e, scim.ErrManagedConflict) || r.Token != "" {
				t.Fatal("a rotation past the credential cap was accepted", e)
			}
			// Retirement goes through the catalog, with an actor, and ends the
			// active credentials.
			if _, e := catalog.Decommission(ctx, d, ""); !invalid(e) {
				t.Fatal("a managed retirement without an actor was accepted", e)
			}
			if _, e := catalog.Decommission(ctx, scim.Directory{ID: "code", ProvisioningDomainID: "code"}, "admin"); !errors.Is(e, scim.ErrManagedNotFound) {
				t.Fatal("a code-defined connection was retired through the catalog", e)
			}
			_, e = catalog.Decommission(ctx, d, "admin")
			must(e)
			after, e := catalog.Get(ctx, d)
			must(e)
			for _, c := range after.Credentials {
				if c.CredentialID == rotated.Credential.CredentialID && c.Status != "decommissioned" || c.CredentialID == issued.Credential.CredentialID && c.Status != "revoked" {
					t.Fatal("retirement did not end the active credentials only", c)
				}
			}
			final, e := catalog.Events(ctx, d, scim.EventQuery{})
			must(e)
			if n := len(final.Events); n < 2 || final.Events[n-2].Type != "connection.decommissioning" || final.Events[n-1].Type != "connection.decommissioned" {
				t.Fatal("retirement did not end the audit trail with its two events", final.Events)
			}
			// Without the catalog option managed tokens are refused.
			plain, e := scim.New(host, scim.Options{Store: s, Connections: []scim.Connection{{Directory: scim.Directory{ID: "code"}, Credentials: []scim.Credential{{ID: "static", Token: "static-token"}}}}})
			must(e)
			if plain.Catalog() != nil {
				t.Fatal("a handler without the managed option has a catalog")
			}
			if w := scimRequest(plain, "GET", "Users", newer.Token, nil); w.Code != 401 {
				t.Fatal("a managed token was accepted without the managed option", w.Code)
			}
			// Management stays a server API, as in another runtime.
			for _, name := range []string{"createSCIMManagedConnection", "listSCIMManagedConnections", "getSCIMManagedConnection", "rotateSCIMManagedConnectionCredential",
				"revokeSCIMManagedConnectionCredential", "listSCIMManagedConnectionEvents", "decommissionSCIMConnection", "reconcileSCIMProjection"} {
				for _, target := range []string{"https://catalog.test" + directoryPath + name, "https://catalog.test/identity/custom/" + name, "https://catalog.test/identity/custom/scim/" + name} {
					r := httptest.NewRequest("POST", target, strings.NewReader("{}"))
					r.Header.Set("Authorization", "Bearer "+issued.Token)
					r.Header.Set("Content-Type", "application/json")
					for _, serve := range []func(*httptest.ResponseRecorder){func(w *httptest.ResponseRecorder) { h.ServeHTTP(w, r) }, func(w *httptest.ResponseRecorder) { host.ServeHTTP(w, r) }} {
						w := httptest.NewRecorder()
						serve(w)
						if w.Code != 404 {
							t.Fatal("a managed operation answered over HTTP", target, w.Code, w.Body.String())
						}
					}
				}
			}
		})
	}
}
