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
