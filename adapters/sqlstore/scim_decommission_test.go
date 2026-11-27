package sqlstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/scim"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestSCIMDirectoryRetirement(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"scim-managed"})
			must(err)
			open := func() (*Store, *scim.Handler) {
				s, err := OpenWithSchema(ctx, dialect, dsn, ddl)
				must(err)
				t.Cleanup(func() { s.Close() })
				host, err := auth.New(auth.Options{Secret: strings.Repeat("x", 40), BaseURL: "https://retire.test", BasePath: "/identity/custom", Store: s})
				must(err)
				h, err := scim.New(host, scim.Options{Store: s, Managed: &scim.ManagedOptions{CredentialHashSecret: strings.Repeat("k", 40)}, Connections: []scim.Connection{
					{Directory: scim.Directory{ID: "static", ProvisioningDomainID: "agency"}, Credentials: []scim.Credential{{ID: "static-key", Token: "static-token"}}},
					{Directory: scim.Directory{ID: "other", ProvisioningDomainID: "foreign"}, Credentials: []scim.Credential{{ID: "other-key", Token: "other-token"}}},
				}})
				must(err)
				return s, h
			}
			s, one := open()
			_, two := open()
			issue := func(request string) scim.IssuedCredential {
				i, e := one.Catalog().Create(ctx, "agency", request, "owner", scim.CredentialPolicy{Scopes: []string{scim.UsersRead, scim.UsersWrite}, ExpiresAt: time.Now().Add(time.Hour)})
				must(e)
				return i
			}
			i := issue("catalog-retire-never-used")
			d := scim.Directory{ID: i.Connection.ConnectionID, ProvisioningDomainID: "agency"}
			f, e := one.Catalog().Decommission(ctx, scim.Directory{ID: d.ID, ProvisioningDomainID: "foreign"}, "imposter")
			if !errors.Is(e, scim.ErrManagedNotFound) || f.Connection.ConnectionID != "" {
				t.Fatal(f, e)
			}
			z, e := one.Catalog().Decommission(ctx, d, "owner")
			must(e)
			if z.Connection.Status != "decommissioned" || z.Decommission.Status != "complete" || z.Decommission.Batches != 0 || z.Decommission.ReconciledUsers != 0 || z.Credentials[0].Status != "decommissioned" {
				t.Fatal(z)
			}
			call := func(handler *scim.Handler, token, verb string, body map[string]any, want int) {
				t.Helper()
				res := scimRequest(handler, verb, "Users", token, body)
				if res.Code != want {
					t.Fatalf("%s: %d %s", verb, res.Code, res.Body.String())
				}
			}
			createUser := func(h *scim.Handler, token, email string) {
				call(h, token, "POST", map[string]any{"userName": email, "schemas": []string{scim.UserSchema}}, 201)
			}
			call(two, i.Token, "GET", nil, 401)
			// Even a declared credential available on another node cannot reopen a
			// connection retired before its first directory request.
			static := scim.Directory{ID: "static", ProvisioningDomainID: "agency"}
			if _, e = two.Decommission(ctx, scim.Directory{ID: "static", ProvisioningDomainID: "foreign"}); !errors.Is(e, scim.ErrDomain) {
				t.Fatal(e)
			}
			base, e := two.Decommission(ctx, static)
			must(e)
			if base.Status != "complete" {
				t.Fatal(base)
			}
			call(one, "static-token", "GET", nil, 401)
			if _, e = two.Decommission(ctx, scim.Directory{ID: "static", ProvisioningDomainID: "foreigN"}); !errors.Is(e, scim.ErrDomain) {
				t.Fatal(e)
			}

			i = issue("catalog-retire-populated")
			d.ID = i.Connection.ConnectionID
			for n := range 51 {
				createUser(one, i.Token, fmt.Sprintf("retire-%02d@example.test", n))
			}
			createUser(two, "other-token", "retained@example.test")
			session := func(email, id string) string {
				u, e := s.FindAccountUser(ctx, email)
				must(e)
				now := time.Now().UTC()
				must(s.CreateSession(ctx, auth.StoredSession{Session: auth.Session{ID: id, Token: id, UserID: u.ID, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}))
				return u.ID
			}
			keep := session("retained@example.test", "keep-session")
			owner := session("retire-00@example.test", "retire-session")
			// Import a second participating source for one account. Retiring this
			// directory releases its profile ownership while that source keeps sessions active.
			sharedOwner := session("retire-01@example.test", "shared-session")
			createUser(two, "other-token", "shared-source@example.test")
			foreignSource, err := s.FindAccountUser(ctx, "shared-source@example.test")
			must(err)
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "scimUser" SET "userId"=? WHERE "userId"=?`), sharedOwner, foreignSource.ID)
			must(err)
			// Put the dependent authorization grant in the second page so the
			// resume test starts after an actual persisted 50-user checkpoint.
			var resource, grantOwner string
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "id","userId" FROM "scimUser" WHERE "connectionId"=? ORDER BY "userId" DESC LIMIT 1`), d.ID).Scan(&resource, &grantOwner))
			stamp := s.date(time.Now())
			_, e = s.db.ExecContext(ctx, s.bind(`INSERT INTO "scimProjectionGrant" ("id","connectionId","provisioningDomainId","scimUserId","userId","sourceKind","sourceId","role","grantKey","createdAt","updatedAt") VALUES (?,?,?,?,?,'user',?,'app-role','test-grant',?,?)`), "test-grant", d.ID, d.ProvisioningDomainID, resource, grantOwner, resource, stamp, stamp)
			must(e)
			bindingStatus := func() string {
				var v string
				must(s.db.QueryRowContext(ctx, s.bind(`SELECT "decommissionStatus" FROM "scimConnectionBinding" WHERE "connectionKey"=?`), scimKey("scim-connection", d.ID)).Scan(&v))
				return v
			}
			if got := bindingStatus(); got != "active" {
				t.Fatal("a populated managed connection's binding is not active", got)
			}
			// The static retirement refuses a managed connection even when the
			// domain is left to the binding.
			var refused *scim.Error
			if _, e := one.Decommission(ctx, scim.Directory{ID: d.ID}); !errors.As(e, &refused) || refused.Status != 400 || refused.Type != "invalidValue" || bindingStatus() != "active" {
				t.Fatal("a managed connection was retired outside its catalog", e)
			}
			_, e = one.Catalog().Decommission(ctx, d, "first-admin")
			var typed *scim.Error
			if !errors.As(e, &typed) || typed.Status != 409 {
				t.Fatal(e)
			}
			if got := bindingStatus(); got != "reconciling" {
				t.Fatal("an interrupted retirement's binding is not reconciling", got)
			}
			call(two, i.Token, "GET", nil, 401)
			openState, e := two.Catalog().Get(ctx, d)
			must(e)
			if openState.Connection.Status != "decommissioning" || openState.Credentials[0].Status != "decommissioned" {
				t.Fatal(openState)
			}
			if _, e = one.Catalog().Rotate(ctx, d, "admin", scim.CredentialPolicy{Scopes: []string{scim.UsersRead}, ExpiresAt: time.Now().Add(time.Hour)}); !errors.Is(e, scim.ErrManagedConflict) {
				t.Fatal(e)
			}

			// A pinned peer already processing a lease retains its checkpoint. Once
			// that worker disappears, a new instance can reclaim its expired lease.
			until := time.Now().Add(time.Minute)
			_, e = s.db.ExecContext(ctx, s.bind(`UPDATE "scimConnectionBinding" SET "decommissionLeaseId"='peer',"decommissionLeaseExpiresAt"=? WHERE "connectionKey"=?`), s.date(until), scimKey("scim-connection", d.ID))
			must(e)
			pending, e := two.Catalog().Decommission(ctx, d, "second-admin")
			must(e)
			if pending.Decommission.RetryAfter == nil || pending.Decommission.Status != "reconciling" || pending.Connection.Status != "decommissioning" || pending.Decommission.Batches != 1 || pending.Decommission.ReconciledUsers != 50 {
				t.Fatal(pending)
			}
			var grantCount int
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "scimProjectionGrant" WHERE "id"='test-grant'`)).Scan(&grantCount))
			if grantCount != 1 {
				t.Fatal("stored authorization grant lost on retirement failure")
			}
			_, e = s.db.ExecContext(ctx, s.bind(`DELETE FROM "scimProjectionGrant" WHERE "id"='test-grant'`))
			must(e)
			_, e = s.db.ExecContext(ctx, s.bind(`UPDATE "scimConnectionBinding" SET "decommissionLeaseExpiresAt"=? WHERE "connectionKey"=?`), s.date(time.Now().Add(-time.Minute)), scimKey("scim-connection", d.ID))
			must(e)
			errs := make(chan error, 2)
			for _, h := range []*scim.Handler{one, two} {
				go func() { _, e := h.Catalog().Decommission(ctx, d, "second-admin"); errs <- e }()
			}
			for range 2 {
				must(<-errs)
			}
			done, e := two.Catalog().Decommission(ctx, d, "third-admin")
			must(e)
			if done.Connection.Status != "decommissioned" || *done.Connection.DecommissionStartedBy != "first-admin" || *done.Connection.DecommissionedBy != "second-admin" || done.Decommission.ReconciledUsers != 51 || done.Decommission.Batches != 2 || done.Decommission.CompletedAt == nil || done.Decommission.RetryAfter != nil {
				t.Fatal(done)
			}
			events, e := one.Catalog().Events(ctx, d, scim.EventQuery{})
			must(e)
			if events.Total != 4 || events.Events[2].Type != "connection.decommissioning" || events.Events[3].Type != "connection.decommissioned" {
				t.Fatal(events)
			}
			for _, check := range []struct {
				q, id string
				want  int
			}{
				{`SELECT COUNT(*) FROM "session" WHERE "userId"=?`, owner, 0},
				{`SELECT COUNT(*) FROM "session" WHERE "userId"=?`, keep, 1},
				{`SELECT COUNT(*) FROM "session" WHERE "userId"=?`, sharedOwner, 1},
				{`SELECT COUNT(*) FROM "scimSubject" WHERE "userId"=? AND "profileSourceId" IS NULL`, sharedOwner, 1},
				{`SELECT COUNT(*) FROM "scimSubject" WHERE "userId"=? AND "profileSourceId" IS NULL`, owner, 1},
				{`SELECT COUNT(*) FROM "scimUser" WHERE "connectionId"=?`, d.ID, 51},
			} {
				var n int
				must(s.db.QueryRowContext(ctx, s.bind(check.q), check.id).Scan(&n))
				if n != check.want {
					t.Fatalf("%s: %d; want %d", check.q, n, check.want)
				}
			}
			call(two, "other-token", "GET", nil, 200)
		})
	}
}

// Retirement without a provisioning domain uses the domain the connection
// is bound to, and a connection without a binding is refused.
func TestSCIMRetirementWithoutDomain(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"scim"})
			must(err)
			s, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer s.Close()
			host, err := auth.New(auth.Options{Secret: strings.Repeat("x", 40), BaseURL: "https://retire.test", BasePath: "/identity/custom", Store: s})
			must(err)
			h, err := scim.New(host, scim.Options{Store: s, Connections: []scim.Connection{
				{Directory: scim.Directory{ID: "bound", ProvisioningDomainID: "agency"}, Credentials: []scim.Credential{{ID: "bound-key", Token: "bound-token"}}},
				{Directory: scim.Directory{ID: "declared", ProvisioningDomainID: "office"}, Credentials: []scim.Credential{{ID: "declared-key", Token: "declared-token"}}},
			}})
			must(err)
			if w := scimRequest(h, "POST", "Users", "bound-token", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "bound@example.test"}); w.Code != 201 {
				t.Fatal("provisioning failed", w.Code, w.Body.String())
			}
			if r, err := s.SCIMDecommission(ctx, scim.Directory{ID: "bound"}); err != nil || r.Status != "complete" || r.ProvisioningDomainID != "agency" {
				t.Fatal("a bound connection was not retired in its bound domain", r, err)
			}
			if _, err := s.SCIMDecommission(ctx, scim.Directory{ID: "never-bound"}); !errors.Is(err, scim.ErrNoBinding) {
				t.Fatal("a connection without a binding was retired without a domain", err)
			}
			// A configured connection is not retired in its configured domain
			// without a binding, as in another runtime.
			if _, err := h.Decommission(ctx, scim.Directory{ID: "declared"}); !errors.Is(err, scim.ErrNoBinding) {
				t.Fatal("a never-bound configured connection was retired without a domain", err)
			}
			if r, err := h.Decommission(ctx, scim.Directory{ID: "declared", ProvisioningDomainID: "office"}); err != nil || r.Status != "complete" {
				t.Fatal("a configured connection was not retired in its given domain", r, err)
			}
		})
	}
}

// Retiring a code-defined connection reconciles its Users in one batch,
// shuts out its token and keeps its directory rows, as another runtime
// does; a managed connection is retired only through its catalog.
func TestSCIMStaticDecommission(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"scim"})
			must(err)
			s, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer s.Close()
			host, err := auth.New(auth.Options{Secret: strings.Repeat("x", 40), BaseURL: "https://retire.test", BasePath: "/identity/custom", Store: s})
			must(err)
			h, err := scim.New(host, scim.Options{Store: s, Connections: []scim.Connection{{Directory: scim.Directory{ID: "static"}, Credentials: []scim.Credential{{ID: "key", Token: "static-token"}}}}})
			must(err)
			w := scimRequest(h, "POST", "Users", "static-token", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "member@example.test"})
			if w.Code != 201 {
				t.Fatal("provisioning failed", w.Code, w.Body.String())
			}
			var created struct{ ID string }
			must(json.Unmarshal(w.Body.Bytes(), &created))
			if w := scimRequest(h, "POST", "Groups", "static-token", map[string]any{"schemas": []string{scim.GroupSchema}, "displayName": "Team", "members": []map[string]any{{"value": created.ID}}}); w.Code != 201 {
				t.Fatal("the Group was not created", w.Code, w.Body.String())
			}
			status := func() string {
				var v string
				must(s.db.QueryRowContext(ctx, s.bind(`SELECT "decommissionStatus" FROM "scimConnectionBinding" WHERE "connectionKey"=?`), scimKey("scim-connection", "static")).Scan(&v))
				return v
			}
			if got := status(); got != "active" {
				t.Fatal("a provisioned connection's binding is not active", got)
			}
			var blank *scim.Error
			if _, err := h.Decommission(ctx, scim.Directory{ID: "static", ProvisioningDomainID: "   "}); !errors.As(err, &blank) || blank.Type != "invalidValue" || status() != "active" {
				t.Fatal("a blank provisioning domain was not refused", err)
			}
			r, err := h.Decommission(ctx, scim.Directory{ID: " static ", ProvisioningDomainID: "static"})
			if err != nil || r.Status != "complete" || r.ReconciledUsers != 1 || r.Batches != 1 {
				t.Fatal("the static connection was not retired in one batch", r, err)
			}
			if got := status(); got != "complete" {
				t.Fatal("a retired connection's binding is not complete", got)
			}
			if w := scimRequest(h, "GET", "Users", "static-token", nil); w.Code != 401 {
				t.Fatal("a retired connection's token still works", w.Code)
			}
			// The token is checked before the query, so an unknown token gets
			// 401 for a repeated filter.
			if w := scimRequest(h, "GET", "Users?filter=a&filter=b", "unknown-token", nil); w.Code != 401 {
				t.Fatal("a repeated filter was read before the bearer token", w.Code, w.Body.String())
			}
			// A retired connection is refused before its query is read and
			// once its body is valid, as another runtime's middleware runs
			// after body validation.
			for _, req := range []struct{ method, path string }{{"GET", "Users?filter=bogus"}, {"GET", "Groups?startIndex=x"}, {"POST", "Users?attributes=a%20b"}} {
				if w := scimRequest(h, req.method, req.path, "static-token", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "late@example.test"}); w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
					t.Fatal("a retired connection's malformed request was read before its binding", req, w.Code, w.Body.String())
				}
			}
			if w := scimRequest(h, "POST", "Users", "static-token", map[string]any{"schemas": []string{scim.UserSchema}}); w.Code != 400 || !strings.Contains(w.Body.String(), "invalidValue") {
				t.Fatal("a retired connection's invalid body was not refused before its binding", w.Code, w.Body.String())
			}
			plain := httptest.NewRequest("POST", "https://untrusted.test"+directoryPath+"Users", strings.NewReader("userName=late"))
			plain.Header.Set("Content-Type", "text/plain")
			plain.Header.Set("Authorization", "Bearer static-token")
			unsupported := httptest.NewRecorder()
			h.ServeHTTP(unsupported, plain)
			if unsupported.Code != 415 {
				t.Fatal("a retired connection's unsupported body was not refused before its binding", unsupported.Code, unsupported.Body.String())
			}
			// A PATCH operation's shape and a repeated query key fail the body or
			// query schema first; a blank member only fails after the binding.
			move := map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []any{map[string]any{"op": "move", "path": "active", "value": false}}}
			nullOp := map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []any{map[string]any{"op": nil, "path": "displayName", "value": "Renamed"}}}
			nullPath := map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []any{map[string]any{"op": "replace", "path": nil, "value": map[string]any{"displayName": "Renamed"}}}}
			for _, req := range []struct {
				method, path string
				body         map[string]any
				status       int
			}{
				{"PATCH", "Users/" + created.ID, move, 400},
				{"GET", "Users?filter=a&filter=b", nil, 400},
				// A null under another spelling of op is an unknown key, so the
				// request reaches the binding.
				{"PATCH", "Users/" + created.ID, map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []any{map[string]any{"Op": nil, "path": "displayName", "value": "Renamed"}}}, 401},
				{"PATCH", "Groups/missing", map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []any{map[string]any{"op": "replace", "Path": nil, "value": map[string]any{"displayName": "Renamed"}}}}, 401},
				// Only a collection read refuses a repeated page or filter key,
				// and repeated projection keys are merged, so these reach the
				// binding.
				{"GET", "Users/" + created.ID + "?count=1&count=2", nil, 401},
				{"GET", "Users?attributes=userName&attributes=emails", nil, 401},
				{"POST", "Users?filter=a&filter=b", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "late@example.test"}, 401},
				{"POST", "Groups", map[string]any{"schemas": []string{scim.GroupSchema}, "displayName": "Blank", "members": []any{map[string]any{"value": "   "}}}, 401},
			} {
				if w := scimRequest(h, req.method, req.path, "static-token", req.body); w.Code != req.status {
					t.Fatal("a retired connection's request was not answered in another runtime's order", req.method, req.path, w.Code, w.Body.String())
				}
			}
			// A null op or path fails the body schema, which wants a string,
			// with invalidValue, even where both are null or the value repeats
			// a name.
			both := map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []any{map[string]any{"op": nil, "path": nil, "value": "Renamed"}}}
			repeated := map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []any{map[string]any{"op": "replace", "path": nil, "value": map[string]any{"displayName": "A", "DISPLAYNAME": "B"}}}}
			for _, path := range []string{"Users/" + created.ID, "Groups/missing"} {
				for _, body := range []map[string]any{nullOp, nullPath, both, repeated} {
					w := scimRequest(h, "PATCH", path, "static-token", body)
					var problem struct{ ScimType string }
					_ = json.Unmarshal(w.Body.Bytes(), &problem)
					if w.Code != 400 || problem.ScimType != "invalidValue" {
						t.Fatal("a null op or path was not refused as invalidValue", path, body, w.Code, w.Body.String())
					}
				}
			}
			for _, table := range []string{"scimUser", "scimGroup", "scimGroupMember"} {
				var n int
				must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "`+table+`"`)).Scan(&n))
				if n == 0 {
					t.Fatal("retirement removed the directory rows", table)
				}
			}
			var se *scim.Error
			if _, err := h.Decommission(ctx, scim.Directory{ID: "ba_scim_connection_x", ProvisioningDomainID: "static"}); !errors.As(err, &se) || se.Status != 400 || se.Type != "invalidValue" {
				t.Fatal("a managed connection was retired outside its catalog", err)
			}
		})
	}
}
