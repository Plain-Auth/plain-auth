package sqlstore

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/plugins/scim"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestSCIMUserRoleProfile(t *testing.T) {
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
			ddl, e := schema.Generate(dialect, []string{"scim", "organization", "admin"})
			must(e)
			store, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			t.Cleanup(func() { store.Close() })
			peer, e := Open(ctx, dialect, dsn)
			must(e)
			t.Cleanup(func() { peer.Close() })
			serve := func(s *Store) http.Handler {
				host, e := auth.New(auth.Options{BaseURL: "https://directory.example.test", BasePath: "/identity/custom", Secret: strings.Repeat("s", 32), Store: s})
				must(e)
				h, e := scim.New(host, scim.Options{Store: s, Connections: []scim.Connection{
					{Directory: scim.Directory{ID: "Workforce", ProvisioningDomainID: "Tenant"}, Credentials: []scim.Credential{{ID: "key", Token: "suite-token"}}},
					{Directory: scim.Directory{ID: "Another", ProvisioningDomainID: "Tenant"}, Credentials: []scim.Credential{{ID: "key", Token: "other-token"}}},
				}})
				must(e)
				return h
			}
			a, b := serve(store), serve(peer)
			request := func(h http.Handler, method, path string, body map[string]any, status int) map[string]any {
				t.Helper()
				res := scimRequest(h, method, path, "suite-token", body)
				if res.Code != status {
					t.Fatalf("%s %s returned %d, want %d: %s", method, path, res.Code, status, res.Body.String())
				}
				var v map[string]any
				must(json.Unmarshal(res.Body.Bytes(), &v))
				return v
			}
			newProfile := func(roles any) map[string]any {
				return map[string]any{"schemas": []string{scim.UserSchema}, "userName": "source@example.test", "externalId": "user-one", "roles": roles}
			}
			assigned := []any{map[string]any{"value": "owner", "type": "work", "primary": true}, map[string]any{"value": "read"}}
			created := request(a, "POST", "Users", newProfile(assigned), 201)
			path := "Users/" + created["id"].(string)
			if !reflect.DeepEqual(created["roles"], assigned) {
				t.Fatalf("unexpected roles: %v", created["roles"])
			}
			if got := scimRequest(b, "GET", path, "other-token", nil); got.Code != 404 {
				t.Fatalf("another directory read an owned profile: %d", got.Code)
			}
			result := request(b, "GET", "Users?attributes=roles.type", nil, 200)
			if rows := result["Resources"].([]any); len(rows) != 1 || !reflect.DeepEqual(rows[0].(map[string]any)["roles"], []any{map[string]any{"type": "work"}}) {
				t.Fatalf("nested role selection: %+v", result)
			}
			subject, e := store.FindAccountUser(ctx, "source@example.test")
			must(e)
			now := time.Now().UTC().Truncate(time.Millisecond)
			manager := auth.User{ID: "org-founder", Email: "org@example.test", Name: "Founder", CreatedAt: now, UpdatedAt: now}
			ss := auth.StoredSession{Session: auth.Session{ID: "fixture-session", UserID: manager.ID, Token: "org-token", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			must(store.CreateUser(ctx, manager, "", &ss))
			must(store.CreateOrganization(ctx, org.Organization{ID: "Tenant", Name: "Company", Slug: "company", CreatedAt: now}, org.Member{ID: "founder-member", OrganizationID: "Tenant", UserID: manager.ID, Role: "owner", CreatedAt: now}, ss.ID, false))
			must(store.AddOrganizationMember(ctx, org.Member{ID: "scim-member", OrganizationID: "Tenant", UserID: subject.ID, Role: "member", CreatedAt: now}, ""))

			patch := func(ops ...map[string]any) map[string]any {
				return map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": ops}
			}
			op := func(path string, value any) map[string]any {
				return map[string]any{"op": "replace", "path": path, "value": value}
			}
			// Concurrent writers change different fields using independent SQL connections.
			out := make(chan int, 2)
			go func() {
				out <- scimRequest(a, "PATCH", path, "suite-token", patch(op(`roles[type eq "work"].display`, "Operations"))).Code
			}()
			go func() {
				out <- scimRequest(b, "PATCH", path, "suite-token", patch(op(`roles[type eq "new"].value`, "admin"))).Code
			}()
			if code1, code2 := <-out, <-out; code1 != 200 || code2 != 200 {
				t.Fatalf("concurrent PATCH: %d %d", code1, code2)
			}
			got := request(b, "GET", path, nil, 200)
			want := []any{map[string]any{"value": "owner", "type": "work", "primary": true, "display": "Operations"}, map[string]any{"value": "read"}, map[string]any{"value": "admin", "type": "new"}}
			if !reflect.DeepEqual(got["roles"], want) {
				t.Fatalf("concurrent edits lost stored roles: %#v", got["roles"])
			}
			var encoded string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "serializedAttributes" FROM "scimUser" WHERE "id"=?`), created["id"]).Scan(&encoded))
			var attrs map[string]any
			must(json.Unmarshal([]byte(encoded), &attrs))
			if !reflect.DeepEqual(attrs["roles"], want) {
				t.Fatal("roles did not persist in canonical profile JSON")
			}
			for _, bad := range []any{[]any{map[string]any{"value": "staff", "type": "A"}, map[string]any{"value": "new", "type": " a "}}, []any{map[string]any{"value": "ok", "primary": true}, map[string]any{"value": "new", "primary": true}}, []any{map[string]any{"value": "ok", "primary": "yes"}}, []any{map[string]any{"value": strings.Repeat("😀", 1025)}}, make([]any, 11)} {
				request(a, "PUT", path, newProfile(bad), 400)
			}
			if got := request(b, "GET", path, nil, 200); !reflect.DeepEqual(got["roles"], want) {
				t.Fatal("an invalid replacement changed the stored roles")
			}
			inactive := request(a, "PATCH", path, patch(op("active", false)), 200)
			if inactive["active"] != false || !reflect.DeepEqual(inactive["roles"], want) {
				t.Fatal("deactivation discarded the directory roles")
			}
			back := request(b, "POST", "Users", newProfile([]any{map[string]any{"value": "super-admin"}}), 201)
			if back["id"] != created["id"] || back["active"] != true {
				t.Fatalf("reprovisioned resource: %#v", back)
			}
			var role, member string
			var grants int
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT COALESCE("role",'user') FROM "user" WHERE "id"=?`), subject.ID).Scan(&role))
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "role" FROM "member" WHERE "id"='scim-member'`)).Scan(&member))
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "scimProjectionGrant" WHERE "userId"=?`), subject.ID).Scan(&grants))
			if role != "user" || member != "member" || grants != 0 {
				t.Fatalf("directory roles changed account authority: %q %q %d", role, member, grants)
			}
			// Ten native-script values can be within the UTF-16 protocol limit
			// while exceeding the physical byte capacity of MySQL's TEXT column.
			wide := make([]any, 10)
			for i := range wide {
				wide[i] = map[string]any{"value": strings.Repeat("界", 1024), "display": strings.Repeat("界", 1024), "type": strings.Repeat("界", 255) + string(rune('a'+i))}
			}
			if dialect == "mysql" {
				out := request(a, "PUT", path, newProfile(wide), 400)
				if got := request(b, "GET", path, nil, 200); !reflect.DeepEqual(got["roles"], back["roles"]) {
					t.Fatal("oversized replacement changed the stored profile")
				}
				if out["scimType"] != "invalidValue" {
					t.Fatalf("incorrect database text bound: %v", out)
				}
			} else {
				out := request(a, "PUT", path, newProfile(wide), 200)
				if !reflect.DeepEqual(out["roles"], wide) {
					t.Fatal("valid multibyte role profile lost data")
				}
			}
			request(a, "PATCH", path, patch(op("roles", nil)), 200)
			if v := request(b, "GET", path, nil, 200); v["roles"] != nil {
				t.Fatal("cleared roles reappeared")
			}
		})
	}
}
