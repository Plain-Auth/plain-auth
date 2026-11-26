package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/scim"
	"github.com/Plain-Org/plain-auth/schema"
)

// Identity.ResolveUser links an incoming SCIM User to an existing account
// before the directory transaction, managing or preserving its profile.
func TestSCIMIdentityResolution(t *testing.T) {
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
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			host, err := auth.New(auth.Options{BaseURL: "https://directory.example.test", BasePath: "/identity/custom", Secret: strings.Repeat("a", 32), Store: store})
			must(err)
			now := time.Now().UTC()
			for _, u := range []auth.User{
				{ID: "target", Name: "Local Name", Email: "local@example.test", EmailVerified: true, CreatedAt: now, UpdatedAt: now},
				{ID: "managed", Name: "Old", Email: "old@example.test", EmailVerified: true, CreatedAt: now, UpdatedAt: now},
			} {
				must(store.CreateUser(ctx, u, "credential", nil))
			}
			var mu sync.Mutex
			var inputs []scim.IdentityResolutionInput
			calls := map[string]int{}
			var readErr error
			decide := func(scim.IdentityResolutionInput) (scim.IdentityResolution, error) {
				return scim.IdentityResolution{}, nil
			}
			set := func(d func(scim.IdentityResolutionInput) (scim.IdentityResolution, error)) {
				mu.Lock()
				decide = d
				mu.Unlock()
			}
			link := func(id, profile string) func(scim.IdentityResolutionInput) (scim.IdentityResolution, error) {
				return func(scim.IdentityResolutionInput) (scim.IdentityResolution, error) {
					return scim.IdentityResolution{Action: "link", UserID: id, Profile: profile}, nil
				}
			}
			resolve := func(rc context.Context, in scim.IdentityResolutionInput) (scim.IdentityResolution, error) {
				read, cancel := context.WithTimeout(rc, 2*time.Second)
				defer cancel()
				_, e := store.FindAccountUser(read, "local@example.test")
				mu.Lock()
				inputs, readErr = append(inputs, in), e
				calls[in.Resource.ExternalID]++
				d := decide
				mu.Unlock()
				return d(in)
			}
			connection := func(id, token string) scim.Connection {
				return scim.Connection{Directory: scim.Directory{ID: id, ProvisioningDomainID: "Org"}, Credentials: []scim.Credential{{ID: "owned", Token: token}}}
			}
			h, err := scim.New(host, scim.Options{Store: store, Connections: []scim.Connection{connection("ACME", "writer"), connection("BETA", "beta")}, Identity: &scim.Identity{ResolveUser: resolve}})
			must(err)
			post := func(token, userName, external, name, email string) (*httptest.ResponseRecorder, map[string]any) {
				body := map[string]any{"schemas": []string{scim.UserSchema}, "userName": userName, "displayName": name, "emails": []any{map[string]any{"value": email, "primary": true}}}
				if external != "" {
					body["externalId"] = external
				}
				w := scimRequest(h, "POST", "Users", token, body)
				var out map[string]any
				_ = json.Unmarshal(w.Body.Bytes(), &out)
				return w, out
			}
			count := func(q string, args ...any) int {
				t.Helper()
				var n int
				must(store.db.QueryRowContext(ctx, store.bind(q), args...).Scan(&n))
				return n
			}
			owner := func(id any) string {
				t.Helper()
				var u string
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT "userId" FROM "scimUser" WHERE "id"=?`), id).Scan(&u))
				return u
			}
			profile := func(id string) (name, email string, verified bool) {
				t.Helper()
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT "name","email","emailVerified" FROM "user" WHERE "id"=?`), id).Scan(&name, &email, &verified))
				return
			}
			patch := func(id any, ops ...map[string]any) *httptest.ResponseRecorder {
				return scimRequest(h, "PATCH", "Users/"+id.(string), "writer", map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": ops})
			}

			set(link("target", "preserve"))
			w, ada := post("writer", "directory-ada", "ada-1", "Directory Managed Name", "directory-managed@example.test")
			if w.Code != 201 {
				t.Fatal("a preserve link was not created", w.Code, w.Body.String())
			}
			mu.Lock()
			in, e := inputs[len(inputs)-1], readErr
			mu.Unlock()
			if e != nil {
				t.Fatal("the SCIM resolver could not read the store, so it ran inside the directory transaction", e)
			}
			if in.ConnectionID != "ACME" || in.ProvisioningDomainID != "Org" || in.Resource.UserName != "directory-ada" || in.Resource.ExternalID != "ada-1" || in.Resource.PrimaryEmail != "directory-managed@example.test" || !in.Resource.Active {
				t.Fatal("the SCIM resolver did not receive the connection, domain and canonical User", in)
			}
			if n := count(`SELECT COUNT(*) FROM "user"`); n != 2 {
				t.Fatal("a SCIM link created an account", n)
			}
			if owner(ada["id"]) != "target" {
				t.Fatal("the SCIM source was not linked to the resolved account")
			}
			if w := patch(ada["id"], map[string]any{"op": "replace", "path": "displayName", "value": "Renamed"}, map[string]any{"op": "replace", "path": "emails", "value": []any{map[string]any{"value": "renamed@example.test", "primary": true}}}); w.Code != 200 {
				t.Fatal("PATCH failed", w.Code, w.Body.String())
			}
			if name, email, verified := profile("target"); name != "Local Name" || email != "local@example.test" || !verified {
				t.Fatal("a preserved SCIM source changed the account's email or name", name, email, verified)
			}
			if w, body := post("writer", "second-ada", "ada-2", "Second", "second@example.test"); w.Code != 409 || body["scimType"] != "uniqueness" {
				t.Fatal("one connection linked two SCIM Users to one account", w.Code, w.Body.String())
			}
			if w, _ := post("beta", "beta-ada", "ada-beta", "Beta", "beta@example.test"); w.Code != 201 || count(`SELECT COUNT(*) FROM "scimUser" WHERE "userId"=?`, "target") != 2 {
				t.Fatal("two connections could not link preserved sources to one account", w.Code, w.Body.String())
			}

			set(link("managed", "manage"))
			w, managedUser := post("writer", "managed-user", "managed-1", "Managed Profile", "managed@example.test")
			var source string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "profileSourceId" FROM "scimSubject" WHERE "userId"=?`), "managed").Scan(&source))
			if name, email, verified := profile("managed"); w.Code != 201 || name != "Managed Profile" || email != "managed@example.test" || verified || source != managedUser["id"] {
				t.Fatal("a manage link did not hand the account's email and name to the source", w.Code, name, email, verified, source)
			}
			if w, body := post("beta", "managed-beta", "managed-2", "Beta Manager", "beta-manager@example.test"); w.Code != 409 || body["scimType"] != "uniqueness" {
				t.Fatal("a second managing source was accepted", w.Code, w.Body.String())
			}
			if name, _, _ := profile("managed"); name != "Managed Profile" {
				t.Fatal("a second managing source was accepted", name)
			}

			set(link("missing", "preserve"))
			sources := count(`SELECT COUNT(*) FROM "scimUser"`)
			if w, body := post("writer", "nobody", "nobody-1", "Nobody", "nobody@example.test"); w.Code != 409 || body["detail"] != "The resolved user does not exist" || count(`SELECT COUNT(*) FROM "scimUser"`) != sources || count(`SELECT COUNT(*) FROM "scimSubject" WHERE "userId"=?`, "missing") != 0 {
				t.Fatal("a link to a missing account stored identity state", w.Code, w.Body.String())
			}
			set(func(scim.IdentityResolutionInput) (scim.IdentityResolution, error) {
				return scim.IdentityResolution{}, errors.New("lookup failed")
			})
			if w, body := post("writer", "failing", "failing-1", "Failing", "failing@example.test"); w.Code != 500 || body["detail"] != "SCIM identity resolution failed" {
				t.Fatal("a failing SCIM resolver did not answer 500", w.Code, w.Body.String())
			}
			set(link("target", "own"))
			if w, _ := post("writer", "invalid", "invalid-1", "Invalid", "invalid@example.test"); w.Code != 500 {
				t.Fatal("an invalid SCIM resolution was accepted", w.Code, w.Body.String())
			}
			set(func(scim.IdentityResolutionInput) (scim.IdentityResolution, error) {
				return scim.IdentityResolution{}, nil
			})
			if w, _ := post("writer", "fresh", "fresh-1", "Fresh", "fresh@example.test"); w.Code != 201 {
				t.Fatal("an empty SCIM resolution did not create an account", w.Code, w.Body.String())
			}
			if _, err := store.FindAccountUser(ctx, "fresh@example.test"); err != nil {
				t.Fatal("an empty SCIM resolution did not create an account", err)
			}

			w, stable := post("writer", "stable", "stable-1", "Stable", "stable@example.test")
			first := owner(stable["id"])
			if d := scimRequest(h, "DELETE", "Users/"+stable["id"].(string), "writer", nil); w.Code != 201 || d.Code != 204 {
				t.Fatal("setup failed", w.Code, d.Code)
			}
			w, again := post("writer", "stable", "stable-1", "Stable", "stable@example.test")
			mu.Lock()
			stableCalls := calls["stable-1"]
			mu.Unlock()
			if w.Code != 201 || owner(again["id"]) != first || stableCalls != 1 {
				t.Fatal("the SCIM resolver ran for a deleted User's externalId", w.Code, stableCalls)
			}
			w, soft := post("writer", "soft", "soft-1", "Soft", "soft@example.test")
			if p := patch(soft["id"], map[string]any{"op": "replace", "path": "active", "value": false}); w.Code != 201 || p.Code != 200 {
				t.Fatal("setup failed", w.Code, p.Code, p.Body.String())
			}
			w, back := post("writer", "soft", "soft-1", "Soft", "soft@example.test")
			mu.Lock()
			softCalls := calls["soft-1"]
			mu.Unlock()
			if w.Code != 201 || back["id"] != soft["id"] || softCalls != 1 {
				t.Fatal("the SCIM resolver ran for an inactive SCIM User's externalId", w.Code, softCalls)
			}
		})
	}
}
