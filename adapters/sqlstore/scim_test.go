package sqlstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/scim"
	"github.com/Plain-Auth/plain-auth/schema"
)

const directoryPath = "/identity/custom/scim/v2/"

func scimRequest(h http.Handler, method, path, token string, body map[string]any) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	r := httptest.NewRequest(method, "https://untrusted.test"+directoryPath+path, bytes.NewReader(data))
	r.Header.Set("Content-Type", scim.MediaType)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestSCIMDirectoryLifecycle(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			core, e := Open(ctx, dialect, dsn)
			must(e)
			defer core.Close()
			now := time.Now().UTC().Truncate(time.Millisecond)
			existing := auth.User{ID: "unrelated", Name: "Account", Email: "existing@example.test", CreatedAt: now, UpdatedAt: now}
			must(core.CreateUser(ctx, existing, "local-only", nil))
			ddl, e := schema.Generate(dialect, []string{"scim"})
			must(e)
			first, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			defer first.Close()
			second, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			defer second.Close()
			if user, e := second.FindAccountUser(ctx, existing.Email); e != nil || user.ID != existing.ID {
				t.Fatalf("populated repeated migration lost account: %+v %v", user, e)
			}
			connection := func(id, domain, token string) scim.Connection {
				return scim.Connection{Directory: scim.Directory{ID: id, ProvisioningDomainID: domain}, Credentials: []scim.Credential{{ID: "owned", Token: token}}}
			}
			build := func(s *Store, domain string) *scim.Handler {
				host, e := auth.New(auth.Options{BaseURL: "https://directory.example.test", BasePath: "/identity/custom", Secret: strings.Repeat("a", 32), Store: s})
				must(e)
				c := connection("ACME", domain, "writer")
				c.Credentials = append(c.Credentials, scim.Credential{ID: "read", Token: "reader", Scopes: []string{scim.UsersRead}}, scim.Credential{ID: "dead", Token: "expired", ExpiresAt: now.Add(-time.Minute)}, scim.Credential{ID: "write-only", Token: "write-only", Scopes: []string{scim.UsersWrite}})
				h, e := scim.New(host, scim.Options{Store: s, Connections: []scim.Connection{c, connection("acme", "Org", "other")}})
				must(e)
				return h
			}
			a, b := build(first, "Org"), build(second, "Org")
			call := func(h http.Handler, method, path, token string, body map[string]any, status int) map[string]any {
				t.Helper()
				w := scimRequest(h, method, path, token, body)
				if w.Code != status || w.Header().Get("Content-Type") != scim.MediaType {
					t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
				}
				var obj map[string]any
				if status != 204 {
					must(json.Unmarshal(w.Body.Bytes(), &obj))
				}
				if status >= 400 && obj["status"] != fmt.Sprint(status) {
					t.Fatalf("wrong error envelope %+v", obj)
				}
				if status == 401 && w.Header().Get("WWW-Authenticate") != `Bearer realm="SCIM"` {
					t.Fatal("missing challenge")
				}
				return obj
			}
			for _, path := range []string{"ServiceProviderConfig", "ResourceTypes", "ResourceTypes/User", "Schemas", "Schemas/" + scim.UserSchema} {
				call(a, "GET", path, "", nil, 200)
			}
			call(a, "GET", "Users", "", nil, 401)
			call(a, "GET", "Users", "expired", nil, 401)
			call(a, "POST", "Users", "reader", nil, 403)
			call(a, "GET", "Users", "write-only", nil, 403)
			// First authenticated lookup fixes the domain even when the resource is missing.
			call(a, "GET", "Users/absent", "reader", nil, 404)
			call(build(second, "moved"), "GET", "Users", "writer", nil, 409)
			req := func(email, external string) map[string]any {
				return map[string]any{"schemas": []string{scim.UserSchema}, "userName": email, "externalId": external}
			}
			call(a, "POST", "Users", "writer", req(existing.Email, "existing"), 409)
			body := req("operator", "ID01")
			body["emails"] = []any{map[string]any{"type": "home", "value": "extra@example.test"}, map[string]any{"type": "WORK", "value": "Primary@Example.Test"}}
			body["name"] = map[string]any{"givenName": "Rae", "familyName": "Doe"}
			// Independent server instances serialize simultaneous creation of one source.
			start := make(chan struct{})
			results := make(chan *httptest.ResponseRecorder, 2)
			for _, h := range []*scim.Handler{a, b} {
				go func() { <-start; results <- scimRequest(h, "POST", "Users", "writer", body) }()
			}
			close(start)
			var id string
			var codes []int
			for range 2 {
				w := <-results
				codes = append(codes, w.Code)
				if w.Code == 201 {
					var obj map[string]any
					must(json.Unmarshal(w.Body.Bytes(), &obj))
					id = obj["id"].(string)
					if w.Header().Get("Location") != "https://directory.example.test"+directoryPath+"Users/"+id || w.Header().Get("Location") != w.Header().Get("Content-Location") {
						t.Fatalf("untrusted location %v", w.Header())
					}
				} else if w.Code != 409 {
					t.Log(w.Body.String())
				}
			}
			slices.Sort(codes)
			if !slices.Equal(codes, []int{201, 409}) {
				t.Fatalf("concurrent status %v", codes)
			}
			path := "Users/" + id
			account, e := first.FindAccountUser(ctx, "primary@example.test")
			must(e)
			if account.Name != "Rae Doe" || account.EmailVerified {
				t.Fatalf("account %+v", account)
			}
			call(b, "GET", path, "reader", nil, 200)
			call(b, "GET", path, "other", nil, 404)
			call(b, "PUT", path, "other", req("wrong@example.test", "ID01"), 404)
			call(b, "DELETE", path, "other", nil, 404)
			if got := call(b, "GET", "Users", "other", nil, 200); got["totalResults"] != float64(0) {
				t.Fatal(got)
			}
			for _, filter := range []string{`userName eq "OPERATOR" and externalId eq "ID01"`, `emails[type eq "work"].value eq "primary@example.test"`, `emails.value eq "extra@example.test"`} {
				got := call(a, "GET", "Users?filter="+url.QueryEscape(filter)+"&attributes=userName", "reader", nil, 200)
				if got["totalResults"] != float64(1) {
					t.Fatal(got)
				}
				u := got["Resources"].([]any)[0].(map[string]any)
				if len(u) != 3 || u["id"] != id || u["userName"] != "operator" {
					t.Fatal(u)
				}
			}
			call(a, "GET", "Users?filter="+url.QueryEscape(`userName co "operator"`), "reader", nil, 400)
			zero := call(a, "GET", "Users?count=0&startIndex=-2", "reader", nil, 200)
			if zero["itemsPerPage"] != float64(0) || zero["totalResults"] != float64(1) || zero["startIndex"] != float64(1) {
				t.Fatal(zero)
			}
			ss := auth.StoredSession{Session: auth.Session{ID: "owned-session", UserID: account.ID, Token: "directory-session", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			must(first.CreateSession(ctx, ss))
			patch := func(ops ...any) map[string]any {
				return map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": ops}
			}
			replace := func(path string, value any) map[string]any {
				return map[string]any{"op": "replace", "path": path, "value": value}
			}
			call(a, "PATCH", path, "writer", patch(replace("displayName", "Transient"), replace("unknown", "value")), 400)
			if got := call(b, "GET", path, "reader", nil, 200); got["displayName"] != "Rae Doe" {
				t.Fatal("partial mutation", got)
			}
			// Both changes survive a race between two adapters.
			start = make(chan struct{})
			for i, h := range []*scim.Handler{a, b} {
				go func() {
					<-start
					attr := []string{"title", "locale"}[i]
					results <- scimRequest(h, "PATCH", path, "writer", patch(replace(attr, "value")))
				}()
			}
			close(start)
			for range 2 {
				if w := <-results; w.Code != 200 {
					t.Fatalf("concurrent patch: %d %s", w.Code, w.Body.String())
				}
			}
			merged := call(b, "GET", path, "reader", nil, 200)
			if merged["title"] != "value" || merged["locale"] != "value" {
				t.Fatal("lost update", merged)
			}
			// Imported application roles require their own reconciliation callback.
			_, e = first.db.ExecContext(ctx, first.bind(`INSERT INTO "scimProjectionGrant" ("id","connectionId","provisioningDomainId","scimUserId","userId","sourceKind","sourceId","role","grantKey","createdAt","updatedAt") VALUES (?,?,?,?,?,?,?,?,?,?,?)`), "grant", "ACME", "Org", id, account.ID, "role", "source", "member", "fixture-grant", first.date(now), first.date(now))
			must(e)
			call(a, "PATCH", path, "writer", patch(replace("active", false)), 409)
			call(b, "DELETE", path, "writer", nil, 409)
			_, e = first.db.ExecContext(ctx, first.bind(`DELETE FROM "scimProjectionGrant" WHERE "id"=?`), "grant")
			must(e)
			call(a, "PATCH", path, "writer", patch(replace("active", "false")), 200)
			var n int
			must(first.db.QueryRowContext(ctx, first.bind(`SELECT COUNT(*) FROM "session" WHERE "userId"=?`), account.ID).Scan(&n))
			if n != 0 {
				t.Fatal("session survived deactivation")
			}
			again := call(b, "POST", "Users", "writer", body, 201)
			if again["id"] != id || again["active"] != true {
				t.Fatal(again)
			}
			newProfile := req("changed@example.test", "ID01")
			newProfile["displayName"] = "Updated"
			_, e = first.db.ExecContext(ctx, first.bind(`UPDATE "user" SET "emailVerified"=? WHERE "id"=?`), true, account.ID)
			must(e)
			call(a, "PUT", path, "writer", newProfile, 200)
			updated, e := second.FindAccountUser(ctx, "changed@example.test")
			must(e)
			if updated.ID != account.ID || updated.EmailVerified || updated.Name != "Updated" {
				t.Fatal(updated)
			}
			must(first.CreateSession(ctx, ss))
			call(b, "DELETE", path, "writer", nil, 204)
			call(a, "GET", path, "reader", nil, 404)
			must(first.db.QueryRowContext(ctx, first.bind(`SELECT COUNT(*) FROM "session" WHERE "userId"=?`), account.ID).Scan(&n))
			if n != 0 {
				t.Fatal("session survived deletion")
			}
			call(a, "POST", "Users", "other", newProfile, 409)
			recreated := call(a, "POST", "Users", "writer", newProfile, 201)
			if recreated["id"] == id {
				t.Fatal("hard delete reused resource ID")
			}
			updated, e = second.FindAccountUser(ctx, "changed@example.test")
			must(e)
			if updated.ID != account.ID {
				t.Fatal("canonical identity was replaced")
			}
			must(first.CreateSession(ctx, ss))
			must(core.DeleteAccount(ctx, account.ID, ss.Token, "", "", now))
			call(b, "GET", "Users/"+recreated["id"].(string), "reader", nil, 404)
			for _, table := range []string{"scimSubject", "scimUser", "scimIdentityTombstone"} {
				must(first.db.QueryRowContext(ctx, first.bind(`SELECT COUNT(*) FROM "`+table+`" WHERE "userId"=?`), account.ID).Scan(&n))
				if n != 0 {
					t.Fatal("account deletion left private rows in", table)
				}
			}
			_, e = first.db.ExecContext(ctx, first.bind(`UPDATE "scimConnectionBinding" SET "decommissionStatus"='completed' WHERE "connectionKey"=?`), scimKey("scim-connection", "ACME"))
			must(e)
			call(b, "GET", "Users", "reader", nil, 401)
		})
	}
}
