package sqlstore

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/scim"
	"github.com/Plain-Org/plain-auth/schema"
)

// The Users routes keep userName unique without case and externalId unique
// with it, per connection, split read and write scopes, accept a credential
// before it expires, list and filter Users and locate each resource type,
// as another runtime does.
func TestSCIMUserContract(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			ddl, e := schema.Generate(dialect, []string{"scim"})
			must(e)
			s, e := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(e)
			defer s.Close()
			host, e := auth.New(auth.Options{BaseURL: "https://directory.test", BasePath: "/identity/custom", Secret: strings.Repeat("x", 32), Store: s})
			must(e)
			h, e := scim.New(host, scim.Options{Store: s, Connections: []scim.Connection{
				{Directory: scim.Directory{ID: "acme"}, Credentials: []scim.Credential{{ID: "writer", Token: "writer"}, {ID: "reader", Token: "reader", Scopes: []string{scim.UsersRead}},
					{ID: "write-only", Token: "write-only", Scopes: []string{scim.UsersWrite}}, {ID: "retiring", Token: "retiring", ExpiresAt: time.Now().Add(time.Hour)}}},
				{Directory: scim.Directory{ID: "other"}, Credentials: []scim.Credential{{ID: "second", Token: "second"}}},
			}})
			must(e)
			call := func(method, path, token string, data map[string]any, status int, scimType string) map[string]any {
				t.Helper()
				w := scimRequest(h, method, path, token, data)
				var m map[string]any
				if w.Code != 204 {
					must(json.Unmarshal(w.Body.Bytes(), &m))
				}
				if w.Code != status || scimType != "" && m["scimType"] != scimType {
					t.Fatalf("%s %s: %d %s, want %d %s", method, path, w.Code, w.Body.String(), status, scimType)
				}
				return m
			}
			user := func(token, name, external, email string) map[string]any {
				u := map[string]any{"schemas": []string{scim.UserSchema}, "userName": name, "emails": []map[string]any{{"value": email, "primary": true}}}
				if external != "" {
					u["externalId"] = external
				}
				return u
			}
			first := call("POST", "Users", "writer", user("writer", "operator", "ID01", "operator@example.test"), 201, "")
			// userName is unique without case within a connection.
			call("POST", "Users", "writer", user("writer", "OPERATOR", "ID02", "upper@example.test"), 409, "uniqueness")
			call("POST", "Users", "second", user("second", "operator", "", "elsewhere@example.test"), 201, "")
			// externalId is unique with case within a connection.
			call("POST", "Users", "writer", user("writer", "another", "ID01", "another@example.test"), 409, "uniqueness")
			time.Sleep(5 * time.Millisecond) // creation order is by millisecond
			lower := call("POST", "Users", "writer", user("writer", "lower", "id01", "lower@example.test"), 201, "")
			call("POST", "Users", "second", user("second", "foreign", "ID01", "foreign@example.test"), 201, "")
			// Lists keep creation order and filter by id.
			list := call("GET", "Users", "reader", nil, 200, "")
			if resources := list["Resources"].([]any); len(resources) != 2 || resources[0].(map[string]any)["id"] != first["id"] || resources[1].(map[string]any)["id"] != lower["id"] {
				t.Fatal("the User list is not in creation order", list)
			}
			byID := call("GET", "Users?"+url.Values{"filter": {`id eq "` + first["id"].(string) + `"`}}.Encode(), "reader", nil, 200, "")
			if byID["totalResults"] != float64(1) || byID["Resources"].([]any)[0].(map[string]any)["id"] != first["id"] {
				t.Fatal("an id filter did not return that User", byID)
			}
			// A credential works until it expires.
			call("GET", "Users", "retiring", nil, 200, "")
			// Users scopes split read from write.
			path := "Users/" + first["id"].(string)
			call("GET", path, "write-only", nil, 403, "")
			call("PUT", path, "reader", user("reader", "operator", "ID01", "operator@example.test"), 403, "")
			call("PATCH", path, "reader", map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": "Op"}}}, 403, "")
			call("DELETE", path, "reader", nil, 403, "")
			call("PATCH", path, "write-only", map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": "Op"}}}, 200, "")
			// Each resource type names its own location.
			types := call("GET", "ResourceTypes", "", nil, 200, "")
			for _, raw := range types["Resources"].([]any) {
				entry := raw.(map[string]any)
				if entry["meta"].(map[string]any)["location"] != "https://directory.test"+directoryPath+"ResourceTypes/"+entry["id"].(string) {
					t.Fatal("a resource type has the wrong location", entry)
				}
			}
		})
	}
}
