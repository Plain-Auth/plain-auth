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
			// PUT and PATCH keep userName unique and do not reach another directory.
			lowerPath := "Users/" + lower["id"].(string)
			call("PUT", lowerPath, "writer", user("writer", "operator", "id01", "lower@example.test"), 409, "uniqueness")
			call("PATCH", lowerPath, "writer", map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []map[string]any{{"op": "replace", "path": "userName", "value": "OPERATOR"}}}, 409, "uniqueness")
			call("PATCH", lowerPath, "second", map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": "Elsewhere"}}}, 404, "")
			// A supplied name.formatted is kept as sent.
			named := user("writer", "named", "", "named@example.test")
			named["displayName"] = "Display Name"
			named["name"] = map[string]any{"formatted": "Formatted Name", "givenName": "Given", "familyName": "Family"}
			got := call("POST", "Users", "writer", named, 201, "")
			for _, read := range []map[string]any{got, call("GET", "Users/"+got["id"].(string), "reader", nil, 200, "")} {
				if n := read["name"].(map[string]any); n["formatted"] != "Formatted Name" || n["givenName"] != "Given" || n["familyName"] != "Family" || read["displayName"] != "Display Name" {
					t.Fatal("a supplied name.formatted was not kept as sent", read)
				}
			}
			// A deleted User answers 404 to a second DELETE.
			// A single read looks the User up before its projection, and a
			// deletion ignores one, as in another runtime.
			const conflicting = "?attributes=userName&excludedAttributes=emails"
			call("GET", lowerPath+conflicting, "writer", nil, 400, "invalidValue")
			call("DELETE", lowerPath+conflicting, "writer", nil, 204, "")
			call("GET", lowerPath+conflicting, "writer", nil, 404, "")
			call("DELETE", lowerPath, "writer", nil, 404, "")
			// POST narrows its response, creates inactive Users and refuses
			// malformed bodies.
			narrowed := call("POST", "Users?attributes=userName", "writer", user("writer", "narrow", "", "narrow@example.test"), 201, "")
			if narrowed["userName"] != "narrow" || narrowed["id"] == nil || narrowed["emails"] != nil || narrowed["meta"] != nil {
				t.Fatal("attributes did not narrow a POST response", narrowed)
			}
			inactive := user("writer", "inactive", "", "inactive@example.test")
			inactive["active"] = false
			if got := call("POST", "Users", "writer", inactive, 201, ""); got["active"] != false {
				t.Fatal("a User created inactive was active", got)
			}
			call("POST", "Users", "writer", map[string]any{"schemas": []string{scim.UserSchema}, "emails": []map[string]any{{"value": "nouser@example.test"}}}, 400, "")
			call("POST", "Users", "writer", map[string]any{"userName": "noschemas", "emails": []map[string]any{{"value": "noschemas@example.test"}}}, 400, "")
			// Each resource type names its own location.
			types := call("GET", "ResourceTypes", "", nil, 200, "")
			for _, raw := range types["Resources"].([]any) {
				entry := raw.(map[string]any)
				if entry["meta"].(map[string]any)["location"] != "https://directory.test"+directoryPath+"ResourceTypes/"+entry["id"].(string) {
					t.Fatal("a resource type has the wrong location", entry)
				}
			}
			for _, id := range []string{"User", "Group"} {
				entry := call("GET", "ResourceTypes/"+id, "", nil, 200, "")
				if entry["id"] != id || entry["meta"].(map[string]any)["location"] != "https://directory.test"+directoryPath+"ResourceTypes/"+id {
					t.Fatal("a resource type read has the wrong location", entry)
				}
			}
		})
	}
}
