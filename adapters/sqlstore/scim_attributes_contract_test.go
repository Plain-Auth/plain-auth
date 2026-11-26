package sqlstore

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/scim"
	"github.com/Plain-Org/plain-auth/schema"
)

// User attributes follow another runtime: a missing name and displayName
// come from the primary email, emails are bounded, the profile strings
// round-trip and leave with PUT or PATCH remove, active is restored by a
// remove, and null subattributes inside whole values are dropped.
func TestSCIMUserAttributeContract(t *testing.T) {
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
			h, e := scim.New(host, scim.Options{Store: s, Connections: []scim.Connection{{Directory: scim.Directory{ID: "acme"}, Credentials: []scim.Credential{{ID: "full", Token: "token"}}}}})
			must(e)
			call := func(method, path string, data map[string]any, status int) map[string]any {
				t.Helper()
				w := scimRequest(h, method, path, "token", data)
				var m map[string]any
				if w.Code != 204 {
					must(json.Unmarshal(w.Body.Bytes(), &m))
				}
				if w.Code != status {
					t.Fatalf("%s %s: %d %s, want %d", method, path, w.Code, w.Body.String(), status)
				}
				return m
			}
			emails := func(values ...string) []map[string]any {
				var out []map[string]any
				for i, v := range values {
					out = append(out, map[string]any{"value": v, "primary": i == 0})
				}
				return out
			}
			user := func(name string, extra map[string]any) map[string]any {
				u := map[string]any{"schemas": []string{scim.UserSchema}, "userName": name, "emails": emails(name + "@example.test")}
				for k, v := range extra {
					u[k] = v
				}
				return u
			}
			patch := func(ops ...map[string]any) map[string]any {
				return map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": ops}
			}
			// The primary email supplies a missing name and displayName.
			bare := call("POST", "Users", user("bare", nil), 201)
			if bare["displayName"] != "bare@example.test" || fmt.Sprint(bare["name"]) != "map[formatted:bare@example.test]" {
				t.Fatal("the primary email did not supply the name and displayName", bare)
			}
			// Twenty emails and a 254-character address fit; more do not.
			many := make([]string, 21)
			for i := range many {
				many[i] = fmt.Sprintf("many%02d@example.test", i)
			}
			call("POST", "Users", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "twenty", "emails": emails(many[:20]...)}, 201)
			call("POST", "Users", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "twentyone", "emails": emails(many...)}, 400)
			long := func(n int) string {
				domain := strings.Repeat("x", 63) + "." + strings.Repeat("y", 63) + "." + strings.Repeat("z", n-1-64-63-1-63-1-5) + ".test"
				return strings.Repeat("a", 64) + "@" + domain
			}
			call("POST", "Users", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "long", "emails": emails(long(254))}, 201)
			call("POST", "Users", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "longer", "emails": emails(long(255))}, 400)
			// The profile strings round-trip, and PUT without them clears them.
			strs := map[string]any{"title": "Engineer", "userType": "Employee", "preferredLanguage": "en-GB", "locale": "en-GB", "timezone": "Europe/London"}
			created := call("POST", "Users", user("profile", strs), 201)
			path := "Users/" + created["id"].(string)
			for _, got := range []map[string]any{created, call("GET", path, nil, 200)} {
				for k, v := range strs {
					if got[k] != v {
						t.Fatal("a profile string did not round-trip", k, got[k])
					}
				}
			}
			cleared := call("PUT", path, user("profile", nil), 200)
			for k := range strs {
				if _, ok := cleared[k]; ok {
					t.Fatal("PUT kept a profile string it did not send", k)
				}
			}
			// PATCH adds, replaces and removes the profile strings.
			call("PATCH", path, patch(map[string]any{"op": "add", "path": "userType", "value": "Contractor"}, map[string]any{"op": "add", "path": "preferredLanguage", "value": "fr"}), 200)
			replaced := call("PATCH", path, patch(map[string]any{"op": "replace", "path": "userType", "value": "Employee"}, map[string]any{"op": "replace", "path": "preferredLanguage", "value": "de"}), 200)
			if replaced["userType"] != "Employee" || replaced["preferredLanguage"] != "de" {
				t.Fatal("PATCH replace did not change the profile strings", replaced)
			}
			var removes []map[string]any
			for k := range strs {
				removes = append(removes, map[string]any{"op": "remove", "path": k})
			}
			removed := call("PATCH", path, patch(removes...), 200)
			for k := range strs {
				if _, ok := removed[k]; ok {
					t.Fatal("PATCH remove kept a profile string", k)
				}
			}
			// active: a remove restores the default of true.
			if got := call("PATCH", path, patch(map[string]any{"op": "add", "path": "active", "value": false}), 200); got["active"] != false {
				t.Fatal("PATCH add active false did not deactivate the User", got)
			}
			if got := call("PATCH", path, patch(map[string]any{"op": "remove", "path": "active"}), 200); got["active"] != true || call("GET", path, nil, 200)["active"] != true {
				t.Fatal("PATCH remove active did not restore true", got)
			}
			// Null subattributes inside whole values are dropped.
			addr := call("PATCH", path, patch(map[string]any{"op": "replace", "path": "addresses", "value": []map[string]any{{"type": "work", "locality": "Bath", "region": nil}}}), 200)
			if a := addr["addresses"].([]any)[0].(map[string]any); a["locality"] != "Bath" || a["region"] != nil {
				t.Fatal("a null address subattribute was kept", addr)
			}
			mail := call("PATCH", path, patch(map[string]any{"op": "replace", "value": map[string]any{"emails": []map[string]any{{"value": "profile@example.test", "type": nil}}}}), 200)
			if m := mail["emails"].([]any)[0].(map[string]any); m["value"] != "profile@example.test" || m["type"] != nil {
				t.Fatal("a null email subattribute was kept", mail)
			}
			if _, has := mail["emails"].([]any)[0].(map[string]any)["type"]; has {
				t.Fatal("a null email type was stored", mail)
			}
			group := call("POST", "Groups", map[string]any{"schemas": []string{scim.GroupSchema}, "displayName": "Team"}, 201)
			call("PATCH", "Groups/"+group["id"].(string), patch(map[string]any{"op": "add", "path": "members", "value": []map[string]any{{"value": created["id"], "display": nil}}}), 200)
		})
	}
}
