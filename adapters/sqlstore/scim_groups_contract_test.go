package sqlstore

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/scim"
	"github.com/Plain-Org/plain-auth/schema"
)

// The Groups routes check scopes, refuse unusable members and names, list
// and filter Groups, narrow a single read, merge PATCH forms and honour the
// Entra marker only when it is accepted, as another runtime does.
func TestSCIMGroupContract(t *testing.T) {
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
			connections := []scim.Connection{
				{Directory: scim.Directory{ID: "ACME", ProvisioningDomainID: "domain"}, Credentials: []scim.Credential{{ID: "full", Token: "first"}, {ID: "read", Token: "readgroups", Scopes: []string{scim.GroupsRead}},
					{ID: "edit", Token: "writegroups", Scopes: []string{scim.GroupsWrite}}, {ID: "users", Token: "usersonly", Scopes: []string{scim.UsersRead, scim.UsersWrite}},
					{ID: "usersread", Token: "usersread", Scopes: []string{scim.UsersRead}}, {ID: "userswrite", Token: "userswrite", Scopes: []string{scim.UsersWrite}}}},
				{Directory: scim.Directory{ID: "other", ProvisioningDomainID: "domain"}, Credentials: []scim.Credential{{ID: "full", Token: "second"}}},
			}
			h, e := scim.New(host, scim.Options{Store: s, AcceptLegacyEntraGroupSchema: true, Connections: connections})
			must(e)
			strict, e := scim.New(host, scim.Options{Store: s, Connections: connections})
			must(e)
			call := func(handler http.Handler, method, path, token string, data map[string]any, status int, scimType string) map[string]any {
				t.Helper()
				w := scimRequest(handler, method, path, token, data)
				var m map[string]any
				if w.Code != 204 {
					must(json.Unmarshal(w.Body.Bytes(), &m))
				}
				if w.Code != status || scimType != "" && m["scimType"] != scimType {
					t.Fatalf("%s %s: %d %s, want %d %s", method, path, w.Code, w.Body.String(), status, scimType)
				}
				return m
			}
			// Users scopes split read from write.
			call(h, "POST", "Users", "usersread", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "nobody@example.test"}, 403, "")
			call(h, "GET", "Users", "userswrite", nil, 403, "")
			user := func(name string) string {
				t.Helper()
				return call(h, "POST", "Users", "first", map[string]any{"schemas": []string{scim.UserSchema}, "userName": name + "@example.test", "displayName": name}, 201, "")["id"].(string)
			}
			a, b := user("Ada"), user("Bea")
			members := func(ids ...string) []map[string]any {
				out := []map[string]any{}
				for _, id := range ids {
					out = append(out, map[string]any{"value": id, "type": "User"})
				}
				return out
			}
			group := func(name string, ids ...string) map[string]any {
				return map[string]any{"schemas": []string{scim.GroupSchema}, "displayName": name, "members": members(ids...)}
			}
			patch := func(ops ...map[string]any) map[string]any {
				return map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": ops}
			}
			op := func(name, path string, value any) map[string]any {
				m := map[string]any{"op": name, "path": path}
				if value != nil {
					m["value"] = value
				}
				return m
			}
			// Unusable Groups are refused.
			many := make([]map[string]any, scim.MaxGroupMembers+1)
			for i := range many {
				many[i] = map[string]any{"value": fmt.Sprintf("member-%04d", i)}
			}
			var owner string
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "userId" FROM "scimUser" WHERE "id"=?`), a).Scan(&owner))
			for name, body := range map[string]map[string]any{
				"too many members":    {"schemas": []string{scim.GroupSchema}, "displayName": "Many", "members": many},
				"Group member":        {"schemas": []string{scim.GroupSchema}, "displayName": "Nested", "members": []map[string]any{{"value": a, "type": "Group"}}},
				"no displayName":      {"schemas": []string{scim.GroupSchema}, "members": members(a)},
				"account ID as value": group("Accounts", owner),
			} {
				if w := scimRequest(h, "POST", "Groups", "first", body); w.Code != 400 || !strings.Contains(w.Body.String(), `"scimType":"invalidValue"`) {
					t.Fatal("an unusable Group was not refused", name, w.Code, w.Body.String())
				} else if name == "too many members" && !strings.Contains(w.Body.String(), "Expected an array of up to 1000 direct User members") {
					t.Fatal("a Group over the member limit was not refused for its size", w.Body.String())
				}
			}
			// The Entra marker is accepted only when the handler accepts it.
			entra := group("Legacy", a)
			entra["schemas"] = []string{scim.GroupSchema, "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group"}
			call(strict, "POST", "Groups", "first", entra, 400, "invalidValue")
			first := call(h, "POST", "Groups", "writegroups", group("Engineering", a), 201, "")
			time.Sleep(5 * time.Millisecond) // creation order is by millisecond
			design := group("Design", b)
			design["externalId"] = "design-dept"
			second := call(h, "POST", "Groups", "first", design, 201, "")
			path := "Groups/" + first["id"].(string)
			// Group membership grants nothing by itself.
			var grants int
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "scimProjectionGrant" WHERE "userId"=?`), owner).Scan(&grants))
			if grants != 0 {
				t.Fatal("a Group membership granted an authorization", grants)
			}
			// Group scopes split read from write.
			for _, token := range []string{"writegroups", "usersonly"} {
				call(h, "GET", path, token, nil, 403, "")
			}
			for _, token := range []string{"readgroups", "usersonly"} {
				call(h, "PUT", path, token, group("Engineering", a), 403, "")
				call(h, "PATCH", path, token, patch(op("add", "displayName", "Engineering")), 403, "")
			}
			call(h, "PATCH", path, "writegroups", patch(op("add", "displayName", "Engineering")), 200, "")
			// Lists keep creation order and filter by id; member filters are refused.
			list := call(h, "GET", "Groups", "readgroups", nil, 200, "")
			if resources := list["Resources"].([]any); len(resources) != 2 || resources[0].(map[string]any)["id"] != first["id"] || resources[1].(map[string]any)["id"] != second["id"] {
				t.Fatal("the Group list is not in creation order", list)
			}
			byID := call(h, "GET", "Groups?"+url.Values{"filter": {`id eq "` + first["id"].(string) + `"`}}.Encode(), "readgroups", nil, 200, "")
			if byID["totalResults"] != float64(1) || byID["Resources"].([]any)[0].(map[string]any)["id"] != first["id"] {
				t.Fatal("an id filter did not return that Group", byID)
			}
			for _, filter := range []string{`displayName eq "design"`, `externalId eq "design-dept"`} {
				if got := call(h, "GET", "Groups?"+url.Values{"filter": {filter}}.Encode(), "readgroups", nil, 200, ""); got["totalResults"] != float64(1) || got["Resources"].([]any)[0].(map[string]any)["id"] != second["id"] {
					t.Fatal("a displayName or externalId filter did not return that Group", filter, got)
				}
			}
			call(h, "GET", "Groups?"+url.Values{"filter": {`members.value eq "x"`}}.Encode(), "readgroups", nil, 400, "invalidFilter")
			if legacy := call(h, "POST", "Groups", "first", entra, 201, ""); fmt.Sprint(legacy["schemas"]) != "["+scim.GroupSchema+"]" {
				t.Fatal("an accepted Entra marker was echoed", legacy["schemas"])
			}
			// A single read narrows its response.
			narrowed := call(h, "GET", path+"?attributes=displayName", "readgroups", nil, 200, "")
			if narrowed["displayName"] != "Engineering" || narrowed["members"] != nil || narrowed["id"] == nil {
				t.Fatal("attributes did not narrow a Group read", narrowed)
			}
			excluded := call(h, "GET", path+"?excludedAttributes=members", "readgroups", nil, 200, "")
			if excluded["members"] != nil || excluded["displayName"] != "Engineering" || excluded["meta"] == nil {
				t.Fatal("excludedAttributes did not narrow a Group read", excluded)
			}
			call(h, "GET", path+"?attributes=displayName&excludedAttributes=members", "readgroups", nil, 400, "invalidValue")
			// Another directory cannot see the Group, and names stay unique.
			call(h, "PUT", path, "second", group("Engineering", a), 404, "")
			call(h, "PATCH", path, "second", patch(op("replace", "displayName", "Elsewhere")), 404, "")
			call(h, "PUT", path, "first", group("DESIGN", a), 409, "uniqueness")
			call(h, "PATCH", path, "first", patch(op("replace", "displayName", "design")), 409, "uniqueness")
			call(h, "PATCH", path, "first", patch(op("replace", "displayName", "")), 400, "invalidValue")
			if got := call(h, "PATCH", path, "first", patch(op("add", "displayName", "Platform")), 200, ""); got["displayName"] != "Platform" {
				t.Fatal("PATCH add did not set displayName", got)
			}
			// A PUT replaces the Group.
			if put := call(h, "PUT", path, "first", group("Platform", b), 200, ""); put["displayName"] != "Platform" || len(put["members"].([]any)) != 1 || put["members"].([]any)[0].(map[string]any)["value"] != b {
				t.Fatal("a PUT did not replace the Group", put)
			}
			// replace sets the members, and a remove of members without a value clears them.
			replaced := call(h, "PATCH", path, "first", patch(op("replace", "members", members(b))), 200, "")
			if ms := replaced["members"].([]any); len(ms) != 1 || ms[0].(map[string]any)["value"] != b {
				t.Fatal("PATCH replace did not set the members", replaced)
			}
			if cleared := call(h, "PATCH", path, "first", patch(op("remove", "members", nil)), 200, ""); cleared["members"] != nil && len(cleared["members"].([]any)) != 0 {
				t.Fatal("PATCH remove members did not clear them", cleared)
			}
		})
	}
}
