package sqlstore

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/scim"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestSCIMGroupMembershipLifecycle(t *testing.T) {
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
			ddl, e := schema.Generate(dialect, []string{"scim"})
			must(e)
			open := func() (*Store, *scim.Handler) {
				s, e := OpenWithSchema(ctx, dialect, dsn, ddl)
				must(e)
				t.Cleanup(func() { s.Close() })
				host, e := auth.New(auth.Options{BaseURL: "https://directory.test", BasePath: "/identity/custom", Secret: strings.Repeat("x", 32), Store: s})
				must(e)
				h, e := scim.New(host, scim.Options{Store: s, AcceptLegacyEntraGroupSchema: true, Connections: []scim.Connection{
					{Directory: scim.Directory{ID: "ACME", ProvisioningDomainID: "domain"}, Credentials: []scim.Credential{{ID: "full", Token: "first"}, {ID: "read", Token: "readgroups", Scopes: []string{scim.GroupsRead}}, {ID: "edit", Token: "writegroups", Scopes: []string{scim.GroupsWrite}}, {ID: "users", Token: "usersonly", Scopes: []string{scim.UsersRead, scim.UsersWrite}}}},
					{Directory: scim.Directory{ID: "acme", ProvisioningDomainID: "domain"}, Credentials: []scim.Credential{{ID: "full", Token: "second"}}},
				}})
				must(e)
				return s, h
			}
			s, h := open()
			_, replica := open()
			call := func(host http.Handler, method, path, token string, data map[string]any, status int) map[string]any {
				t.Helper()
				w := scimRequest(host, method, path, token, data)
				if w.Code != status || w.Header().Get("Content-Type") != scim.MediaType {
					t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
				}
				var m map[string]any
				if status != 204 {
					must(json.Unmarshal(w.Body.Bytes(), &m))
				}
				return m
			}
			call(h, "GET", "ResourceTypes/Group", "", nil, 200)
			call(h, "GET", "Schemas/"+scim.GroupSchema, "", nil, 200)
			for _, token := range []string{"", "readgroups", "usersonly"} {
				want := 403
				if token == "" {
					want = 401
				}
				call(h, "POST", "Groups", token, nil, want)
			}
			call(h, "GET", "Groups", "writegroups", nil, 403)
			call(h, "GET", "Users", "readgroups", nil, 403)
			user := func(name, token string) string {
				t.Helper()
				return call(h, "POST", "Users", token, map[string]any{"schemas": []string{scim.UserSchema}, "userName": name + "@example.test", "displayName": name}, 201)["id"].(string)
			}
			one, two, three, foreign := user("One", "first"), user("Two", "first"), user("Three", "first"), user("Else", "second")
			values := func(ids ...string) []map[string]any {
				result := []map[string]any{}
				for _, id := range ids {
					result = append(result, map[string]any{"value": id, "type": "User"})
				}
				return result
			}
			profile := func(name, ext string, ids ...string) map[string]any {
				return map[string]any{"schemas": []string{scim.GroupSchema}, "displayName": name, "externalId": ext, "members": values(ids...)}
			}
			patch := func(ops ...map[string]any) map[string]any {
				if ops == nil {
					ops = []map[string]any{}
				}
				return map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": ops}
			}
			op := func(method, path string, value any) map[string]any {
				return map[string]any{"op": method, "path": path, "value": value}
			}
			g := profile("Engineering", "dept", one, one)
			g["schemas"] = []string{scim.GroupSchema, "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group"}
			created := call(h, "POST", "Groups", "writegroups", g, 201)
			id := created["id"].(string)
			path := "Groups/" + id
			ms := created["members"].([]any)
			if len(ms) != 1 {
				t.Fatal(ms)
			}
			m := ms[0].(map[string]any)
			if m["display"] != "One" || m["$ref"] != "https://directory.test"+directoryPath+"Users/"+one || m["type"] != "User" {
				t.Fatal(m)
			}
			call(h, "POST", "Groups", "first", profile("ENGINEERING", "other"), 409)
			call(h, "POST", "Groups", "first", profile("alt", "dept"), 409)
			call(h, "POST", "Groups", "first", profile("foreign", "foreign", foreign), 400)
			call(h, "POST", "Groups", "first", profile("nested", "nested", id), 400)
			peer := call(h, "POST", "Groups", "second", profile("Engineering", "dept", foreign), 201)["id"].(string)
			call(replica, "GET", path, "second", nil, 404)
			call(replica, "DELETE", path, "second", nil, 404)
			if page := call(replica, "GET", "Groups?"+url.Values{"filter": {`displayName eq "ENGINEERING" and externalId eq "dept"`}, "attributes": {"members.value,meta.resourceType"}}.Encode(), "readgroups", nil, 200); page["totalResults"] != float64(1) {
				t.Fatal(page)
			} else {
				entry := page["Resources"].([]any)[0].(map[string]any)
				if len(entry) != 4 || len(entry["members"].([]any)[0].(map[string]any)) != 1 {
					t.Fatal(entry)
				}
			}
			call(h, "PATCH", path, "first", patch(op("replace", "displayName", "rollback"), op("add", "members", values(foreign))), 400)
			call(h, "PATCH", path, "first", patch(op("add", "members", values(foreign)), op("remove", "members", values(foreign))), 400)
			for _, body := range []map[string]any{patch(), patch(op("add", "members", values(one)))} {
				after := call(h, "PATCH", path, "first", body, 200)
				if after["meta"].(map[string]any)["lastModified"] != created["meta"].(map[string]any)["lastModified"] || after["displayName"] != "Engineering" {
					t.Fatal(after)
				}
			}
			start := make(chan struct{})
			res := make(chan *httptest.ResponseRecorder, 2)
			for i, host := range []*scim.Handler{h, replica} {
				go func() {
					<-start
					res <- scimRequest(host, "PATCH", path, "first", patch(op("add", "members", values([]string{two, three}[i]))))
				}()
			}
			close(start)
			for range 2 {
				if w := <-res; w.Code != 200 {
					t.Fatalf("concurrent membership: %s", w.Body.String())
				}
			}
			got := call(h, "GET", path, "readgroups", nil, 200)
			if len(got["members"].([]any)) != 3 {
				t.Fatal("lost additions", got)
			}
			updated := call(replica, "PATCH", path, "first", patch(map[string]any{"op": "remove", "path": `members[value eq "` + two + `"]`}, op("replace", "displayName", []string{"Updated"})), 200)
			if updated["displayName"] != "Updated" || len(updated["members"].([]any)) != 2 {
				t.Fatal(updated)
			}
			// A private external authorization grant must survive any local mutation.
			var owner string
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "userId" FROM "scimUser" WHERE "id"=?`), one).Scan(&owner))
			now := s.date(time.Now())
			_, e = s.db.ExecContext(ctx, s.bind(`INSERT INTO "scimProjectionGrant" ("id","connectionId","provisioningDomainId","scimUserId","userId","sourceKind","sourceId","role","grantKey","createdAt","updatedAt") VALUES (?,?,?,?,?,'group',?,?,?,?,?)`), "grant", "ACME", "domain", one, owner, id, "test", "grant", now, now)
			must(e)
			call(h, "PATCH", path, "first", patch(op("replace", "displayName", "Blocked")), 409)
			call(h, "DELETE", path, "first", nil, 409)
			_, e = s.db.ExecContext(ctx, s.bind(`DELETE FROM "scimProjectionGrant" WHERE "id"=?`), "grant")
			must(e)
			replaced := call(h, "PUT", path, "first", profile("Replacement", "new", one, two), 200)
			time.Sleep(5 * time.Millisecond) // revisions have millisecond precision
			call(replica, "DELETE", "Users/"+one, "first", nil, 204)
			got = call(h, "GET", path, "readgroups", nil, 200)
			ms = got["members"].([]any)
			if len(ms) != 1 || ms[0].(map[string]any)["value"] != two {
				t.Fatal(ms)
			}
			// Losing a member is a new Group revision.
			before, _ := time.Parse(time.RFC3339Nano, replaced["meta"].(map[string]any)["lastModified"].(string))
			after, _ := time.Parse(time.RFC3339Nano, got["meta"].(map[string]any)["lastModified"].(string))
			if !after.After(before) {
				t.Fatal("deleting a member did not revise its Group", replaced["meta"], got["meta"])
			}
			// A deletion ignores a projection, as in another runtime.
			call(replica, "DELETE", path+"?attributes=displayName&excludedAttributes=members", "first", nil, 204)
			call(h, "GET", path, "first", nil, 404)
			var n int
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "scimGroupMember" WHERE "groupId"=?`), id).Scan(&n))
			if n != 0 {
				t.Fatal("membership survived delete")
			}
			call(h, "GET", "Groups/"+peer, "second", nil, 200)
			call(h, "GET", "Users/"+two, "first", nil, 200)
			// A regular account deletion and a directory membership addition must
			// not leave an orphan on engines without enforced inline cascades.
			for attempt := range 4 {
				label := fmt.Sprintf("Race%d", attempt)
				raced := user(label, "first")
				owner, e := s.FindAccountUser(ctx, strings.ToLower(label)+"@example.test")
				must(e)
				g := call(h, "POST", "Groups", "first", profile(label, label), 201)["id"].(string)
				stamp := time.Now().UTC().Truncate(time.Millisecond)
				ss := auth.StoredSession{Session: auth.Session{ID: label, Token: label, UserID: owner.ID, CreatedAt: stamp, UpdatedAt: stamp, ExpiresAt: stamp.Add(time.Hour)}}
				must(s.CreateSession(ctx, ss))
				start := make(chan struct{})
				removed := make(chan error, 1)
				added := make(chan *httptest.ResponseRecorder, 1)
				go func() { <-start; removed <- s.DeleteAccount(ctx, owner.ID, ss.Token, "", "", stamp) }()
				go func() {
					<-start
					added <- scimRequest(replica, "PATCH", "Groups/"+g, "first", patch(op("add", "members", values(raced))))
				}()
				close(start)
				must(<-removed)
				w := <-added
				if w.Code != 200 && w.Code != 400 {
					t.Fatalf("delete/add race %d %s", w.Code, w.Body.String())
				}
				must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "scimGroupMember" WHERE "scimUserId"=?`), raced).Scan(&n))
				if n != 0 {
					t.Fatal("orphaned directory membership")
				}
			}
			// Populate enough real provisioned users to cross both a SQL batch
			// boundary and the public direct-membership limit.
			d := scim.Directory{ID: "ACME", ProvisioningDomainID: "domain"}
			ids := make([]string, scim.MaxGroupMembers)
			must(s.scimTx(ctx, d, func(tx *sql.Tx) error {
				stamp := time.Now().UTC().Truncate(time.Millisecond)
				for i := range ids {
					id := fmt.Sprintf("bounded-%04d", i)
					ids[i] = id
					email := id + "@example.test"
					_, e := tx.ExecContext(ctx, s.bind(`INSERT INTO "user" ("id","name","email","emailVerified","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), id, id, email, false, s.date(stamp), s.date(stamp))
					if e != nil {
						return e
					}
					p := scim.Profile{UserName: email, DisplayName: id, Active: true, PrimaryEmail: email, Attributes: map[string]any{"schemas": []any{scim.UserSchema}, "name": map[string]any{"formatted": id}, "emails": []any{map[string]any{"value": email, "primary": true}}}}
					if e = s.scimInsert(ctx, tx, d, directoryUser{Record: scim.Record{ID: id, Profile: p, CreatedAt: stamp, UpdatedAt: stamp}, owner: id}); e != nil {
						return e
					}
				}
				return nil
			}))
			bounded := call(h, "POST", "Groups", "first", profile("Large", "large", ids...), 201)
			bp := "Groups/" + bounded["id"].(string)
			if len(bounded["members"].([]any)) != scim.MaxGroupMembers {
				t.Fatal("partial Group")
			}
			call(h, "PATCH", bp, "first", patch(op("add", "members", values(two))), 400)
			call(replica, "PATCH", bp, "first", patch(op("remove", "members", values(ids[0])), op("add", "members", values(two))), 200)
			groups := call(replica, "GET", bp+"?attributes=members.value", "readgroups", nil, 200)
			var actual []string
			for _, item := range groups["members"].([]any) {
				actual = append(actual, item.(map[string]any)["value"].(string))
			}
			if len(actual) != scim.MaxGroupMembers || !slices.Contains(actual, two) || slices.Contains(actual, ids[0]) {
				t.Fatal("wrong membership boundary")
			}
		})
	}
}

// Group PATCH accepts schema-prefixed and pathless forms and null removal,
// and the legacy Entra marker is honoured only on creation.
func TestSCIMGroupPatchRouteForms(t *testing.T) {
	const marker = "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group"
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ddl, err := schema.Generate(dialect, []string{"scim"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(t.Context(), dialect, organizationTestDSN(t, dialect), ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			host, err := auth.New(auth.Options{BaseURL: "https://directory.test", BasePath: "/identity/custom", Secret: strings.Repeat("x", 32), Store: store})
			if err != nil {
				t.Fatal(err)
			}
			h, err := scim.New(host, scim.Options{Store: store, AcceptLegacyEntraGroupSchema: true, Connections: []scim.Connection{{Directory: scim.Directory{ID: "ACME", ProvisioningDomainID: "domain"}, Credentials: []scim.Credential{{ID: "full", Token: "first"}}}}})
			if err != nil {
				t.Fatal(err)
			}
			call := func(method, path string, body map[string]any, status int, failure string) map[string]any {
				t.Helper()
				w := scimRequest(h, method, path, "first", body)
				if w.Code != status {
					t.Fatal(failure, w.Code, w.Body.String())
				}
				var out map[string]any
				_ = json.Unmarshal(w.Body.Bytes(), &out)
				return out
			}
			patch := func(ops ...map[string]any) map[string]any {
				return map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": ops}
			}
			member := call("POST", "Users", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "member@example.test"}, 201, "a User was refused")["id"].(string)
			created := call("POST", "Groups", map[string]any{"schemas": []string{scim.GroupSchema, marker}, "displayName": "Engineering", "members": []any{map[string]any{"value": member}}}, 201, "a Group with the legacy marker was refused on creation")
			if !jsonEqual(created["schemas"], []string{scim.GroupSchema}) {
				t.Fatal("a created Group echoed the legacy Entra marker", created["schemas"])
			}
			id := created["id"].(string)
			if got := call("GET", "Groups/"+id, nil, 200, "GET failed"); !jsonEqual(got["schemas"], []string{scim.GroupSchema}) {
				t.Fatal("a stored Group carried the legacy Entra marker", got["schemas"])
			}
			if body := call("PUT", "Groups/"+id, map[string]any{"schemas": []string{scim.GroupSchema, marker}, "displayName": "Engineering"}, 400, "PUT accepted the legacy Entra Group marker"); body["scimType"] != "invalidValue" {
				t.Fatal("PUT accepted the legacy Entra Group marker", body)
			}
			call("PATCH", "Groups/"+id, map[string]any{"schemas": []string{scim.PatchSchema, marker}, "Operations": []any{map[string]any{"op": "replace", "path": "displayName", "value": "X"}}}, 400, "PATCH accepted the legacy marker in its schema list")
			withMarker := patch(map[string]any{"op": "replace", "path": "displayName", "value": "X"})
			withMarker[marker] = map[string]any{}
			if body := call("PATCH", "Groups/"+id, withMarker, 400, "PATCH accepted a legacy marker object"); body["scimType"] != "invalidValue" {
				t.Fatal("PATCH accepted a legacy marker object", body)
			}
			if got := call("GET", "Groups/"+id, nil, 200, "GET failed"); got["displayName"] != "Engineering" {
				t.Fatal("a refused legacy marker PATCH changed the Group", got["displayName"])
			}
			if w := scimRequest(h, "GET", "Schemas", "", nil); strings.Contains(w.Body.String(), "ADSCIM") {
				t.Fatal("the schema listing advertised the legacy Entra marker")
			}
			if w := scimRequest(h, "GET", "ResourceTypes", "", nil); strings.Contains(w.Body.String(), "ADSCIM") {
				t.Fatal("the resource types advertised the legacy Entra marker")
			}
			if w := scimRequest(h, "GET", "Schemas/"+scim.GroupSchema, "", nil); strings.Contains(w.Body.String(), "ADSCIM") {
				t.Fatal("the Group schema advertised the legacy Entra marker")
			}

			group := func() map[string]any { t.Helper(); return call("GET", "Groups/"+id, nil, 200, "GET failed") }
			call("PATCH", "Groups/"+id, patch(map[string]any{"op": "replace", "path": scim.GroupSchema + ":displayName", "value": "Platform"}), 200, "a schema-prefixed Group path was not applied")
			if group()["displayName"] != "Platform" {
				t.Fatal("a schema-prefixed Group path was not applied")
			}
			call("PATCH", "Groups/"+id, patch(map[string]any{"op": "Replace", "value": map[string]any{"displayName": "Ops", "externalId": "ops-1", "schemas": nil, "meta": nil}}), 200, "a pathless Group value was refused")
			if g := group(); g["displayName"] != "Ops" {
				t.Fatal("a pathless Group displayName was not applied", g)
			}
			if g := group(); g["externalId"] != "ops-1" {
				t.Fatal("a pathless Group externalId was not applied", g)
			}
			call("PATCH", "Groups/"+id, patch(map[string]any{"op": "remove", "path": scim.GroupSchema + `:members[value eq "` + member + `"]`}), 200, "a schema-prefixed member selector did not remove the member")
			if members, _ := group()["members"].([]any); len(members) != 0 {
				t.Fatal("a schema-prefixed member selector did not remove the member", members)
			}
			call("PATCH", "Groups/"+id, patch(map[string]any{"op": "add", "path": "members", "value": []any{map[string]any{"value": member}}}), 200, "adding a member failed")
			call("PATCH", "Groups/"+id, patch(map[string]any{"op": "replace", "path": "members", "value": nil}), 200, "a null Group members value did not clear the membership")
			if members, _ := group()["members"].([]any); len(members) != 0 {
				t.Fatal("a null Group members value did not clear the membership", members)
			}
			if body := call("PATCH", "Groups/"+id, patch(map[string]any{"op": "replace", "path": "displayName", "value": nil}), 400, "a null Group displayName PATCH was accepted"); body["scimType"] != "mutability" {
				t.Fatal("a null Group displayName PATCH was accepted", body)
			}
			if body := call("PATCH", "Groups/"+id, patch(map[string]any{"op": "replace", "value": map[string]any{"displayName": "A", "DisplayName": "B"}}), 400, "a Group PATCH value naming displayName twice was not invalidSyntax"); body["scimType"] != "invalidSyntax" {
				t.Fatal("a Group PATCH value naming displayName twice was not invalidSyntax", body)
			}

			call("PATCH", "Groups/"+id, patch(map[string]any{"op": "add", "path": "externalId", "value": "grp-2"}), 200, "PATCH did not add a Group externalId")
			if group()["externalId"] != "grp-2" {
				t.Fatal("PATCH did not add a Group externalId")
			}
			call("PATCH", "Groups/"+id, patch(map[string]any{"op": "replace", "path": "externalId", "value": "grp-3"}), 200, "replacing the externalId failed")
			if list := call("GET", `Groups?filter=externalId%20eq%20%22grp-3%22`, nil, 200, "the filtered list failed"); list["totalResults"] != 1.0 {
				t.Fatal("a replaced Group externalId is not filterable", list["totalResults"])
			}
			call("PATCH", "Groups/"+id, patch(map[string]any{"op": "remove", "path": "externalId"}), 200, "removing the externalId failed")
			if _, has := group()["externalId"]; has {
				t.Fatal("PATCH did not clear a Group externalId")
			}
			call("PATCH", "Groups/"+id, patch(map[string]any{"op": "add", "path": "externalId", "value": "grp-4"}), 200, "re-adding the externalId failed")
			call("PATCH", "Groups/"+id, patch(map[string]any{"op": "replace", "path": "externalId", "value": nil}), 200, "a null Group externalId did not clear it")
			if _, has := group()["externalId"]; has {
				t.Fatal("a null Group externalId did not clear it")
			}
		})
	}
}

// Group routes refuse oversized and nested member lists and the classic
// Entra marker without its option, and each scope admits only its routes.
func TestSCIMGroupRouteRefusals(t *testing.T) {
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
			h, e := scim.New(host, scim.Options{Store: s, Connections: []scim.Connection{{Directory: scim.Directory{ID: "ACME", ProvisioningDomainID: "domain"}, Credentials: []scim.Credential{
				{ID: "full", Token: "first"}, {ID: "reader", Token: "usersread", Scopes: []string{scim.UsersRead}}, {ID: "writer", Token: "userswrite", Scopes: []string{scim.UsersWrite}}}}}})
			must(e)
			status := func(method, path, token string, body map[string]any) (int, string) {
				t.Helper()
				w := scimRequest(h, method, path, token, body)
				var m map[string]any
				_ = json.Unmarshal(w.Body.Bytes(), &m)
				kind, _ := m["scimType"].(string)
				return w.Code, kind
			}
			members := []map[string]any{}
			for i := range scim.MaxGroupMembers + 1 {
				members = append(members, map[string]any{"value": fmt.Sprintf("u-%04d", i)})
			}
			if code, kind := status("POST", "Groups", "first", map[string]any{"schemas": []string{scim.GroupSchema}, "displayName": "Crowd", "members": members}); code != 400 || kind != "invalidValue" {
				t.Fatal("a Group with 1,001 members was not refused with invalidValue", code, kind)
			}
			if code, _ := status("POST", "Groups", "first", map[string]any{"schemas": []string{scim.GroupSchema}, "displayName": "Nested", "members": []map[string]any{{"value": "g-1", "type": "Group"}}}); code != 400 {
				t.Fatal("a Group with a nested Group member was not refused", code)
			}
			legacy := "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group"
			if code, kind := status("POST", "Groups", "first", map[string]any{"schemas": []string{scim.GroupSchema, legacy}, "displayName": "Classic"}); code != 400 || kind != "invalidValue" {
				t.Fatal("the classic Entra Group marker was accepted without its option", code, kind)
			}
			if code, _ := status("POST", "Users", "usersread", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "reader@example.test"}); code != 403 {
				t.Fatal("a read-only credential created a User", code)
			}
			if code, _ := status("GET", "Users", "userswrite", nil); code != 403 {
				t.Fatal("a write-only credential listed Users", code)
			}
			if code, _ := status("GET", "Users", "usersread", nil); code != 200 {
				t.Fatal("a read credential could not list Users", code)
			}
			// A Group body drops values that only hold nulls, and refuses two
			// spellings of a member subattribute.
			w := scimRequest(h, "POST", "Users", "first", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "member@example.test"})
			var member map[string]any
			must(json.Unmarshal(w.Body.Bytes(), &member))
			w = scimRequest(h, "POST", "Groups", "first", map[string]any{"schemas": []string{scim.GroupSchema}, "displayName": "Stripped", "externalId": map[string]any{"x": nil},
				"members": []map[string]any{{"value": member["id"], "type": map[string]any{"x": nil}}}})
			var stripped map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &stripped)
			if members, _ := stripped["members"].([]any); w.Code != 201 || stripped["externalId"] != nil || len(members) != 1 {
				t.Fatal("a Group body did not drop values holding only nulls", w.Code, w.Body.String())
			}
			// A PATCH member entry drops its null subattributes too.
			w = scimRequest(h, "PATCH", "Groups/"+stripped["id"].(string), "first", map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []any{
				map[string]any{"op": "replace", "path": "members", "value": []map[string]any{{"value": member["id"], "type": map[string]any{"x": nil}}}}}})
			if w.Code != 200 {
				t.Fatal("a PATCH member entry with a null-only type was refused", w.Code, w.Body.String())
			}
			for _, entry := range []map[string]any{{"value": member["id"], "display": "a", "Display": "b"}, {"value": member["id"], "$ref": "a", "$REF": "b"}} {
				if code, kind := status("POST", "Groups", "first", map[string]any{"schemas": []string{scim.GroupSchema}, "displayName": "Twice", "members": []map[string]any{entry}}); code != 400 || kind != "invalidSyntax" {
					t.Fatal("a Group member naming a subattribute twice was not invalidSyntax", entry, code, kind)
				}
			}
		})
	}
}
