package sqlstore

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/scim"
	"github.com/Plain-Org/plain-auth/schema"
)

type attributeCall func(method, path string, body map[string]any, status int, failure string) map[string]any

// attributeDirectory opens a SCIM store with one connection and returns a
// call helper that fails the test with failure on an unexpected status.
func attributeDirectory(t *testing.T, dialect string) (*Store, attributeCall) {
	t.Helper()
	ddl, err := schema.Generate(dialect, []string{"scim"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenWithSchema(t.Context(), dialect, organizationTestDSN(t, dialect), ddl)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	host, err := auth.New(auth.Options{BaseURL: "https://directory.example.test", BasePath: "/identity/custom", Secret: strings.Repeat("a", 32), Store: store})
	if err != nil {
		t.Fatal(err)
	}
	h, err := scim.New(host, scim.Options{Store: store, Connections: []scim.Connection{{Directory: scim.Directory{ID: "Attributes", ProvisioningDomainID: "Tenant"}, Credentials: []scim.Credential{{ID: "owned", Token: "attribute-token"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	return store, func(method, path string, body map[string]any, status int, failure string) map[string]any {
		t.Helper()
		w := scimRequest(h, method, path, "attribute-token", body)
		if w.Code != status {
			t.Fatal(failure, w.Code, w.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
}

// Null attributes are dropped on create and replace, classic name parts and
// unsupported attributes are handled as documented, and custom extensions
// are refused.
func TestSCIMUserAttributesOverHTTP(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store, call := attributeDirectory(t, dialect)
			user := func(fields map[string]any) map[string]any {
				body := map[string]any{"schemas": []string{scim.UserSchema}}
				for k, v := range fields {
					body[k] = v
				}
				return body
			}
			created := call("POST", "Users", user(map[string]any{"externalId": "jyoung", "userName": "jyoung@example.test", "active": true, "addresses": nil, "phoneNumbers": nil, "preferredLanguage": nil, "title": nil,
				"displayName": "Joy Young", "name": map[string]any{"givenName": "Joy", "familyName": "Young", "middleName": nil}, "emails": []any{map[string]any{"type": "work", "value": "jyoung@example.test", "primary": nil}},
				"meta": map[string]any{"resourceType": "User"}}), 201, "the documented Entra create with null attributes was refused")
			if _, has := created["title"]; has {
				t.Fatal("a null attribute was stored on creation", created)
			}
			if _, has := created["preferredLanguage"]; has {
				t.Fatal("a null attribute was stored on creation", created)
			}
			if _, has := created["name"].(map[string]any)["middleName"]; has {
				t.Fatal("a null name part was stored", created["name"])
			}
			want := []any{map[string]any{"value": "jyoung@example.test", "type": "work", "primary": true}}
			if !jsonEqual(created["emails"], want) {
				t.Fatal("a null email subattribute was kept", created["emails"])
			}
			id := created["id"].(string)
			replace := func(fields map[string]any, status int, failure string) {
				t.Helper()
				body := user(map[string]any{"externalId": "jyoung", "userName": "jyoung@example.test", "displayName": "Joy Young", "emails": []any{map[string]any{"value": "jyoung@example.test", "primary": true}}})
				for k, v := range fields {
					body[k] = v
				}
				call("PUT", "Users/"+id, body, status, failure)
			}
			replace(map[string]any{"title": "Engineer"}, 200, "PUT with a title failed")
			replace(nil, 200, "PUT without a title failed")
			if got := call("GET", "Users/"+id, nil, 200, "GET failed"); got["title"] != nil {
				t.Fatal("PUT kept an attribute it omitted", got["title"])
			}
			replace(map[string]any{"active": nil}, 400, "PUT accepted a null active value")
			if got := call("GET", "Users/"+id, nil, 200, "GET failed"); got["active"] != true {
				t.Fatal("PUT accepted a null active value", got["active"])
			}
			call("POST", "Users", user(map[string]any{"userName": nil}), 400, "a null userName was accepted")
			call("POST", "Users", user(map[string]any{"userName": "nulls@example.test", "emails": []any{nil}}), 400, "a null email entry was accepted")

			// Classic name parts.
			parts := map[string]any{"givenName": "Ada", "familyName": "Lovelace", "middleName": "Byron", "honorificPrefix": "Countess", "honorificSuffix": "FRS"}
			ada := call("POST", "Users", user(map[string]any{"userName": "ada@example.test", "name": parts}), 201, "a User with classic name parts was refused")
			name := func(m map[string]any) map[string]any { n, _ := m["name"].(map[string]any); return n }
			for k, v := range parts {
				if name(ada)[k] != v {
					t.Fatal("classic name parts were not returned on creation", name(ada))
				}
			}
			if name(ada)["formatted"] != "Ada Lovelace" {
				t.Fatal("classic name parts were not returned on creation", name(ada))
			}
			adaID := ada["id"].(string)
			got := call("GET", "Users/"+adaID, nil, 200, "GET failed")
			for k, v := range parts {
				if name(got)[k] != v {
					t.Fatal("classic name parts were not stored", name(got))
				}
			}
			call("PUT", "Users/"+adaID, user(map[string]any{"userName": "ada@example.test", "name": map[string]any{"middleName": "King"}}), 200, "PUT with a name part failed")
			got = call("GET", "Users/"+adaID, nil, 200, "GET failed")
			if n := name(got); n["middleName"] != "King" || n["givenName"] != nil || n["honorificPrefix"] != nil || n["honorificSuffix"] != nil {
				t.Fatal("PUT did not replace the classic name parts", n)
			}

			// Custom extensions, groups and unsupported attributes.
			custom := user(map[string]any{"userName": "badge@example.test", "urn:example:custom:2.0:User": map[string]any{"badge": "7"}})
			custom["schemas"] = []string{scim.UserSchema, "urn:example:custom:2.0:User"}
			if body := call("POST", "Users", custom, 400, "a User with a custom schema extension was accepted"); body["scimType"] != "invalidValue" {
				t.Fatal("a User with a custom schema extension was accepted", body)
			}
			if body := call("POST", "Groups", map[string]any{"schemas": []string{scim.GroupSchema, "urn:example:custom:2.0:Group"}, "displayName": "X"}, 400, "a Group with a custom schema extension was accepted"); body["scimType"] != "invalidValue" {
				t.Fatal("a Group with a custom schema extension was accepted", body)
			}
			grouped := call("POST", "Users", user(map[string]any{"userName": "grouped@example.test", "groups": []any{map[string]any{"value": "g-1", "display": "Group"}}}), 201, "a User with groups was refused")
			if _, has := grouped["groups"]; has {
				t.Fatal("a User response carried a groups attribute", grouped)
			}
			if got := call("GET", "Users/"+grouped["id"].(string), nil, 200, "GET failed"); got["groups"] != nil {
				t.Fatal("a User stored a supplied groups value", got)
			}
			userSchema := call("GET", "Schemas/"+scim.UserSchema, nil, 200, "the User schema was not served")
			var names []string
			for _, a := range userSchema["attributes"].([]any) {
				names = append(names, a.(map[string]any)["name"].(string))
			}
			if slices.Contains(names, "groups") {
				t.Fatal("the User schema advertised groups", names)
			}
			ignored := call("POST", "Users", user(map[string]any{"userName": "secret@example.test", "password": "Secret-Value-1", "ims": []any{map[string]any{"value": "im-1"}},
				"photos": []any{map[string]any{"value": "https://example.test/p.png"}}, "x509Certificates": []any{map[string]any{"value": "MIIB"}}}), 201, "a User with unsupported attributes was refused")
			for _, key := range []string{"password", "ims", "photos", "x509Certificates"} {
				if _, has := ignored[key]; has {
					t.Fatal("an unsupported User attribute was returned", key)
				}
			}
			var serialized string
			if err := store.db.QueryRowContext(t.Context(), store.bind(`SELECT "serializedAttributes" FROM "scimUser" WHERE "id"=?`), ignored["id"]).Scan(&serialized); err != nil {
				t.Fatal(err)
			}
			for _, needle := range []string{`"password"`, "Secret-Value-1", `"ims"`, `"photos"`, `"x509Certificates"`} {
				if strings.Contains(serialized, needle) {
					t.Fatal("an unsupported User attribute was stored", needle)
				}
			}
		})
	}
}

// Null Group attributes are dropped, a null member subattribute keeps the
// member, and a null members list on PUT empties the Group.
func TestSCIMGroupNullAttributesOverHTTP(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			_, call := attributeDirectory(t, dialect)
			member := call("POST", "Users", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "member@example.test"}, 201, "a User was refused")["id"].(string)
			group := call("POST", "Groups", map[string]any{"schemas": []string{scim.GroupSchema}, "displayName": "Engineering", "externalId": nil, "members": []any{map[string]any{"value": member, "display": nil}}}, 201, "a Group with null attributes was refused")
			if _, has := group["externalId"]; has {
				t.Fatal("a null Group externalId was stored", group)
			}
			members, _ := group["members"].([]any)
			if len(members) != 1 || members[0].(map[string]any)["value"] != member {
				t.Fatal("a null member subattribute dropped the member", group["members"])
			}
			id := group["id"].(string)
			call("PUT", "Groups/"+id, map[string]any{"schemas": []string{scim.GroupSchema}, "displayName": "Engineering", "members": nil}, 200, "PUT with null members failed")
			if got := call("GET", "Groups/"+id, nil, 200, "GET failed"); len(got["members"].([]any)) != 0 {
				t.Fatal("PUT kept Group members it sent as null", got["members"])
			}
			call("POST", "Groups", map[string]any{"schemas": []string{scim.GroupSchema}, "displayName": nil}, 400, "a null Group displayName was accepted")
		})
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// PATCH replaces, adds and removes the scalar User attributes, the account
// name follows displayName, and null subattributes in whole values are
// treated as omitted.
func TestSCIMUserScalarPatchOverHTTP(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store, call := attributeDirectory(t, dialect)
			created := call("POST", "Users", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "scalar@example.test", "externalId": "ext-1", "name": map[string]any{"formatted": "Ada Lovelace"}, "displayName": "Countess"}, 201, "the User was refused")
			id := created["id"].(string)
			patch := func(status int, failure string, ops ...map[string]any) map[string]any {
				t.Helper()
				return call("PATCH", "Users/"+id, map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": ops}, status, failure)
			}
			get := func() map[string]any { t.Helper(); return call("GET", "Users/"+id, nil, 200, "GET failed") }
			if got := patch(200, "PATCH did not replace userName", map[string]any{"op": "replace", "path": "userName", "value": "renamed@example.test"}); got["userName"] != "renamed@example.test" || get()["userName"] != "renamed@example.test" {
				t.Fatal("PATCH did not replace userName", got["userName"])
			}
			if body := patch(400, "PATCH accepted an empty userName", map[string]any{"op": "replace", "path": "userName", "value": ""}); body["scimType"] != "invalidValue" {
				t.Fatal("PATCH accepted an empty userName", body)
			}
			if body := patch(400, "PATCH removed userName", map[string]any{"op": "remove", "path": "userName"}); body["scimType"] != "mutability" {
				t.Fatal("PATCH removed userName", body)
			}

			filtered := func(external string) float64 {
				t.Helper()
				list := call("GET", `Users?filter=externalId%20eq%20%22`+external+`%22`, nil, 200, "the filtered list failed")
				n, _ := list["totalResults"].(float64)
				return n
			}
			if got := patch(200, "PATCH did not add externalId", map[string]any{"op": "add", "path": "externalId", "value": "ext-2"}); got["externalId"] != "ext-2" {
				t.Fatal("PATCH did not add externalId", got["externalId"])
			}
			patch(200, "replacing externalId failed", map[string]any{"op": "replace", "path": "externalId", "value": "ext-3"})
			if filtered("ext-3") != 1 {
				t.Fatal("a replaced externalId is not filterable")
			}
			if got := patch(200, "PATCH did not clear externalId", map[string]any{"op": "remove", "path": "externalId"}); got["externalId"] != nil {
				t.Fatal("PATCH did not clear externalId", got["externalId"])
			}
			if filtered("ext-3") != 0 {
				t.Fatal("a removed externalId still matched a filter")
			}

			if got := patch(200, "PATCH did not replace displayName", map[string]any{"op": "replace", "path": "displayName", "value": "Ada L"}); got["displayName"] != "Ada L" {
				t.Fatal("PATCH did not replace displayName", got["displayName"])
			}
			var name string
			if err := store.db.QueryRowContext(t.Context(), store.bind(`SELECT u."name" FROM "user" u JOIN "scimUser" s ON s."userId"=u."id" WHERE s."id"=?`), id).Scan(&name); err != nil || name != "Ada L" {
				t.Fatal("the account name did not follow a patched display name", name, err)
			}
			if got := patch(200, "removing displayName failed", map[string]any{"op": "remove", "path": "displayName"}); got["displayName"] != "Ada Lovelace" {
				t.Fatal("removing displayName did not fall back to the formatted name", got["displayName"])
			}

			if got := patch(200, "replacing emails failed", map[string]any{"op": "replace", "path": "emails", "value": []any{map[string]any{"value": "z@example.test", "type": nil, "primary": nil}}}); !jsonEqual(got["emails"], []any{map[string]any{"value": "z@example.test", "primary": true}}) {
				t.Fatal("a null subattribute in a whole emails value was kept", got["emails"])
			}
			if got := patch(200, "replacing roles failed", map[string]any{"op": "replace", "path": "roles", "value": []any{map[string]any{"value": "r2", "display": nil, "type": nil}}}); !jsonEqual(got["roles"], []any{map[string]any{"value": "r2"}}) {
				t.Fatal("a null subattribute in a whole roles value was kept", got["roles"])
			}
		})
	}
}

// An empty or unchanged PATCH keeps the User and its lastModified, operation
// names are case-insensitive, and read-only and pathless-remove targets are
// refused.
func TestSCIMUserPatchOperationForms(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store, call := attributeDirectory(t, dialect)
			created := call("POST", "Users", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "ops@example.test", "displayName": "No Op"}, 201, "the User was refused")
			id := created["id"].(string)
			patch := func(status int, failure string, ops ...any) map[string]any {
				t.Helper()
				if ops == nil {
					ops = []any{}
				}
				return call("PATCH", "Users/"+id, map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": ops}, status, failure)
			}
			modified := func(m map[string]any) any { return m["meta"].(map[string]any)["lastModified"] }
			before := modified(created)
			// A rewrite would move lastModified past these pauses.
			time.Sleep(5 * time.Millisecond)
			got := patch(200, "an empty PATCH was refused")
			if got["displayName"] != "No Op" {
				t.Fatal("an empty PATCH changed the User", got)
			}
			if modified(got) != before {
				t.Fatal("an empty PATCH rewrote lastModified", before, modified(got))
			}
			if got := patch(200, "an uppercase replace op was refused", map[string]any{"op": "REPLACE", "path": "title", "value": "Lead"}); got["title"] != "Lead" {
				t.Fatal("an uppercase replace op was not applied", got["title"])
			}
			if got := patch(200, "an omitted op was refused", map[string]any{"path": "locale", "value": "en-GB"}); got["locale"] != "en-GB" {
				t.Fatal("an omitted op did not default to replace", got["locale"])
			}
			stamped := modified(patch(200, "a mixed-case add op was refused", map[string]any{"op": "Add", "path": "timezone", "value": "Europe/London"}))
			if got := call("GET", "Users/"+id, nil, 200, "GET failed"); got["timezone"] != "Europe/London" {
				t.Fatal("a mixed-case add op was not applied", got["timezone"])
			}
			time.Sleep(5 * time.Millisecond)
			if got := patch(200, "an unchanged PATCH was refused", map[string]any{"op": "replace", "path": "title", "value": "Lead"}); modified(got) != stamped {
				t.Fatal("an unchanged PATCH rewrote lastModified", stamped, modified(got))
			}
			many := make([]any, 101)
			for i := range many {
				many[i] = map[string]any{"op": "replace", "path": "title", "value": "Lead"}
			}
			patch(200, "a PATCH with 101 operations was refused", many...)
			revision := func() int {
				t.Helper()
				var n int
				if err := store.db.QueryRowContext(t.Context(), store.bind(`SELECT j."revision" FROM "scimSubject" j JOIN "scimUser" u ON u."userId"=j."userId" WHERE u."id"=?`), id).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			unchangedRevision := revision()
			time.Sleep(5 * time.Millisecond)
			if got := patch(200, "an empty pathless PATCH value was refused", map[string]any{"op": "replace", "value": map[string]any{}}); modified(got) != stamped || revision() != unchangedRevision {
				t.Fatal("an empty pathless PATCH value rewrote the User", stamped, modified(got))
			}
			if body := patch(400, "an unknown PATCH op was accepted", map[string]any{"op": "move", "path": "title", "value": "X"}); body["scimType"] != "invalidSyntax" {
				t.Fatal("an unknown PATCH op was accepted", body)
			}
			if body := patch(400, "a pathless User remove did not answer noTarget", map[string]any{"op": "remove"}); body["scimType"] != "noTarget" {
				t.Fatal("a pathless User remove did not answer noTarget", body)
			}
			if body := patch(400, "PATCH accepted a write to the User id", map[string]any{"op": "replace", "path": "id", "value": "other"}); body["scimType"] != "mutability" {
				t.Fatal("PATCH accepted a write to the User id", body)
			}
			if body := patch(400, "a pathless schemas key was not read-only", map[string]any{"op": "replace", "value": map[string]any{"schemas": []string{scim.UserSchema}}}); body["scimType"] != "mutability" {
				t.Fatal("a pathless schemas key was not read-only", body)
			}
			if body := patch(400, "PATCH accepted a write to User meta", map[string]any{"op": "replace", "path": "meta.created", "value": "2020-01-01T00:00:00Z"}); body["scimType"] != "mutability" {
				t.Fatal("PATCH accepted a write to User meta", body)
			}
		})
	}
}

// A row written before serializedAttributes existed is read from its
// mirror columns, and its next change writes the canonical attributes.
func TestSCIMUserPrereleaseRow(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			store, call := attributeDirectory(t, dialect)
			name := map[string]any{"formatted": "Legacy Employee", "givenName": "Legacy", "familyName": "Employee"}
			created := call("POST", "Users", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "legacy.login@example.test", "name": name,
				"emails": []any{map[string]any{"value": "legacy.primary@example.test", "primary": true}}}, 201, "the User was refused")
			id := created["id"].(string)
			setColumn := func(value any) {
				t.Helper()
				if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "scimUser" SET "serializedAttributes"=? WHERE "id"=?`), value, id); err != nil {
					t.Fatal(err)
				}
			}
			stored := func() bool {
				t.Helper()
				var raw any
				if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "serializedAttributes" FROM "scimUser" WHERE "id"=?`), id).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				return raw != nil
			}
			setColumn(nil)
			got := call("GET", "Users/"+id, nil, 200, "GET failed on a prerelease row")
			if !jsonEqual(got["name"], name) {
				t.Fatal("a prerelease row lost its mirrored name", got["name"])
			}
			if !jsonEqual(got["emails"], []any{map[string]any{"value": "legacy.primary@example.test", "primary": true}}) {
				t.Fatal("a prerelease row lost its mirrored emails", got["emails"])
			}
			if stored() {
				t.Fatal("reading a prerelease row rewrote it")
			}
			call("PUT", "Users/"+id, map[string]any{"schemas": []string{scim.UserSchema}, "userName": "legacy.login@example.test", "name": map[string]any{"formatted": "Renamed Employee"},
				"emails": []any{map[string]any{"value": "legacy.primary@example.test", "primary": true}}}, 200, "PUT failed on a prerelease row")
			if !stored() {
				t.Fatal("PUT did not write canonical attributes for a prerelease row")
			}
			setColumn(nil)
			call("PATCH", "Users/"+id, map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []any{map[string]any{"op": "replace", "path": "title", "value": "Archivist"}}}, 200, "PATCH failed on a prerelease row")
			if got := call("GET", "Users/"+id, nil, 200, "GET failed"); got["title"] != "Archivist" {
				t.Fatal("PATCH failed on a prerelease row", got["title"])
			}
			if !stored() {
				t.Fatal("PATCH did not write canonical attributes for a prerelease row")
			}
			setColumn("")
			if got := call("GET", "Users/"+id, nil, 200, "an empty serializedAttributes value was not read from the mirrors"); got["name"].(map[string]any)["formatted"] != "Renamed Employee" {
				t.Fatal("an empty serializedAttributes value was not read from the mirrors", got["name"])
			}
		})
	}
}
