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

// name add and replace merge, a derived display name follows the formatted
// name, removing name.formatted composes it, and single-valued values may
// arrive as a one-element array.
func TestSCIMUserNamePatchOverHTTP(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			_, call := attributeDirectory(t, dialect)
			created := call("POST", "Users", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "ada@example.test", "name": map[string]any{"givenName": "Ada", "familyName": "Lovelace", "middleName": "Byron"}}, 201, "the User was refused")
			id := created["id"].(string)
			patch := func(status int, failure string, ops ...any) map[string]any {
				t.Helper()
				return call("PATCH", "Users/"+id, map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": ops}, status, failure)
			}
			got := patch(200, "replacing name failed", map[string]any{"op": "replace", "path": "name", "value": map[string]any{"familyName": "King"}})
			if !jsonEqual(got["name"], map[string]any{"formatted": "Ada Lovelace", "givenName": "Ada", "familyName": "King", "middleName": "Byron"}) {
				t.Fatal("replacing name dropped unspecified name parts", got["name"])
			}
			if got := patch(200, "replacing name.formatted failed", map[string]any{"op": "replace", "path": "name.formatted", "value": "Ada King"}); got["displayName"] != "Ada King" {
				t.Fatal("a derived display name did not follow the new formatted name", got["displayName"])
			}
			patch(200, "replacing displayName failed", map[string]any{"op": "replace", "path": "displayName", "value": "Countess"})
			if got := patch(200, "replacing name.formatted failed", map[string]any{"op": "replace", "path": "name.formatted", "value": "A. King"}); got["displayName"] != "Countess" {
				t.Fatal("an explicit display name followed the formatted name", got["displayName"])
			}
			if got := patch(200, "removing name.formatted failed", map[string]any{"op": "remove", "path": "name.formatted"}); got["name"].(map[string]any)["formatted"] != "Ada King" {
				t.Fatal("removing name.formatted did not compose the given and family names", got["name"])
			}
			if body := patch(400, "an unknown name subattribute was accepted", map[string]any{"op": "replace", "path": "name", "value": map[string]any{"nickName": "x"}}); body["scimType"] != "invalidPath" {
				t.Fatal("an unknown name subattribute was accepted", body)
			}
			if got := patch(200, "a one-element active array was refused", map[string]any{"op": "replace", "path": "active", "value": []any{false}}); got["active"] != false {
				t.Fatal("a single-element active array was not unwrapped", got["active"])
			}
			if body := patch(400, "an array-wrapped string active was coerced", map[string]any{"op": "replace", "path": "active", "value": []any{"true"}}); body["scimType"] != "invalidValue" {
				t.Fatal("an array-wrapped string active was coerced", body)
			}
			if got := patch(200, "a one-element userName array was refused", map[string]any{"op": "replace", "path": "userName", "value": []any{"single@example.test"}}); got["userName"] != "single@example.test" {
				t.Fatal("a single-element userName array was not unwrapped", got["userName"])
			}
			if got := patch(200, "removing name failed", map[string]any{"op": "remove", "path": "name"}); !jsonEqual(got["name"], map[string]any{"formatted": "Countess"}) {
				t.Fatal("removing name kept name parts", got["name"])
			}
		})
	}
}

// Email PATCH paths add, replace and select emails like another runtime:
// an added primary demotes the stored one, stored pairs are skipped, and the
// emails cannot be emptied or removed.
func TestSCIMUserEmailPatchOverHTTP(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store, call := attributeDirectory(t, dialect)
			user := func(name string, emails ...any) func(int, string, ...any) map[string]any {
				t.Helper()
				id := call("POST", "Users", map[string]any{"schemas": []string{scim.UserSchema}, "userName": name, "emails": emails}, 201, "the User was refused")["id"].(string)
				return func(status int, failure string, ops ...any) map[string]any {
					t.Helper()
					return call("PATCH", "Users/"+id, map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": ops}, status, failure)
				}
			}
			// emails lists each email as value/type/primary.
			emails := func(got map[string]any) string {
				var out []string
				list, _ := got["emails"].([]any)
				for _, item := range list {
					e := item.(map[string]any)
					typ, _ := e["type"].(string)
					out = append(out, e["value"].(string)+"/"+typ+"/"+map[bool]string{true: "primary", false: "-"}[e["primary"] == true])
				}
				return strings.Join(out, " ")
			}
			op := func(o, path string, value any) map[string]any {
				m := map[string]any{"op": o, "path": path}
				if value != nil {
					m["value"] = value
				}
				return m
			}
			email := func(fields ...any) map[string]any {
				m := map[string]any{}
				for i := 0; i < len(fields); i += 2 {
					m[fields[i].(string)] = fields[i+1]
				}
				return m
			}
			patch := user("a@example.test", email("value", "a@example.test", "type", "work", "primary", true), email("value", "b@example.test", "type", "home"))
			got := patch(200, "adding a primary email failed", op("add", "emails", []any{email("value", "c@example.test", "type", "other", "primary", true)}))
			if emails(got) != "a@example.test/work/- b@example.test/home/- c@example.test/other/primary" {
				t.Fatal("adding a primary email did not demote the previous primary", emails(got))
			}
			if u, err := store.FindAccountUser(t.Context(), "c@example.test"); err != nil || u.Email != "c@example.test" {
				t.Fatal("the account email did not follow the added primary email", u.Email, err)
			}
			got = patch(200, "adding an existing email failed", op("add", "emails", []any{email("value", "A@example.test", "type", "WORK")}))
			if emails(got) != "a@example.test/work/- b@example.test/home/- c@example.test/other/primary" {
				t.Fatal("adding an existing email duplicated it", emails(got))
			}
			got = patch(200, "adding a repeated email failed", op("add", "emails", []any{email("value", "d@example.test", "type", "x"), email("value", "D@example.test", "type", "X", "primary", "True")}))
			if emails(got) != "a@example.test/work/- b@example.test/home/- c@example.test/other/- d@example.test/x/primary" {
				t.Fatal("a repeated added email did not coalesce into one primary", emails(got))
			}
			if body := patch(400, "two added primary emails were accepted", op("add", "emails", []any{email("value", "e@example.test", "primary", true), email("value", "f@example.test", "primary", true)})); body["scimType"] != "invalidValue" {
				t.Fatal("two added primary emails were not invalidValue", body)
			}
			if body := patch(400, "PATCH replaced the emails with an empty set", op("replace", "emails", []any{})); body["scimType"] != "invalidValue" {
				t.Fatal("an empty email replacement was not invalidValue", body)
			}
			if body := patch(400, "PATCH removed every email", op("remove", "emails", nil)); body["scimType"] != "invalidValue" {
				t.Fatal("removing the emails was not invalidValue", body)
			}
			got = patch(200, "the work email selector failed", op("replace", `emails[type eq "work"].value`, "w2@example.test"))
			if emails(got) != "w2@example.test/work/- b@example.test/home/- c@example.test/other/- d@example.test/x/primary" {
				t.Fatal("the work email selector did not replace its value", emails(got))
			}
			got = patch(200, "a type-filter miss failed", op("add", `urn:ietf:params:scim:schemas:core:2.0:User:emails [ type eq "Mobile" ] . value`, "m@example.test"))
			if emails(got) != "w2@example.test/work/- b@example.test/home/- c@example.test/other/- d@example.test/x/primary m@example.test/mobile/-" {
				t.Fatal("a type-filter miss did not append a non-primary email", emails(got))
			}
			got = patch(200, "removing a type-selected email failed", op("remove", `emails[type eq "home"].value`, nil))
			if emails(got) != "w2@example.test/work/- c@example.test/other/- d@example.test/x/primary m@example.test/mobile/-" {
				t.Fatal("removing a type-selected email kept it", emails(got))
			}
			patch(200, "removing an unmatched email selector failed", op("remove", `emails[type eq "absent"].value`, nil))
			got = patch(200, "the primary email selector failed", op("replace", `emails[primary eq "true"].value`, "p@example.test"))
			if emails(got) != "w2@example.test/work/- c@example.test/other/- p@example.test/x/primary m@example.test/mobile/-" {
				t.Fatal("the primary email selector did not replace its value", emails(got))
			}
			if read := call("GET", "Users/"+got["id"].(string), nil, 200, "the patched User could not be read"); emails(read) != emails(got) {
				t.Fatal("the email PATCH answered emails it did not store", emails(read), emails(got))
			}
			if body := patch(400, "PATCH removed the primary email value", op("remove", "emails[primary eq true].value", nil)); body["scimType"] != "invalidValue" {
				t.Fatal("removing the primary email value was not invalidValue", body)
			}
			if body := patch(400, "an unsupported email path was accepted", op("replace", "emails.type", "work")); body["scimType"] != "invalidPath" {
				t.Fatal("an unsupported email path was not invalidPath", body)
			}

			second := user("two@example.test", email("value", "x@example.test", "type", "work"), email("value", "y@example.test", "type", "home"))
			got = second(200, "replacing emails.value failed", op("replace", "emails.value", "same@example.test"))
			if emails(got) != "same@example.test/work/primary same@example.test/home/-" {
				t.Fatal("emails.value did not replace every entry", emails(got))
			}
			if body := second(400, "PATCH removed emails.value", op("remove", "emails.value", nil)); body["scimType"] != "invalidValue" {
				t.Fatal("removing emails.value was not invalidValue", body)
			}
			// Each email operation leaves the emails normalized for the next.
			fourth := user("four@example.test", email("value", "a4@example.test", "type", "work", "primary", true), email("value", "b4@example.test", "type", "home"))
			got = fourth(200, "a primary selector after removing the primary failed", op("remove", `emails[type eq "work"].value`, nil), op("replace", "emails[primary eq true].value", "c4@example.test"))
			if emails(got) != "c4@example.test/home/primary" {
				t.Fatal("a later email operation did not see the primary chosen by the earlier one", emails(got))
			}
			got = fourth(200, "a type selector after an uppercase replace failed", op("replace", "emails", []any{email("value", "a4@example.test", "type", "Work"), email("value", "b4@example.test", "type", "home")}), op("remove", `emails[type eq "work"].value`, nil))
			if emails(got) != "b4@example.test/home/primary" {
				t.Fatal("a later email operation did not see the lowercased types", emails(got))
			}
			third := user("three@example.test", email("value", "three@example.test", "type", "work"))
			if body := third(400, "removing the last email was accepted", op("remove", `emails[type eq "work"].value`, nil)); body["scimType"] != "invalidValue" {
				t.Fatal("removing the last email was not invalidValue", body)
			}
		})
	}
}

// A null PATCH value removes its target, and a null key in a name or
// pathless value removes that attribute after the other keys apply. active,
// userName and emails cannot be removed, so a null on them is refused.
func TestSCIMUserPatchNullsOverHTTP(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			_, call := attributeDirectory(t, dialect)
			created := call("POST", "Users", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "ada@example.test", "externalId": "ada", "title": "Engineer", "locale": "en-GB",
				"name": map[string]any{"givenName": "Ada", "familyName": "Lovelace", "middleName": "Countess"}}, 201, "the User was refused")
			id := created["id"].(string)
			patch := func(status int, failure string, ops ...any) map[string]any {
				t.Helper()
				return call("PATCH", "Users/"+id, map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": ops}, status, failure)
			}
			got := patch(200, "a null replace or add failed", map[string]any{"op": "Replace", "path": "title", "value": nil}, map[string]any{"op": "Add", "path": "externalId", "Value": nil})
			if _, has := got["title"]; has {
				t.Fatal("a null replace did not remove its target", got)
			}
			if _, has := got["externalId"]; has {
				t.Fatal("a null add did not remove its target", got)
			}
			got = patch(200, "a null name key failed", map[string]any{"op": "replace", "path": "name", "value": map[string]any{"familyName": "King", "middleName": nil, "formatted": nil}})
			if !jsonEqual(got["name"], map[string]any{"formatted": "Ada King", "givenName": "Ada", "familyName": "King"}) {
				t.Fatal("null name keys were not removed after the other keys applied", got["name"])
			}
			if got["displayName"] != "Ada King" {
				t.Fatal("a derived display name did not follow a composed formatted name", got["displayName"])
			}
			got = patch(200, "a pathless null key failed", map[string]any{"op": "replace", "value": map[string]any{"displayName": "Ada L", "locale": nil, "name.givenName": nil}})
			if _, has := got["locale"]; has || got["displayName"] != "Ada L" {
				t.Fatal("a pathless null key did not remove its attribute", got)
			}
			if _, has := got["name"].(map[string]any)["givenName"]; has {
				t.Fatal("a pathless null name subattribute was not removed", got["name"])
			}
			if body := patch(400, "a null active PATCH was accepted", map[string]any{"op": "replace", "path": "active", "value": nil}); body["scimType"] != "invalidValue" {
				t.Fatal("a null active PATCH was not invalidValue", body)
			}
			if body := patch(400, "a pathless null active was accepted", map[string]any{"op": "replace", "value": map[string]any{"title": "X", "active": nil}}); body["scimType"] != "invalidValue" {
				t.Fatal("a pathless null active was not invalidValue", body)
			}
			if body := patch(400, "a null userName PATCH was accepted", map[string]any{"op": "replace", "path": "userName", "value": nil}); body["scimType"] != "mutability" {
				t.Fatal("a null userName PATCH was not mutability", body)
			}
			if body := patch(400, "a null emails PATCH was accepted", map[string]any{"op": "replace", "path": "emails", "value": nil}); body["scimType"] != "invalidValue" {
				t.Fatal("a null emails PATCH was not invalidValue", body)
			}
			if body := patch(400, "a PATCH without a value was accepted", map[string]any{"op": "replace", "path": "title"}); body["scimType"] != "invalidValue" {
				t.Fatal("a PATCH without a value was not invalidValue", body)
			}
			got = call("GET", "Users/"+id, nil, 200, "the User could not be read")
			if _, has := got["title"]; has || got["userName"] != "ada@example.test" || got["active"] != true || len(got["emails"].([]any)) != 1 {
				t.Fatal("a refused null PATCH changed the User", got)
			}
			// A PATCH value that only holds nulls is a value to check, not an
			// omission, so it cannot reactivate a deactivated User.
			patch(200, "deactivating the User failed", map[string]any{"op": "replace", "path": "active", "value": false})
			for _, op := range []map[string]any{{"op": "replace", "path": "active", "value": map[string]any{"x": nil}}, {"op": "replace", "value": map[string]any{"active": map[string]any{"x": nil}}}} {
				if body := patch(400, "a PATCH active holding only nulls was accepted", op); body["scimType"] != "invalidValue" {
					t.Fatal("a PATCH active holding only nulls was not invalidValue", body)
				}
			}
			if got := call("GET", "Users/"+id, nil, 200, "the User could not be read"); got["active"] != false {
				t.Fatal("a PATCH value holding only nulls reactivated the User", got["active"])
			}
			patch(200, "reactivating the User failed", map[string]any{"op": "replace", "path": "active", "value": true})
			if body := patch(400, "a null second spelling in a name value was applied", map[string]any{"op": "replace", "path": "name", "value": map[string]any{"familyName": "Byron", "FAMILYNAME": nil}}); body["scimType"] != "invalidSyntax" {
				t.Fatal("a null second spelling in a name value was not invalidSyntax", body)
			}

			// The display and formatted name fallbacks apply at once, as
			// another runtime applies them.
			solo := call("POST", "Users", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "solo@example.test", "displayName": "Ada", "name": map[string]any{"formatted": "Ada"}}, 201, "the User was refused")
			soloPatch := func(failure string, ops ...any) map[string]any {
				t.Helper()
				return call("PATCH", "Users/"+solo["id"].(string), map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": ops}, 200, failure)
			}
			got = soloPatch("a null display and formatted name failed", map[string]any{"op": "replace", "value": map[string]any{"displayName": nil, "name": map[string]any{"formatted": nil}}})
			if got["displayName"] != "Ada" || got["name"].(map[string]any)["formatted"] != "Ada" {
				t.Fatal("a null display and formatted name fell back to the email", got["displayName"], got["name"])
			}
			got = soloPatch("removing the name and display name failed", map[string]any{"op": "remove", "path": "name"}, map[string]any{"op": "remove", "path": "displayName"})
			if got["displayName"] != "Ada" || !jsonEqual(got["name"], map[string]any{"formatted": "Ada"}) {
				t.Fatal("removing the name and then the display name lost the name", got["displayName"], got["name"])
			}
			parts := call("POST", "Users", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "parts@example.test", "name": map[string]any{"givenName": "Ada", "familyName": "Lovelace"}}, 201, "the User was refused")
			got = call("PATCH", "Users/"+parts["id"].(string), map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []any{map[string]any{"op": "replace", "path": "name", "value": map[string]any{"givenName": nil, "formatted": nil}}}}, 200, "null name parts with a null formatted name failed")
			if got["name"].(map[string]any)["formatted"] != "Lovelace" || got["displayName"] != "Lovelace" {
				t.Fatal("a null formatted name was composed before the other null name parts were removed", got["name"], got["displayName"])
			}
		})
	}
}

// Phone numbers, addresses and entitlements are stored in the canonical
// attributes, returned and replaced like roles, and a User carrying them can
// still be patched.
func TestSCIMUserMultiValuedOverHTTP(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store, call := attributeDirectory(t, dialect)
			phones := []any{map[string]any{"value": "+1 555 0100", "type": "work", "primary": true}}
			addresses := []any{map[string]any{"type": "work", "streetAddress": "44 Montgomery St", "formatted": nil, "country": nil}}
			entitlements := []any{map[string]any{"value": "reports", "display": "Reports", "type": "license"}}
			created := call("POST", "Users", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "multi@example.test", "title": strings.Repeat("😀", 1024),
				"phoneNumbers": phones, "addresses": addresses, "entitlements": entitlements}, 201, "a User with phone numbers, addresses and entitlements was refused")
			id := created["id"].(string)
			got := call("GET", "Users/"+id, nil, 200, "the User could not be read")
			if !jsonEqual(got["phoneNumbers"], phones) {
				t.Fatal("created phone numbers were not stored and returned", got["phoneNumbers"])
			}
			// Limits count code points: 1,024 emoji are 2,048 UTF-16 units.
			if got["title"] != strings.Repeat("😀", 1024) {
				t.Fatal("a title of 1024 code points was not stored", got["title"])
			}
			if !jsonEqual(got["addresses"], []any{map[string]any{"type": "work", "streetAddress": "44 Montgomery St"}}) {
				t.Fatal("a null address subattribute was stored", got["addresses"])
			}
			if !jsonEqual(got["entitlements"], entitlements) {
				t.Fatal("created entitlements were not stored and returned", got["entitlements"])
			}
			var serialized string
			if err := store.db.QueryRowContext(t.Context(), store.bind(`SELECT "serializedAttributes" FROM "scimUser" WHERE "id"=?`), id).Scan(&serialized); err != nil || !strings.Contains(serialized, `"entitlements":[`) {
				t.Fatal("entitlements were not stored in the canonical attributes", serialized, err)
			}
			patched := call("PATCH", "Users/"+id, map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []any{map[string]any{"op": "replace", "path": "title", "value": "X"}}}, 200, "a User carrying phone numbers could not be patched")
			if patched["title"] != "X" || !jsonEqual(patched["phoneNumbers"], phones) {
				t.Fatal("a PATCH of a User with phone numbers lost them", patched)
			}
			call("PUT", "Users/"+id, map[string]any{"schemas": []string{scim.UserSchema}, "userName": "multi@example.test"}, 200, "the replacement was refused")
			if got := call("GET", "Users/"+id, nil, 200, "the replaced User could not be read"); got["addresses"] != nil || got["phoneNumbers"] != nil || got["entitlements"] != nil {
				t.Fatal("PUT kept addresses it omitted", got)
			}
			schema := call("GET", "Schemas/"+scim.UserSchema, nil, 200, "the User schema could not be read")
			var names []string
			for _, a := range schema["attributes"].([]any) {
				names = append(names, a.(map[string]any)["name"].(string))
			}
			if strings.Join(names, " ") != "userName displayName active name emails title userType preferredLanguage locale timezone phoneNumbers addresses roles entitlements" {
				t.Fatal("the User schema did not list phoneNumbers, addresses and entitlements in order", names)
			}
		})
	}
}

// phoneNumbers, addresses and entitlements take the role PATCH paths: whole
// values, subattributes and exact type or primary selectors.
func TestSCIMUserMultiValuedPatchOverHTTP(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			_, call := attributeDirectory(t, dialect)
			created := call("POST", "Users", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "patch@example.test",
				"addresses":    []any{map[string]any{"type": "home", "locality": "Bath", "region": "Somerset"}},
				"entitlements": []any{map[string]any{"value": "e1", "primary": true}}}, 201, "the User was refused")
			id := created["id"].(string)
			patch := func(status int, failure string, ops ...any) map[string]any {
				t.Helper()
				return call("PATCH", "Users/"+id, map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": ops}, status, failure)
			}
			op := func(o, path string, value any) map[string]any {
				m := map[string]any{"op": o, "path": path}
				if value != nil {
					m["value"] = value
				}
				return m
			}
			patch(200, "adding a phone number failed", op("add", "phoneNumbers", []any{map[string]any{"value": "+1 555 0100", "type": "work", "primary": true}}))
			got := patch(200, "adding a second phone number failed", op("add", "phoneNumbers", map[string]any{"value": "+1 555 0101", "type": "mobile", "primary": true}))
			if !jsonEqual(got["phoneNumbers"], []any{map[string]any{"value": "+1 555 0100", "type": "work", "primary": false}, map[string]any{"value": "+1 555 0101", "type": "mobile", "primary": true}}) {
				t.Fatal("adding a primary phone number did not demote the previous primary", got["phoneNumbers"])
			}
			got = patch(200, "the work phone selector failed", op("replace", `phoneNumbers[type eq "work"].value`, "+1 555 0102"))
			if got["phoneNumbers"].([]any)[0].(map[string]any)["value"] != "+1 555 0102" {
				t.Fatal("the work phone selector did not replace its value", got["phoneNumbers"])
			}
			got = patch(200, "an address filter miss failed", op("replace", `addresses[type eq "office"].locality`, "Bristol"))
			if !jsonEqual(got["addresses"], []any{map[string]any{"type": "home", "locality": "Bath", "region": "Somerset"}, map[string]any{"type": "office", "locality": "Bristol"}}) {
				t.Fatal("an address filter miss did not create the entry", got["addresses"])
			}
			before := got["addresses"]
			got = patch(200, "clearing a field on an unmatched address failed", op("replace", `addresses[type eq "work"]`, map[string]any{"country": nil}))
			if !jsonEqual(got["addresses"], before) {
				t.Fatal("clearing a field on an unmatched address created it", got["addresses"])
			}
			got = patch(200, "merging a selected address failed", op("replace", `addresses[type eq "home"]`, map[string]any{"locality": "Wells", "region": nil}))
			if !jsonEqual(got["addresses"].([]any)[0], map[string]any{"type": "home", "locality": "Wells"}) {
				t.Fatal("a selected address kept a null subattribute", got["addresses"])
			}
			got = patch(200, "a primary entitlement selector failed", op("replace", "entitlements[primary eq true].display", "Main"))
			if !jsonEqual(got["entitlements"], []any{map[string]any{"value": "e1", "primary": true, "display": "Main"}}) {
				t.Fatal("a primary entitlement selector did not merge its display", got["entitlements"])
			}
			patch(200, "removing an unmatched entitlement selector failed", op("remove", `entitlements[type eq "absent"]`, nil))
			got = patch(200, "a null whole entitlements entry failed", op("replace", "entitlements", []any{map[string]any{"value": "e2", "display": nil}}))
			if !jsonEqual(got["entitlements"], []any{map[string]any{"value": "e2"}}) {
				t.Fatal("a null subattribute in whole entitlements was stored", got["entitlements"])
			}
			got = patch(200, "removing phoneNumbers failed", op("remove", "phoneNumbers", nil))
			if _, has := got["phoneNumbers"]; has {
				t.Fatal("removing phoneNumbers kept them", got["phoneNumbers"])
			}
			if read := call("GET", "Users/"+id, nil, 200, "the patched User could not be read"); !jsonEqual(read["addresses"], got["addresses"]) || read["phoneNumbers"] != nil {
				t.Fatal("the multi-valued PATCH answered values it did not store", read)
			}
			if body := patch(400, "an unsupported address filter was accepted", op("replace", `addresses[value eq "x"]`, map[string]any{"locality": "x"})); body["scimType"] != "invalidPath" {
				t.Fatal("an unsupported address filter was not invalidPath", body)
			}
			if body := patch(400, "an unknown address subattribute was accepted", op("replace", "addresses.value", "x")); body["scimType"] != "invalidPath" {
				t.Fatal("an unknown address subattribute was not invalidPath", body)
			}
		})
	}
}

// attributes and excludedAttributes select nested paths on every User
// response, and an unknown path selects nothing.
func TestSCIMUserSelectionOverHTTP(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			_, call := attributeDirectory(t, dialect)
			created := call("POST", "Users?attributes=userName", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "sel@example.test",
				"name": map[string]any{"givenName": "Sel", "familyName": "Ection"}, "emails": []any{map[string]any{"value": "sel@example.test", "type": "work"}}}, 201, "the User was refused")
			if len(created) != 3 || created["userName"] != "sel@example.test" || created["id"] == nil || created["schemas"] == nil {
				t.Fatal("POST ignored the attribute selection", created)
			}
			id := created["id"].(string)
			put := call("PUT", "Users/"+id+"?excludedAttributes=name.givenName", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "sel@example.test",
				"name": map[string]any{"givenName": "Sel", "familyName": "Ection"}}, 200, "the replacement was refused")
			if !jsonEqual(put["name"], map[string]any{"formatted": "Sel Ection", "familyName": "Ection"}) || put["userName"] == nil {
				t.Fatal("PUT ignored a nested exclusion", put)
			}
			patched := call("PATCH", "Users/"+id+"?attributes=emails.value", map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []any{map[string]any{"op": "replace", "path": "title", "value": "Lead"}}}, 200, "the PATCH was refused")
			if !jsonEqual(patched["emails"], []any{map[string]any{"value": "sel@example.test"}}) || patched["title"] != nil {
				t.Fatal("PATCH ignored a nested selection", patched)
			}
			list := call("GET", "Users?attributes=name.familyName", nil, 200, "the collection was refused")
			if !jsonEqual(list["Resources"].([]any)[0], map[string]any{"schemas": []any{scim.UserSchema}, "id": id, "name": map[string]any{"familyName": "Ection"}}) {
				t.Fatal("a collection ignored a nested selection", list["Resources"])
			}
			// Repeated projection keys are merged into one list.
			merged := call("GET", "Users?attributes=userName&attributes=name.familyName", nil, 200, "a repeated attributes key was refused")
			if !jsonEqual(merged["Resources"].([]any)[0], map[string]any{"schemas": []any{scim.UserSchema}, "id": id, "userName": "sel@example.test", "name": map[string]any{"familyName": "Ection"}}) {
				t.Fatal("repeated attributes keys were not merged", merged["Resources"])
			}
			if got := call("GET", "Users/"+id+"?excludedAttributes=name&excludedAttributes=emails", nil, 200, "a repeated excludedAttributes key was refused"); got["name"] != nil || got["emails"] != nil || got["userName"] == nil {
				t.Fatal("repeated excludedAttributes keys were not merged", got)
			}
			if body := call("GET", "Users?attributes=userName&excludedAttributes=title", nil, 400, "a collection accepted both selection parameters"); body["scimType"] != "invalidValue" {
				t.Fatal("combined selection parameters were not invalidValue", body)
			}
			if got := call("GET", "Users/"+id+"?attributes=unknownThing", nil, 200, "a User selection refused an unknown path"); len(got) != 2 {
				t.Fatal("an unknown User selection path returned attributes", got)
			}
			group := call("POST", "Groups", map[string]any{"schemas": []string{scim.GroupSchema}, "displayName": "Readers", "members": []any{map[string]any{"value": id}}}, 201, "the Group was refused")
			// Two spellings in a Group PATCH are refused before the lookup.
			if body := call("PATCH", "Groups/absent", map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []any{map[string]any{"op": "replace", "value": map[string]any{"displayName": "A", "DisplayName": "B"}}}}, 400, "a PATCH of an unknown Group with two spellings was not refused first"); body["scimType"] != "invalidSyntax" {
				t.Fatal("a PATCH of an unknown Group with two spellings was not invalidSyntax", body)
			}
			if got := call("GET", "Groups/"+group["id"].(string)+"?attributes=unknownThing", nil, 200, "a Group selection refused an unknown path"); len(got) != 2 {
				t.Fatal("an unknown Group selection path returned attributes", got)
			}
			if got := call("GET", "Groups/"+group["id"].(string)+"?attributes=members.value,meta.created", nil, 200, "a nested Group selection was refused"); !jsonEqual(got["members"], []any{map[string]any{"value": id}}) || len(got["meta"].(map[string]any)) != 1 {
				t.Fatal("a nested Group selection returned the wrong fields", got)
			}
		})
	}
}

// The Enterprise User extension is sent under its URN, stored under the
// canonical enterprise key another runtime reads, and discovered with the
// User schema.
func TestSCIMEnterpriseUserOverHTTP(t *testing.T) {
	const urn = scim.EnterpriseUserSchema
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store, call := attributeDirectory(t, dialect)
			extension := map[string]any{"employeeNumber": "701984", "department": "Tour Operations", "manager": map[string]any{"value": "m-1"}}
			created := call("POST", "Users", map[string]any{"schemas": []string{scim.UserSchema, urn}, "userName": "bjensen@example.test",
				urn: map[string]any{"employeeNumber": "701984", "department": "Tour Operations", "manager": map[string]any{"value": "m-1", "displayName": "John Smith"}}}, 201, "an Enterprise User was refused")
			if !jsonEqual(created["schemas"], []any{scim.UserSchema, urn}) || !jsonEqual(created[urn], extension) || created["enterprise"] != nil {
				t.Fatal("the Enterprise extension was not returned on creation", created)
			}
			id := created["id"].(string)
			if got := call("GET", "Users/"+id, nil, 200, "the Enterprise User could not be read"); !jsonEqual(got[urn], extension) {
				t.Fatal("the Enterprise extension was not stored", got)
			}
			var serialized string
			if err := store.db.QueryRowContext(t.Context(), store.bind(`SELECT "serializedAttributes" FROM "scimUser" WHERE "id"=?`), id).Scan(&serialized); err != nil || !strings.Contains(serialized, `"enterprise":{`) || strings.Contains(serialized, urn+`":`) {
				t.Fatal("the Enterprise extension was not stored under its canonical key", serialized, err)
			}
			if got := call("GET", "Users/"+id+"?attributes=manager,"+urn+":department", nil, 200, "an Enterprise selection was refused"); !jsonEqual(got[urn], map[string]any{"department": "Tour Operations", "manager": map[string]any{"value": "m-1"}}) || got["userName"] != nil {
				t.Fatal("an Enterprise or manager selection returned the wrong fields", got)
			}
			if body := call("POST", "Users", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "undeclared@example.test", urn: map[string]any{"department": "R&D"}}, 400, "HTTP accepted an Enterprise object without its schema URI"); body["scimType"] != "invalidValue" {
				t.Fatal("an undeclared Enterprise object was not invalidValue", body)
			}
			call("PUT", "Users/"+id, map[string]any{"schemas": []string{scim.UserSchema, urn}, "userName": "bjensen@example.test"}, 200, "the replacement was refused")
			if got := call("GET", "Users/"+id, nil, 200, "the replaced User could not be read"); got[urn] != nil || !jsonEqual(got["schemas"], []any{scim.UserSchema, urn}) {
				t.Fatal("PUT kept an omitted Enterprise extension", got)
			}
			var ids []any
			for _, r := range call("GET", "Schemas", nil, 200, "the schemas could not be listed")["Resources"].([]any) {
				ids = append(ids, r.(map[string]any)["id"])
			}
			if !jsonEqual(ids, []any{scim.UserSchema, urn, scim.GroupSchema}) {
				t.Fatal("discovery did not list the User, Enterprise User and Group schemas in order", ids)
			}
			schema := call("GET", "Schemas/"+urn, nil, 200, "the Enterprise User schema could not be retrieved by ID")
			var names []string
			for _, a := range schema["attributes"].([]any) {
				names = append(names, a.(map[string]any)["name"].(string))
			}
			if schema["name"] != "EnterpriseUser" || strings.Join(names, " ") != "employeeNumber costCenter organization division department manager" || !strings.HasSuffix(schema["meta"].(map[string]any)["location"].(string), "/Schemas/"+urn) {
				t.Fatal("the Enterprise User schema could not be retrieved by ID", schema)
			}
			want := []any{map[string]any{"schema": urn, "required": false}}
			if got := call("GET", "ResourceTypes/User", nil, 200, "the User resource type could not be read"); !jsonEqual(got["schemaExtensions"], want) {
				t.Fatal("the User resource type did not declare the Enterprise extension", got)
			}
			if got := call("GET", "ResourceTypes", nil, 200, "the resource types could not be listed"); !jsonEqual(got["Resources"].([]any)[0].(map[string]any)["schemaExtensions"], want) {
				t.Fatal("the ResourceTypes listing omitted the Enterprise extension", got)
			}
		})
	}
}

// Enterprise paths patch the extension like another runtime: qualified
// attributes and object values merge, writes declare the extension, the
// classic manager aliases reach its manager, and removing the last field
// removes the extension and its declaration.
func TestSCIMEnterpriseUserPatchOverHTTP(t *testing.T) {
	const urn = scim.EnterpriseUserSchema
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			_, call := attributeDirectory(t, dialect)
			user := func(name string, fields map[string]any) func(int, string, ...any) map[string]any {
				t.Helper()
				body := map[string]any{"schemas": []string{scim.UserSchema}, "userName": name}
				if fields != nil {
					body["schemas"], body[urn] = []string{scim.UserSchema, urn}, fields
				}
				id := call("POST", "Users", body, 201, "the User was refused")["id"].(string)
				return func(status int, failure string, ops ...any) map[string]any {
					t.Helper()
					got := call("PATCH", "Users/"+id, map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": ops}, status, failure)
					if status == 200 {
						if _, leaked := got["manager"]; leaked {
							t.Fatal("a manager alias leaked into the response", got)
						}
						if read := call("GET", "Users/"+id, nil, 200, "the patched User could not be read"); !jsonEqual(read[urn], got[urn]) || !jsonEqual(read["schemas"], got["schemas"]) {
							t.Fatal("an Enterprise PATCH answered values it did not store", read[urn], got[urn])
						}
					}
					return got
				}
			}
			op := func(o, path string, value any) map[string]any {
				m := map[string]any{"op": o, "path": path}
				if value != nil {
					m["value"] = value
				}
				return m
			}
			declared := []any{scim.UserSchema, urn}
			patch := user("ent@example.test", map[string]any{"department": "R&D", "costCenter": "C1", "manager": map[string]any{"value": "m-1"}})
			if got := patch(200, "a qualified Enterprise path failed", op("replace", urn+":department", "Eng")); !jsonEqual(got[urn], map[string]any{"department": "Eng", "costCenter": "C1", "manager": map[string]any{"value": "m-1"}}) {
				t.Fatal("a qualified Enterprise path did not preserve the other fields", got[urn])
			}
			if got := patch(200, "an Enterprise object replace failed", op("replace", urn, map[string]any{"Division": "D", "manager": map[string]any{"$ref": "https://directory.example.test/Users/m-1"}})); !jsonEqual(got[urn], map[string]any{"department": "Eng", "costCenter": "C1", "division": "D", "manager": map[string]any{"value": "m-1", "$ref": "https://directory.example.test/Users/m-1"}}) {
				t.Fatal("an Enterprise object replace did not merge", got[urn])
			}
			if got := patch(200, "a null Enterprise key failed", op("replace", urn, map[string]any{"department": nil, "employeeNumber": "7"})); got[urn].(map[string]any)["department"] != nil || got[urn].(map[string]any)["employeeNumber"] != "7" {
				t.Fatal("a null Enterprise key was not removed after the merge", got[urn])
			}
			if got := patch(200, "the enterprise alias failed", op("replace", "enterprise", map[string]any{"costCenter": nil})); got[urn].(map[string]any)["costCenter"] != nil {
				t.Fatal("the enterprise path alias did not clear a field", got[urn])
			}
			before := patch(200, "reading the manager failed", op("replace", "title", "Lead"))[urn]
			if got := patch(200, "a null manager displayName failed", op("replace", urn+":manager", map[string]any{"displayName": nil})); !jsonEqual(got[urn], before) {
				t.Fatal("a null read-only manager displayName changed the manager", got[urn])
			}
			if got := patch(200, "the manager alias failed", op("replace", "manager", "m-9")); !jsonEqual(got[urn].(map[string]any)["manager"], map[string]any{"value": "m-9", "$ref": "https://directory.example.test/Users/m-1"}) {
				t.Fatal("the manager alias did not set the Enterprise manager", got[urn])
			}
			if got := patch(200, "manager.$ref failed", op("replace", "manager.$ref", "https://directory.example.test/Users/m-9")); !jsonEqual(got[urn].(map[string]any)["manager"], map[string]any{"value": "m-9", "$ref": "https://directory.example.test/Users/m-9"}) {
				t.Fatal("manager.$ref did not merge into the manager", got[urn])
			}
			if body := patch(400, "manager.displayName was writable", op("replace", "manager.displayName", "Boss")); body["scimType"] != "mutability" {
				t.Fatal("manager.displayName was not mutability", body)
			}
			if body := patch(400, "a manager without value or $ref was accepted", op("replace", "manager", map[string]any{"displayName": "Boss"})); body["scimType"] != "invalidValue" {
				t.Fatal("a manager without value or $ref was not invalidValue", body)
			}
			if got := patch(200, "an empty manager replace failed", op("replace", "manager", "")); got[urn].(map[string]any)["manager"] != nil {
				t.Fatal("an empty manager replace did not clear it", got[urn])
			}
			patch(200, "setting the manager failed", op("add", "manager", map[string]any{"value": "m-1"}))
			if got := patch(200, "removing manager.value failed", op("remove", "manager.value", nil)); got[urn].(map[string]any)["manager"] != nil {
				t.Fatal("an emptied manager stayed in the extension", got[urn])
			}
			if body := patch(400, "a core-prefixed manager alias was accepted", op("replace", scim.UserSchema+":manager", "m-2")); body["scimType"] != "invalidPath" {
				t.Fatal("a core-prefixed manager alias was not invalidPath", body)
			}
			// A null key behind a core-prefixed enterprise alias joins with
			// ":", as in another runtime, so it names no attribute.
			if body := patch(400, "a null key behind a core-prefixed enterprise alias was applied", op("replace", scim.UserSchema+":enterprise", map[string]any{"division": nil})); body["scimType"] != "invalidPath" {
				t.Fatal("a null key behind a core-prefixed enterprise alias was not invalidPath", body)
			}
			// The enterprise alias still works behind the core prefix.
			if got := patch(200, "a core-prefixed enterprise alias failed", op("replace", scim.UserSchema+":enterprise.division", "Core")); got[urn].(map[string]any)["division"] != "Core" {
				t.Fatal("a core-prefixed enterprise alias did not set the field", got[urn])
			}
			// Two spellings are refused before the User is looked up.
			body := call("PATCH", "Users/absent", map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []any{map[string]any{"op": "replace", "value": map[string]any{"displayName": "A", "DisplayName": nil}}}}, 400, "a PATCH of an unknown User with two spellings was not refused first")
			if body["scimType"] != "invalidSyntax" {
				t.Fatal("a PATCH of an unknown User with two spellings was not invalidSyntax", body)
			}
			patch(200, "setting a cost center failed", op("replace", urn+":costCenter", "C2"))
			if got := patch(200, "a null Enterprise value failed", map[string]any{"op": "replace", "path": urn + ":costCenter", "value": nil}); got[urn].(map[string]any)["costCenter"] != nil {
				t.Fatal("a null Enterprise attribute value did not remove it", got[urn])
			}
			if body := patch(400, "an unknown Enterprise attribute path was accepted", op("replace", urn+":unknownAttr", "x")); body["scimType"] != "invalidPath" {
				t.Fatal("an unknown Enterprise attribute path was not invalidPath", body)
			}
			if body := patch(400, "an empty Enterprise department was accepted", op("replace", urn+":department", "")); body["scimType"] != "invalidValue" {
				t.Fatal("an empty Enterprise department was not invalidValue", body)
			}
			if got := patch(200, "removing the Enterprise extension failed", op("remove", urn, nil)); got[urn] != nil || !jsonEqual(got["schemas"], []any{scim.UserSchema}) {
				t.Fatal("removing the Enterprise extension kept its declaration", got)
			}

			core := user("core@example.test", nil)
			if got := core(200, "an Enterprise write failed", op("replace", urn+":employeeNumber", "42")); !jsonEqual(got["schemas"], declared) || !jsonEqual(got[urn], map[string]any{"employeeNumber": "42"}) {
				t.Fatal("an Enterprise write did not declare the extension", got)
			}
			if got := core(200, "a flat pathless Enterprise key failed", map[string]any{"op": "replace", "value": map[string]any{urn + ":department": "Ops", "manager": "m-2"}}); !jsonEqual(got[urn], map[string]any{"employeeNumber": "42", "department": "Ops", "manager": map[string]any{"value": "m-2"}}) {
				t.Fatal("flat pathless Enterprise keys were not applied", got[urn])
			}
			if got := core(200, "a pathless all-null Enterprise clear failed", map[string]any{"op": "replace", "value": map[string]any{urn: map[string]any{"employeeNumber": nil, "department": nil, "manager": nil}}}); got[urn] != nil {
				t.Fatal("clearing every Enterprise field kept the extension", got)
			} else if !jsonEqual(got["schemas"], []any{scim.UserSchema}) {
				t.Fatal("clearing every Enterprise field kept its schema declaration", got["schemas"])
			}
		})
	}
}
