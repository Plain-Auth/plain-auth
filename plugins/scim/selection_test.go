package scim

import (
	"net/url"
	"reflect"
	"testing"
)

func TestSCIMUserResponseSelectionTree(t *testing.T) {
	resource := func() map[string]any {
		return map[string]any{
			"schemas": []any{UserSchema}, "id": "u1", "userName": "ada@example.test",
			"name":   map[string]any{"givenName": "Ada", "familyName": "King"},
			"emails": []any{map[string]any{"value": "a@example.test", "type": "work", "primary": true}, map[string]any{"value": "b@example.test", "type": "home", "primary": false}},
			"roles":  []any{map[string]any{"value": "admin"}},
			"meta":   map[string]any{"resourceType": "User"},
		}
	}
	selected := func(q url.Values) (map[string]any, error) {
		s, err := selectionQuery(q, UserSchema)
		if err != nil {
			return nil, err
		}
		return s.apply(resource()), nil
	}
	got, err := selected(url.Values{"attributes": {"name.givenName,EMAILS.value"}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"schemas": []any{UserSchema}, "id": "u1", "name": map[string]any{"givenName": "Ada"},
		"emails": []any{map[string]any{"value": "a@example.test"}, map[string]any{"value": "b@example.test"}}}) {
		t.Fatal("a nested include selection returned the wrong fields", got, err)
	}
	got, err = selected(url.Values{"excludedAttributes": {"name.givenName,emails.type,meta"}})
	if err != nil || got["userName"] != "ada@example.test" || got["meta"] != nil || !reflect.DeepEqual(got["name"], map[string]any{"familyName": "King"}) ||
		!reflect.DeepEqual(got["emails"], []any{map[string]any{"value": "a@example.test", "primary": true}, map[string]any{"value": "b@example.test", "primary": false}}) {
		t.Fatal("a nested exclusion returned the wrong fields", got, err)
	}
	if got, err = selected(url.Values{"attributes": {"urn:ietf:params:scim:schemas:core:2.0:User:userName"}}); err != nil || !reflect.DeepEqual(got, map[string]any{"schemas": []any{UserSchema}, "id": "u1", "userName": "ada@example.test"}) {
		t.Fatal("a core-qualified selection was not applied", got, err)
	}
	if got, err = selected(url.Values{"attributes": {"unknownThing"}}); err != nil || !reflect.DeepEqual(got, map[string]any{"schemas": []any{UserSchema}, "id": "u1"}) {
		t.Fatal("an unknown selection path was not ignored", got, err)
	}
	for _, q := range []url.Values{{"attributes": {"user Name"}}, {"attributes": {"userName,"}}, {"excludedAttributes": {"a,,b"}}, {"attributes": {"a"}, "excludedAttributes": {"b"}}} {
		if _, err := selected(q); err == nil || err.(*Error).Type != "invalidValue" {
			t.Fatal("an invalid selection was accepted", q, err)
		}
	}
	// Inner whitespace follows JavaScript: the byte order mark counts and
	// NEXT LINE does not.
	if _, err := selected(url.Values{"attributes": {"user\uFEFFName"}}); err == nil {
		t.Fatal("a selection path with an inner byte order mark was accepted")
	}
	if got, err = selected(url.Values{"attributes": {"user\u0085Name"}}); err != nil || len(got) != 2 {
		t.Fatal("a selection path with an inner NEXT LINE was refused", got, err)
	}
	if got, err = selected(url.Values{"attributes": {" "}, "excludedAttributes": {"meta"}}); err != nil || got["meta"] != nil || got["userName"] == nil {
		t.Fatal("an empty attributes parameter blocked the exclusion", got, err)
	}
	if got, err = selected(url.Values{"excludedAttributes": {"roles.value"}}); err != nil || !reflect.DeepEqual(got["roles"], []any{map[string]any{}}) {
		t.Fatal("excluding roles.value dropped role entries", got, err)
	}
	if s, _ := selectionQuery(url.Values{"attributes": {"members.value"}}, GroupSchema); !s.returns("members") || s.returns("displayName") {
		t.Fatal("a member subattribute selection did not load members alone")
	}
	if s, _ := selectionQuery(url.Values{"excludedAttributes": {"members"}}, GroupSchema); s.returns("members") || !s.returns("displayName") {
		t.Fatal("excluding members still loaded them")
	}
}
