package scim

import (
	"reflect"
	"strings"
	"testing"
)

func TestSCIMRoleProfileLimits(t *testing.T) {
	maxValue := strings.Repeat("😀", 1024)
	roles, err := roleAttribute.normalize([]any{map[string]any{"value": "\uFEFF" + maxValue + " ", "display": maxValue, "type": " İ ", "primary": "fAlSe"}, map[string]any{"value": "a"}, map[string]any{"value": "a"}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"value": maxValue, "display": maxValue, "type": "i\u0307", "primary": false}
	if !reflect.DeepEqual(roles[0], want) {
		t.Fatal("Unicode value, normalized type or false primary changed")
	}
	for _, v := range []any{42, []any{nil}, []any{map[string]any{"value": "a", "TYPE": "a", "type": "b"}}, []any{map[string]any{"value": "a", "primary": 1}}, []any{map[string]any{"display": "missing value"}}, []any{map[string]any{"value": maxValue + "x"}}} {
		if _, err := roleAttribute.normalize(v); err == nil {
			t.Fatalf("accepted invalid role entry of type %T", v)
		}
	}
}

func TestSCIMRolePatchEdges(t *testing.T) {
	p, err := normalize(map[string]any{"schemas": []any{UserSchema}, "userName": "r@example.test", "roles": []any{map[string]any{"value": "admin", "type": "admin", "primary": true}, map[string]any{"value": "reader", "type": "read", "primary": false}}})
	if err != nil {
		t.Fatal(err)
	}
	run := func(ops ...map[string]any) (Profile, error) {
		values := make([]any, len(ops))
		for i, op := range ops {
			values[i] = op
		}
		return patchProfile(Record{Profile: p}, values)
	}
	for _, operation := range []map[string]any{
		{"op": "replace", "path": "roles"},
		{"op": "remove", "path": "roles[unknown eq \"admin\"]"},
		{"op": "remove", "path": "roles."},
		{"op": "remove", "path": "roles[type eq \"admin\"].value"},
		{"op": "replace", "path": "roles[type eq \"read\"]", "value": []any{map[string]any{"value": "one"}, map[string]any{"value": "two"}}},
	} {
		if _, err := run(operation); err == nil {
			t.Fatal("accepted invalid role operation", operation)
		}
	}
	next, err := run(map[string]any{"op": "replace", "path": `roles[type eq "missing"]`, "value": map[string]any{"display": nil}}, map[string]any{"op": "replace", "path": `roles[primary eq false].primary`, "value": "true"})
	if err != nil {
		t.Fatal(err)
	}
	rows := next.Attributes["roles"].([]any)
	if len(rows) != 2 || rows[0].(map[string]any)["primary"] != false || rows[1].(map[string]any)["primary"] != true {
		t.Fatalf("primary handoff failed: %#v", rows)
	}
	if p.Attributes["roles"].([]any)[0].(map[string]any)["primary"] != true {
		t.Fatal("patch mutated the input profile")
	}
}
