package scim

import (
	"errors"
	"net/url"
	"testing"
)

func TestSCIMGroupCompatibilityAndPatchForms(t *testing.T) {
	base := map[string]any{"schemas": []any{legacyGroupSchema, GroupSchema}, "displayName": " Legacy "}
	if _, e := parseGroup(base, false); e == nil {
		t.Fatal("enabled legacy marker by default")
	}
	if g, e := parseGroup(base, true); e != nil || g.DisplayName != "Legacy" {
		t.Fatal(g, e)
	}
	base[legacyGroupSchema] = map[string]any{}
	if _, e := parseGroup(base, true); e == nil {
		t.Fatal("accepted attributes under legacy marker")
	}
	delete(base, legacyGroupSchema)
	base["schemas"] = []any{GroupSchema, legacyGroupSchema, legacyGroupSchema}
	if _, e := parseGroup(base, true); e == nil {
		t.Fatal("accepted repeated schema marker")
	}
	// The exception names only the classic marker: other extension URIs,
	// including another Entra one, stay invalid.
	for _, extension := range []string{"urn:example:params:scim:schemas:extension:2.0:Group", "urn:ietf:params:scim:schemas:extension:Microsoft:Entra:2.0:Group"} {
		base["schemas"] = []any{GroupSchema, extension}
		var se *Error
		if _, e := parseGroup(base, true); !errors.As(e, &se) || se.Status != 400 || se.Type != "invalidValue" {
			t.Fatal("accepted an unknown Group extension schema with the legacy exception", extension, e)
		}
	}
	g := Group{ID: "group", DisplayName: "Initial", ExternalID: "ext", Members: []GroupMember{{"one", "One"}, {"two", "Two"}}}
	op := func(method, path string, v any) map[string]any {
		return map[string]any{"op": method, "path": path, "value": v}
	}
	got, e := applyGroupPatch(g, []any{op("REPLACE", "", map[string]any{"id": "group", "meta": nil, "schemas": []any{GroupSchema}, "displayName": []any{" New "}, "externalId": nil}), op("remove", GroupSchema+`:members [ value eq "one" ]`, nil)})
	if e != nil || got.DisplayName != "New" || got.ExternalID != "" || len(got.MemberIDs) != 1 || got.MemberIDs[0] != "two" {
		t.Fatal(got, e)
	}
	got, e = applyGroupPatch(g, []any{op("replace", "members", nil)})
	if e != nil || len(got.MemberIDs) != 0 {
		t.Fatal(got, e)
	}
	for _, tc := range []struct {
		op   map[string]any
		kind string
	}{
		{op("remove", "", nil), "noTarget"}, {op("remove", "displayName", nil), "mutability"}, {op("replace", "id", "new"), "mutability"},
		{op("replace", "", "not an object"), "invalidValue"}, {op("add", "members", map[string]any{"value": "id"}), "invalidValue"}, {op("add", "members", []any{map[string]any{"value": "id", "type": "Group"}}), "invalidValue"},
		{op("add", "members[value eq \"id\"]", "unsupported"), "invalidPath"},
	} {
		_, e := applyGroupPatch(g, []any{tc.op})
		api, ok := e.(*Error)
		if !ok || api.Type != tc.kind {
			t.Fatalf("%+v expected %s, got %v", tc.op, tc.kind, e)
		}
	}
	h := Handler{base: "https://test.example/identity/scim/v2"}
	for _, tc := range []struct {
		q          url.Values
		hasMembers bool
	}{
		{url.Values{"attributes": {"members.value"}}, false},
		{url.Values{"attributes": {"members"}}, true},
		{url.Values{"excludedAttributes": {"members"}}, false},
	} {
		p, e := selectionQuery(tc.q, GroupSchema)
		if e != nil {
			t.Fatal(e)
		}
		result := p.apply(h.groupResource(Group{ID: "empty"}, p.returns("members")))
		_, ok := result["members"]
		if ok != tc.hasMembers {
			t.Fatal(tc, result)
		}
	}
}
