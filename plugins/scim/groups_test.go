package scim

import (
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
		p, e := projectQuery(tc.q, groupProjectionFields, GroupSchema)
		if e != nil {
			t.Fatal(e)
		}
		result := h.groupResource(Group{ID: "empty"}, p)
		_, ok := result["members"]
		if ok != tc.hasMembers {
			t.Fatal(tc, result)
		}
	}
}
