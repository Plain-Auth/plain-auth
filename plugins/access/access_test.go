package access_test

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/Plain-Org/plain-auth/plugins/access"
)

func TestRoleDecisions(t *testing.T) {
	control := access.New(access.Statements{"project": {"create", "edit", "delete"}, "audit": {"read", "edit"}})
	grants := access.Statements{"project": {"create", "edit"}, "audit": {"read"}}
	role, err := control.NewRole(grants)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/decisions.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Case         string
		Match        access.Match
		Requirements []access.Requirement
		Allowed      bool
	}
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Case, func(t *testing.T) {
			err := role.Authorize(tc.Match, tc.Requirements...)
			if (err == nil) != tc.Allowed || (err != nil && !errors.Is(err, access.ErrDenied)) {
				t.Fatalf("expected allowed=%v, got %v", tc.Allowed, err)
			}
		})
	}
}

func TestRoleDefinition(t *testing.T) {
	vocabulary := access.Statements{"document": {"read", "write"}}
	control := access.New(vocabulary)
	vocabulary["document"][0] = "delete"
	grants := access.Statements{"document": {"read"}}
	role, err := control.NewRole(grants)
	if err != nil {
		t.Fatal(err)
	}
	grants["document"][0] = "delete"
	read := access.Requirement{Resource: "document", Actions: []string{"read"}}
	if err := role.Authorize(access.All, read); err != nil {
		t.Fatal("role changed with caller-owned slices", err)
	}
	for _, invalid := range []access.Statements{{"document": {"delete"}}, {"other": {}}} {
		if _, err := control.NewRole(invalid); err == nil {
			t.Fatal("role accepted an undefined grant")
		}
	}
	if role.Authorize(9, read) == nil {
		t.Fatal("invalid resource mode granted access")
	}
	read.Match = 9
	if role.Authorize(access.All, read) == nil {
		t.Fatal("invalid action mode granted access")
	}
}

// Statements returns a copy of a role's grants: changing it leaves the role's
// grants and decisions unchanged, and a role built from an extended copy
// gains the added actions.
func TestRoleStatements(t *testing.T) {
	control := access.New(access.Statements{"project": {"read", "edit", "delete"}, "report": {"read", "publish"}})
	editor, err := control.NewRole(access.Statements{"project": {"read", "edit"}, "report": {"read"}})
	if err != nil {
		t.Fatal(err)
	}
	want := access.Statements{"project": {"read", "edit"}, "report": {"read"}}
	grants := editor.Statements()
	if !reflect.DeepEqual(grants, want) {
		t.Fatal("role statements", grants)
	}
	grants["project"][0] = "delete"
	grants["audit"] = []string{"read"}
	if again := editor.Statements(); !reflect.DeepEqual(again, want) {
		t.Fatal("changing returned statements changed the role", again)
	}
	if editor.Authorize(access.All, access.Requirement{Resource: "project", Actions: []string{"delete"}}) == nil {
		t.Fatal("editor gained a grant from its returned statements")
	}
	extended := editor.Statements()
	extended["project"] = append(extended["project"], "delete")
	extended["report"] = append(extended["report"], "publish")
	owner, err := control.NewRole(extended)
	if err != nil || owner.Authorize(access.All, access.Requirement{Resource: "project", Actions: []string{"delete"}}, access.Requirement{Resource: "report", Actions: []string{"read", "publish"}}) != nil {
		t.Fatal("role built from returned statements", err)
	}
	if len((access.Role{}).Statements()) != 0 {
		t.Fatal("zero role reported grants")
	}
}
