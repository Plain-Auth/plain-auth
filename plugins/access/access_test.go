package access_test

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Stonewrit/stonewrit-auth/plugins/access"
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
