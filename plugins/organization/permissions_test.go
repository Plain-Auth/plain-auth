package organization_test

import (
	"testing"

	"github.com/Plain-Org/plain-auth/plugins/access"
	"github.com/Plain-Org/plain-auth/plugins/organization"
)

func TestDefaultOrganizationRolePermissions(t *testing.T) {
	for _, tc := range []struct {
		roles   string
		actions access.Statements
		want    bool
	}{
		{"unregistered, admin, member", access.Statements{"member": {"update", "delete"}, "invitation": {"cancel"}}, true},
		{"member, admin", access.Statements{"organization": {"delete"}}, false},
		{"member", access.Statements{"ac": {"read"}}, true},
		{"owner", access.Statements{"ac": {"read", "unknown"}}, false},
		{"owner", access.Statements{"unknown": {"read"}}, false},
		{"owner", access.Statements{"organization": nil}, false},
		{"owner", nil, false},
		{"", access.Statements{"ac": {"read"}}, false},
	} {
		if got := organization.DefaultRoleHasPermission(tc.roles, tc.actions); got != tc.want {
			t.Errorf("DefaultRoleHasPermission(%q,%v) = %v, want %v", tc.roles, tc.actions, got, tc.want)
		}
	}
}

func TestStaticOrganizationRolePolicies(t *testing.T) {
	roles := organization.DefaultRoles()
	roles["owner"]["organization"][0] = "archive"
	roles["reviewer"] = access.Statements{"reports": {"read"}}
	policy, err := organization.NewRolePolicy("founder", roles)
	if err != nil {
		t.Fatal(err)
	}
	roles["reviewer"]["reports"][0] = "publish"
	delete(roles, "owner")
	if !policy.HasPermission("reviewer", access.Statements{"reports": {"read"}}) || !policy.HasAction("owner", "organization", "archive") {
		t.Fatal("editing the host map altered a running role policy")
	}
	if policy.HasPermission("reviewer,owner", access.Statements{"reports": {"read"}, "organization": {"archive"}}) {
		t.Fatal("combined partial grants authorized a request")
	}
	if !organization.DefaultRoleHasPermission("owner", access.Statements{"organization": {"update"}}) {
		t.Fatal("host edits changed the built-in grants")
	}
	empty, err := organization.NewRolePolicy("", map[string]access.Statements{})
	if err != nil || empty.HasAction("owner", "organization", "update") || !empty.Recognizes("owner") {
		t.Fatal("an empty policy must recognize built-in names without granting their actions", err)
	}
	if policy.CreatorRole() != "founder" || empty.CreatorRole() != "owner" {
		t.Fatal("incorrect creator membership")
	}
	for _, name := range []string{"a,b", " admin", "admin "} {
		if _, err := organization.NewRolePolicy(name, nil); err == nil {
			t.Errorf("accepted ambiguous creator %q", name)
		}
		if _, err := organization.NewRolePolicy("", map[string]access.Statements{name: {}}); err == nil {
			t.Errorf("accepted ambiguous role %q", name)
		}
	}
}
