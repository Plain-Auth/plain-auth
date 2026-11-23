package organization_test

import (
	"testing"

	"github.com/Plain-Auth/plain-auth/plugins/access"
	"github.com/Plain-Auth/plain-auth/plugins/organization"
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
