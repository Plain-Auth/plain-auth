package organization_test

import (
	"reflect"
	"slices"
	"testing"

	"github.com/Plain-Org/plain-auth/plugins/access"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
)

// Compose custom roles from the exported default statements and roles, and
// split role lists the way stored memberships are written.
func TestDefaultRolesAndRoleParsing(t *testing.T) {
	// The default control describes the built-in statement vocabulary.
	control := org.DefaultRoleControl()
	vocabulary := access.Statements{
		"organization": {"update", "delete"},
		"member":       {"create", "update", "delete"},
		"invitation":   {"create", "cancel"},
		"team":         {"create", "update", "delete"},
		"ac":           {"create", "read", "update", "delete"},
	}
	for resource, actions := range vocabulary {
		for _, action := range actions {
			if !control.HasAction(resource, action) {
				t.Errorf("default control lacks %s.%s", resource, action)
			}
		}
	}
	if control.HasResource("billing") || control.HasAction("organization", "read") {
		t.Fatal("default control accepted a statement outside the vocabulary")
	}
	if _, err := control.NewRole(access.Statements{"billing": {"refund"}}); err == nil {
		t.Fatal("default control built a role outside its vocabulary")
	}

	// The default owner, admin and member roles can be reused to build custom ones.
	roles := org.DefaultRoles()
	owner, admin, member := roles["owner"], roles["admin"], roles["member"]
	if !reflect.DeepEqual(owner, vocabulary) {
		t.Fatal("unexpected default owner grants", owner)
	}
	if slices.Contains(admin["organization"], "delete") || !slices.Contains(admin["organization"], "update") || !reflect.DeepEqual(admin["team"], vocabulary["team"]) {
		t.Fatal("unexpected default admin grants", admin)
	}
	if !reflect.DeepEqual(member, access.Statements{"ac": {"read"}}) {
		t.Fatal("unexpected default member grants", member)
	}
	auditor := access.Statements{"ac": slices.Clone(member["ac"]), "invitation": {"create"}}
	roles["auditor"] = auditor
	roles["admin"]["organization"] = append(roles["admin"]["organization"], "delete")
	policy, err := org.NewRolePolicy("", roles)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.HasPermission("auditor", access.Statements{"ac": {"read"}, "invitation": {"create"}}) || policy.HasPermission("auditor", access.Statements{"member": {"delete"}}) {
		t.Fatal("a role composed from the member grants did not apply")
	}
	if !policy.HasPermission("admin", access.Statements{"organization": {"delete"}}) {
		t.Fatal("an extended admin role did not apply")
	}
	if fresh := org.DefaultRoles(); slices.Contains(fresh["admin"]["organization"], "delete") {
		t.Fatal("changing a copy of the defaults changed the built-in grants")
	}
	if org.DefaultRoleHasPermission("admin", access.Statements{"organization": {"delete"}}) {
		t.Fatal("the built-in admin role gained organization deletion")
	}

	// Role lists split on commas, trim entries, drop empty ones and keep order and repeats.
	if got := org.NormalizeRoles(" admin, member ", "", "owner,, admin"); !slices.Equal(got, []string{"admin", "member", "owner", "admin"}) {
		t.Fatal("unexpected parsed roles", got)
	}
	if got := org.NormalizeRoles(" , "); got != nil {
		t.Fatal("an empty list parsed to roles", got)
	}
}
