package admin_test

import (
	"slices"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth/plugins/access"
	"github.com/Plain-Org/plain-auth/plugins/admin"
)

func TestAdministrativeRolePolicy(t *testing.T) {
	policy := admin.Options{}
	if !policy.HasPermission("", "admin", admin.Permissions{"session": {"list", "revoke"}}) || policy.HasPermission("", "admin", admin.Permissions{"user": {"impersonate-admins"}}) {
		t.Fatal("default administrative grants")
	}
	if policy.HasPermission("", "user", admin.Permissions{"user": {"list"}}) {
		t.Fatal("default user received administrative permissions")
	}
	custom := admin.Options{DefaultRole: "reader", AdminRoles: []string{"manager"}, AdminUserIDs: []string{"explicit"}, Roles: map[string]admin.Permissions{"reader": {"user": {"get"}}, "manager": {"user": {"update"}}}}
	if !custom.HasPermission("abc", "", admin.Permissions{"user": {"get"}}) || !custom.HasPermission("explicit", "", admin.Permissions{"user": {"impersonate-admins"}}) {
		t.Fatal("default/explicit grants")
	}
	if custom.HasPermission("abc", "reader,manager", admin.Permissions{"user": {"get", "update"}}) {
		t.Fatal("required statement split across independent roles")
	}
	if _, err := admin.New(custom); err != nil {
		t.Fatal(err)
	}
	for _, opts := range []admin.Options{{DefaultRole: "missing"}, {AdminRoles: []string{"missing"}}, {DefaultBanDuration: -time.Second}, {ImpersonationSessionDuration: -time.Second}} {
		if _, err := admin.New(opts); err == nil {
			t.Fatal("invalid admin policy accepted")
		}
	}
	if _, err := admin.New(admin.Options{AdminRoles: []string{"Admin"}}); err == nil {
		t.Fatal("a protected role name that differs only in case was accepted")
	}
}

// The default role control holds the built-in vocabulary, and the default
// roles are an independent copy a custom role map can extend.
func TestDefaultAdministrativeRoles(t *testing.T) {
	// The default control holds the built-in administrative vocabulary.
	control := admin.DefaultRoleControl()
	vocabulary := access.Statements{
		"user":    {"create", "list", "set-role", "ban", "impersonate", "impersonate-admins", "delete", "set-password", "set-email", "set-phone", "get", "update"},
		"session": {"list", "revoke", "delete"},
	}
	for resource, actions := range vocabulary {
		for _, action := range actions {
			if !control.HasAction(resource, action) {
				t.Errorf("default control lacks %s:%s", resource, action)
			}
		}
	}
	if control.HasResource("organization") || control.HasAction("user", "promote") || control.HasAction("session", "create") {
		t.Fatal("default control accepted a statement outside the vocabulary")
	}
	for _, outside := range []access.Statements{{"user": {"promote"}}, {"billing": {}}} {
		if _, err := control.NewRole(outside); err == nil {
			t.Fatal("default control built a role outside its vocabulary", outside)
		}
	}

	// The built-in admin and user roles can be reused to build custom ones.
	roles := admin.DefaultRoles()
	for name, grants := range roles {
		if _, err := control.NewRole(access.Statements(grants)); err != nil {
			t.Fatal("built-in role outside the default vocabulary", name, err)
		}
	}
	adminGrants := roles["admin"]
	want := slices.DeleteFunc(slices.Clone(vocabulary["user"]), func(a string) bool { return a == "impersonate-admins" })
	if len(roles) != 2 || len(adminGrants) != 2 || !slices.Equal(adminGrants["user"], want) || !slices.Equal(adminGrants["session"], vocabulary["session"]) {
		t.Fatal("unexpected default admin grants", adminGrants)
	}
	builtin := admin.Options{}
	for resource, actions := range vocabulary {
		for _, action := range actions {
			if len(roles["user"][resource]) != 0 || builtin.HasPermission("", "user", admin.Permissions{resource: {action}}) {
				t.Fatal("the built-in user role granted an action", resource, action)
			}
		}
	}
	support := admin.Permissions{"user": {"get", "list"}, "session": {"list"}}
	if _, err := control.NewRole(access.Statements(support)); err != nil {
		t.Fatal(err)
	}
	roles["admin"]["user"] = append(roles["admin"]["user"], "impersonate-admins")
	roles["support"] = support
	custom := admin.Options{Roles: roles}
	if _, err := admin.New(custom); err != nil {
		t.Fatal(err)
	}
	if !custom.HasPermission("", "admin", admin.Permissions{"user": {"impersonate-admins"}}) {
		t.Fatal("an extended admin role did not apply")
	}
	if !custom.HasPermission("", "support", admin.Permissions{"user": {"get", "list"}, "session": {"list"}}) || custom.HasPermission("", "support", admin.Permissions{"user": {"ban"}}) {
		t.Fatal("a role composed from the default vocabulary did not apply")
	}
	roles["admin"]["session"][0] = "delete"
	if fresh := admin.DefaultRoles(); slices.Contains(fresh["admin"]["user"], "impersonate-admins") || !slices.Equal(fresh["admin"]["session"], vocabulary["session"]) || builtin.HasPermission("", "admin", admin.Permissions{"user": {"impersonate-admins"}}) || !builtin.HasPermission("", "admin", admin.Permissions{"session": {"list"}}) {
		t.Fatal("changing a copy of the defaults changed the built-in grants")
	}
}
