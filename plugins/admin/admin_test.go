package admin_test

import (
	"testing"
	"time"

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
}
