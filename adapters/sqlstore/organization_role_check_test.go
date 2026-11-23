package sqlstore

import (
	"context"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/access"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

// Check role strings against built-in and stored roles from server code.
func TestOrganizationRolePermissionCheck(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			store, err := OpenWithOptions(ctx, dialect, dsn, []string{"organization-roles"}, schema.Options{})
			must(err)
			t.Cleanup(func() { store.Close() })
			now := time.Now().UTC().Truncate(time.Millisecond)
			user := auth.User{ID: "Ada", Name: "Ada", Email: "ada@example.test", CreatedAt: now, UpdatedAt: now}
			session := auth.StoredSession{Session: auth.Session{ID: "Ada-s", Token: "Ada-t", UserID: "Ada", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			must(store.CreateUser(ctx, user, "", &session))
			for _, id := range []string{"Acme", "Other"} {
				must(store.CreateOrganization(ctx, org.Organization{ID: id, Name: id, Slug: id, CreatedAt: now}, org.Member{ID: id + "-m", UserID: "Ada", OrganizationID: id, Role: "owner", CreatedAt: now}, session.ID, false))
			}
			dynamic, err := org.NewService(org.Options{Store: store, DynamicAccessControl: true, RoleControl: org.DefaultRoleControl()})
			must(err)
			_, err = organizationRoleClient(t, store, dynamic, session.Session).CreateOrganizationRole(ctx, org.CreateRoleRequest{OrganizationID: "Acme", Role: "reviewer", Permission: access.Statements{"organization": {"update"}}})
			must(err)
			plain, err := org.NewService(org.Options{Store: store})
			must(err)
			update := access.Statements{"organization": {"update"}}
			for _, tc := range []struct {
				name    string
				service *org.Service
				check   org.RolePermissionCheck
				want    bool
			}{
				{"stored role in its organization", dynamic, org.RolePermissionCheck{OrganizationID: "Acme", Role: "reviewer", Permissions: update}, true},
				{"stored role in another organization", dynamic, org.RolePermissionCheck{OrganizationID: "Other", Role: "reviewer", Permissions: update}, false},
				{"stored role without dynamic access control", plain, org.RolePermissionCheck{OrganizationID: "Acme", Role: "reviewer", Permissions: update}, false},
				{"built-in member grant", dynamic, org.RolePermissionCheck{OrganizationID: "Acme", Role: "member", Permissions: access.Statements{"ac": {"read"}}}, true},
				{"built-in member denial", dynamic, org.RolePermissionCheck{OrganizationID: "Acme", Role: "member", Permissions: update}, false},
				{"any listed role", dynamic, org.RolePermissionCheck{OrganizationID: "Acme", Role: "member, reviewer", Permissions: update}, true},
				{"creator without the shortcut", dynamic, org.RolePermissionCheck{OrganizationID: "Acme", Role: "owner", Permissions: access.Statements{"billing": {"refund"}}}, false},
				{"creator with the shortcut", dynamic, org.RolePermissionCheck{OrganizationID: "Acme", Role: "owner", Permissions: access.Statements{"billing": {"refund"}}, AllowCreatorAllPermissions: true}, true},
				{"shortcut for another role", dynamic, org.RolePermissionCheck{OrganizationID: "Acme", Role: "admin", Permissions: access.Statements{"billing": {"refund"}}, AllowCreatorAllPermissions: true}, false},
				{"empty request", dynamic, org.RolePermissionCheck{OrganizationID: "Acme", Role: "owner", AllowCreatorAllPermissions: true}, false},
				{"local check without an organization", plain, org.RolePermissionCheck{Role: "owner", Permissions: access.Statements{"billing": {"refund"}}, AllowCreatorAllPermissions: true}, true},
				{"local check of built-in grants", plain, org.RolePermissionCheck{Role: "admin", Permissions: update}, true},
			} {
				got, err := tc.service.HasRolePermission(ctx, tc.check)
				must(err)
				if got != tc.want {
					t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
				}
			}
		})
	}
}
