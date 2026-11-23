package sqlstore

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/access"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestOrganizationRoleUpdate(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			base, peer, owner, admin, group := invitationWriterFixture(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"organization-teams", "organization-roles"})
			must(err)
			must(base.migrate(ctx, ddl))
			control := org.DefaultRoleControl()
			roles := org.DefaultRoles()
			roles["admin"] = access.Statements{"ac": {"read", "update"}}
			options := org.Options{Store: base, DynamicAccessControl: true, Roles: roles, RoleControl: control}
			service, err := org.NewService(options)
			must(err)
			options.Store = peer
			second, err := org.NewService(options)
			must(err)
			sdk := organizationRoleClient(t, base, service, owner)
			delegate := organizationRoleClient(t, peer, second, admin)
			create := func(name string) org.RoleQuery {
				t.Helper()
				created, err := sdk.CreateOrganizationRole(ctx, org.CreateRoleRequest{
					OrganizationID: group.ID, Role: name, Permission: access.Statements{"team": {"create"}},
				})
				must(err)
				return org.RoleQuery{OrganizationID: group.ID, RoleID: created.RoleData.ID}
			}
			desk := create("desk")
			_, err = delegate.UpdateOrganizationRole(ctx, desk, org.RoleUpdate{RoleName: "editor"})
			var missing *auth.MissingPermissionsError
			if !errors.As(err, &missing) || missing.Code != org.ErrUpdateRoleDenied.Code || !slices.Equal(missing.MissingPermissions, []string{"team:create"}) {
				t.Fatalf("renaming an existing grant requires authority to delegate it: %v", err)
			}
			before, err := sdk.GetOrganizationRole(ctx, desk)
			must(err)
			if before.Role != "desk" || before.UpdatedAt != nil || !slices.Equal(before.Permission["team"], []string{"create"}) {
				t.Fatal("a denied rename changed the definition", before)
			}
			cleared, err := delegate.UpdateOrganizationRole(ctx, desk, org.RoleUpdate{RoleName: "Editor", Permission: access.Statements{}})
			must(err)
			if !cleared.Success || cleared.RoleData.Role != "editor" || cleared.RoleData.UpdatedAt != nil || cleared.RoleData.Permission == nil || len(cleared.RoleData.Permission) != 0 {
				t.Fatal("unexpected SDK acknowledgement after clearing grants and renaming", cleared)
			}
			current, err := sdk.GetOrganizationRole(ctx, desk)
			must(err)
			if current.UpdatedAt == nil {
				t.Fatal("stored role has no modification time")
			}
			touched, err := sdk.UpdateOrganizationRole(ctx, desk, org.RoleUpdate{})
			must(err)
			if touched.RoleData.UpdatedAt == nil || !touched.RoleData.UpdatedAt.Equal(*current.UpdatedAt) || len(touched.RoleData.Permission) != 0 {
				t.Fatal("an empty edit must preserve grants and acknowledge the previous timestamp", touched)
			}
			stores := []org.RoleUpdateStore{service.Store().(org.RoleUpdateStore), second.Store().(org.RoleUpdateStore)}
			race := func(queries [2]org.RoleQuery, changes [2]org.RoleUpdate) [2]error {
				t.Helper()
				start := make(chan struct{})
				done := make(chan struct{}, 2)
				var results [2]error
				for i, store := range stores {
					go func() {
						<-start
						_, results[i] = store.UpdateOrganizationRole(ctx, owner.UserID, owner.Token, queries[i], changes[i], *control)
						done <- struct{}{}
					}()
				}
				close(start)
				<-done
				<-done
				return results
			}
			edits := race([2]org.RoleQuery{desk, desk}, [2]org.RoleUpdate{{RoleName: "copydesk"}, {Permission: access.Statements{"ac": {"read"}}}})
			must(edits[0])
			must(edits[1])
			after, err := sdk.GetOrganizationRole(ctx, desk)
			must(err)
			if after.ID != desk.RoleID || after.Role != "copydesk" || !slices.Equal(after.Permission["ac"], []string{"read"}) {
				t.Fatal("concurrent edits lost a name or permission change", after)
			}
			other := create("other")
			queries := [2]org.RoleQuery{desk, other}
			results := race(queries, [2]org.RoleUpdate{{RoleName: "same", Permission: access.Statements{}}, {RoleName: "SAME", Permission: access.Statements{}}})
			if !((results[0] == nil && errors.Is(results[1], org.ErrRoleNameTaken)) || (results[1] == nil && errors.Is(results[0], org.ErrRoleNameTaken))) {
				t.Fatalf("concurrent renames must have one winner: %v", results)
			}
			for i, q := range queries {
				row, err := sdk.GetOrganizationRole(ctx, q)
				must(err)
				if results[i] == nil {
					if row.Role != "same" || len(row.Permission) != 0 {
						t.Fatal("winning rename did not persist both changes", row)
					}
				} else if row.Role != [2]string{"copydesk", "other"}[i] || len(row.Permission) != 1 {
					t.Fatal("failed rename changed the original definition", row)
				}
			}
		})
	}
}
