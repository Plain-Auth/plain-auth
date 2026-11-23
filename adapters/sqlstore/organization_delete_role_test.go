package sqlstore

import (
	"errors"
	"fmt"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestOrganizationRoleDeletionAndAssignment(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			base, peer, owner, _, group := invitationWriterFixture(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"organization-teams", "organization-roles"})
			must(err)
			must(base.migrate(ctx, ddl))
			service, err := org.NewService(org.Options{Store: base, DynamicAccessControl: true})
			must(err)
			second, err := org.NewService(org.Options{Store: peer, DynamicAccessControl: true})
			must(err)
			roles := second.Store().(*Store)
			sdk := organizationRoleClient(t, base, service, owner)
			save := func(id string) {
				t.Helper()
				_, err := peer.db.ExecContext(ctx, peer.bind(`INSERT INTO "organizationRole" ("id","organizationId","role","permission","createdAt") VALUES (?,?,?,?,?)`), id, group.ID, id, "{}", peer.date(group.CreatedAt))
				must(err)
			}
			save("release & edit")
			must(sdk.DeleteOrganizationRole(ctx, org.RoleQuery{RoleName: "release & edit"}))
			if err := sdk.DeleteOrganizationRole(ctx, org.RoleQuery{RoleID: "release & edit"}); err == nil {
				t.Fatal("deleted the same stored role twice")
			}
			for i := range 8 {
				role := fmt.Sprintf("desk-%d", i)
				save(role)
				assigned, deleted := make(chan error, 1), make(chan error, 1)
				start := make(chan struct{})
				go func() {
					<-start
					_, err := roles.UpdateOrganizationMemberRole(ctx, owner.UserID, owner.Token, org.UpdateMemberRoleRequest{OrganizationID: group.ID, MemberID: "admin", Roles: []string{"member", role}})
					assigned <- err
				}()
				go func() {
					<-start
					deleted <- service.Store().(org.RoleDeletionStore).DeleteOrganizationRole(ctx, owner.UserID, owner.Token, org.RoleQuery{OrganizationID: group.ID, RoleID: role})
				}()
				close(start)
				assignErr, deleteErr := <-assigned, <-deleted
				var count int
				must(base.db.QueryRowContext(ctx, base.bind(`SELECT COUNT(*) FROM "organizationRole" WHERE "id"=?`), role).Scan(&count))
				if assignErr == nil {
					if !errors.Is(deleteErr, org.ErrRoleAssigned) || count != 1 {
						t.Fatalf("retired a role during a successful assignment: count %d, error %v", count, deleteErr)
					}
				} else {
					var problem *auth.APIError
					if deleteErr != nil || count != 0 || !errors.As(assignErr, &problem) || problem.Code != "ROLE_NOT_FOUND" {
						t.Fatalf("competing role assignment and deletion: count %d, assignment %v, deletion %v", count, assignErr, deleteErr)
					}
				}
			}
			save("press")
			tx, err := peer.db.BeginTx(ctx, nil)
			must(err)
			defer tx.Rollback()
			for i := range 105 {
				id := fmt.Sprintf("participant-%03d", i)
				memberRoles := "pressroom"
				if i == 104 {
					memberRoles = "member, press "
				}
				_, err := tx.ExecContext(ctx, peer.bind(`INSERT INTO "user" ("id","name","email","emailVerified","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`),
					id, id, id+"@example.test", false, peer.date(group.CreatedAt), peer.date(group.CreatedAt))
				must(err)
				_, err = tx.ExecContext(ctx, peer.bind(`INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES (?,?,?,?,?)`),
					id, group.ID, id, memberRoles, peer.date(group.CreatedAt))
				must(err)
			}
			must(tx.Commit())
			err = roles.DeleteOrganizationRole(ctx, owner.UserID, owner.Token, org.RoleQuery{RoleName: "press"})
			if !errors.Is(err, org.ErrRoleAssigned) {
				t.Fatal("lost an exact assignment beyond the first hundred similar memberships", err)
			}
			save("retained")
			must(peer.DeleteSession(ctx, owner.Token))
			err = roles.DeleteOrganizationRole(ctx, owner.UserID, owner.Token, org.RoleQuery{OrganizationID: group.ID, RoleID: "retained"})
			if !errors.Is(err, org.ErrUnauthenticated) {
				t.Fatal("revoked session authorized role removal", err)
			}
		})
	}
}
