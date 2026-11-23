package sqlstore

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/access"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

func TestCustomOrganizationRolePolicyAcrossEngines(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			base, peer, creator, issuer, group := invitationWriterFixture(t, dialect)
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			roles := map[string]access.Statements{
				"founder": {}, "editor": {"invitation": {"create"}}, "supervisor": {"member": {"update"}},
			}
			service, err := org.NewService(org.Options{Store: base, CreatorRole: "founder", Roles: roles, Teams: &org.TeamOptions{}})
			must(err)
			scoped := service.Store().(*Store)
			roles["editor"]["invitation"][0] = "cancel"
			delete(roles, "supervisor")
			reused, err := org.NewService(org.Options{Store: scoped})
			must(err)
			_, err = peer.db.ExecContext(ctx, peer.bind(`UPDATE "member" SET "role"=? WHERE "id"=?`), "founder", "owner")
			must(err)
			change := func(role string) error {
				_, err := service.UpdateMemberRole(ctx, creator, org.UpdateMemberRoleRequest{OrganizationID: group.ID, MemberID: "admin", Roles: []string{role}})
				return err
			}
			must(change("editor"))
			proposal := org.Invitation{ID: "first", InviterID: issuer.UserID, OrganizationID: group.ID, Email: "first@example.test", Status: "pending", Role: "member", CreatedAt: group.CreatedAt, ExpiresAt: group.CreatedAt.Add(time.Hour)}
			issue := func(store *Store, grant org.Invitation, hook org.InvitationCreationHook) error {
				_, err := store.IssuePreparedInvitation(ctx, grant, issuer, org.InvitationIssueOptions{}, hook)
				return err
			}
			if err := issue(base, proposal, nil); !errors.Is(err, org.ErrInviteDenied) {
				t.Fatalf("base service inherited a configured grant: %v", err)
			}
			must(issue(scoped, proposal, func(context.Context, org.InvitationCreationEvent) (*org.InvitationChanges, error) {
				return &org.InvitationChanges{Roles: []string{"supervisor"}}, nil
			}))
			var savedRole string
			must(peer.db.QueryRowContext(ctx, peer.bind(`SELECT "role" FROM "invitation" WHERE "id"=?`), proposal.ID).Scan(&savedRole))
			if savedRole != "supervisor" {
				t.Fatalf("saved callback role %q", savedRole)
			}
			proposal.ID, proposal.Email = "second", "second@example.test"
			if err := issue(scoped, proposal, func(context.Context, org.InvitationCreationEvent) (*org.InvitationChanges, error) {
				return &org.InvitationChanges{Roles: []string{"founder"}}, nil
			}); !errors.Is(err, org.ErrRoleDenied) {
				t.Fatalf("unprivileged callback creator grant: %v", err)
			}
			err = issue(scoped, proposal, func(context.Context, org.InvitationCreationEvent) (*org.InvitationChanges, error) {
				return nil, change("admin")
			})
			if !errors.Is(err, org.ErrInviteDenied) {
				t.Fatalf("revoked custom role issued a grant: %v", err)
			}
			var count int
			must(peer.db.QueryRowContext(ctx, peer.bind(`SELECT COUNT(*) FROM "invitation" WHERE "id"=?`), proposal.ID).Scan(&count))
			if count != 0 {
				t.Fatal("denied grant committed")
			}
			user := auth.User{ID: "direct", Email: "direct@example.test", Name: "Direct", CreatedAt: group.CreatedAt, UpdatedAt: group.CreatedAt}
			must(base.CreateUser(ctx, user, "", nil))
			added, err := reused.AddMember(ctx, org.AddMemberRequest{OrganizationID: group.ID, UserID: user.ID, Roles: []string{"supervisor"}})
			must(err)
			if added.Role != "supervisor" {
				t.Fatalf("trusted grant saved role %q", added.Role)
			}
		})
	}
}
