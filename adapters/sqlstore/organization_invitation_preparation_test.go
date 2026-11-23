package sqlstore

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

func TestInvitationPreparationAcrossEngines(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store, peer, owner, admin, group := invitationWriterFixture(t, dialect)
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			newGrant := func(id string) org.Invitation {
				return org.Invitation{ID: id, OrganizationID: group.ID, InviterID: owner.UserID, Email: id + "@example.test", Role: "member", Status: "pending", CreatedAt: group.CreatedAt, ExpiresAt: group.CreatedAt.Add(time.Hour)}
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			draft := newGrant("original")
			_, err := store.InviteOrganizationMember(ctx, draft, owner.ID, false)
			must(err)
			raw := newGrant("replacement")
			raw.Email = draft.Email
			resolve, before := 0, 0
			limit, err := store.WithOrganizationInvitationLimit(org.InvitationLimit{Resolve: func(context.Context, org.InvitationLimitInput) (int, error) {
				resolve++
				return 1, nil
			}})
			must(err)
			scoped := limit.(*Store)
			stop := errors.New("host veto")
			run := func(hook org.InvitationCreationHook, want error) {
				t.Helper()
				res, err := scoped.IssuePreparedInvitation(ctx, raw, owner, org.InvitationIssueOptions{Replace: true, UseActiveOrganization: true}, hook)
				if res != nil || !errors.Is(err, want) {
					t.Fatalf("replacement returned %v, want %v", err, want)
				}
				var status string
				must(peer.db.QueryRowContext(ctx, peer.bind(`SELECT "status" FROM "invitation" WHERE "id"=?`), draft.ID).Scan(&status))
				var count int
				must(peer.db.QueryRowContext(ctx, peer.bind(`SELECT COUNT(*) FROM "invitation" WHERE "id"=?`), raw.ID).Scan(&count))
				if status != "pending" || count != 0 {
					t.Fatal("failed preparation disturbed the original invitation")
				}
			}
			run(func(ctx context.Context, e org.InvitationCreationEvent) (*org.InvitationChanges, error) {
				before++
				if resolve != 1 || e.Invitation.Email != draft.Email || e.Inviter.ID != owner.UserID || e.Organization.ID != group.ID {
					t.Fatal("unexpected preparation inputs")
				}
				return nil, stop
			}, stop)
			run(func(ctx context.Context, e org.InvitationCreationEvent) (*org.InvitationChanges, error) {
				before++
				_, err := peer.db.ExecContext(ctx, peer.bind(`UPDATE "organization" SET "name"=? WHERE "id"=?`), "Renamed", group.ID)
				return nil, err
			}, org.ErrInvitationLimitChanged)
			run(func(ctx context.Context, e org.InvitationCreationEvent) (*org.InvitationChanges, error) {
				before++
				other := draft
				other.ExpiresAt = other.ExpiresAt.Add(time.Hour)
				_, err := peer.InviteOrganizationMember(ctx, other, owner.ID, true)
				return nil, err
			}, org.ErrInvitationCreationChanged)
			run(func(ctx context.Context, e org.InvitationCreationEvent) (*org.InvitationChanges, error) {
				before++
				return nil, peer.SetActiveOrganization(ctx, owner.ID, owner.UserID, nil)
			}, org.ErrNoActiveOrg)
			must(peer.SetActiveOrganization(ctx, owner.ID, owner.UserID, &group.ID))
			run(func(ctx context.Context, e org.InvitationCreationEvent) (*org.InvitationChanges, error) {
				before++
				_, err := peer.InviteOrganizationMember(ctx, newGrant("last-slot"), owner.ID, false)
				return nil, err
			}, org.ErrInvitationLimit)
			if resolve != 5 || before != 5 {
				t.Fatalf("callbacks reran during commit: %d resolutions and %d preparations", resolve, before)
			}

			calls := 0
			renewed, err := scoped.IssuePreparedInvitation(ctx, raw, owner, org.InvitationIssueOptions{Resend: true}, func(context.Context, org.InvitationCreationEvent) (*org.InvitationChanges, error) {
				calls++
				return nil, stop
			})
			must(err)
			if calls != 0 || resolve != 5 || !renewed.Resent || renewed.Invitation.ID != draft.ID {
				t.Fatal("renewal invoked a creation policy")
			}

			teams, err := store.WithOrganizationTeams(org.TeamOptions{})
			must(err)
			adminGrant := newGrant("admin-sent")
			adminGrant.InviterID = admin.UserID
			for _, tc := range []struct {
				changes org.InvitationChanges
				want    error
			}{
				{org.InvitationChanges{Roles: []string{"owner"}}, org.ErrRoleDenied},
				{org.InvitationChanges{TeamIDs: []string{"missing"}}, org.ErrTeamNotFound},
				{org.InvitationChanges{Email: &draft.Email}, org.ErrAlreadyInvited},
			} {
				result, err := teams.(*Store).IssuePreparedInvitation(ctx, adminGrant, admin, org.InvitationIssueOptions{}, func(context.Context, org.InvitationCreationEvent) (*org.InvitationChanges, error) {
					return &tc.changes, nil
				})
				if result != nil || !errors.Is(err, tc.want) {
					t.Fatalf("invalid override returned %v, want %v", err, tc.want)
				}
			}
			// An explicit destination survives a selection change made by the host.
			created, err := store.IssuePreparedInvitation(ctx, raw, owner, org.InvitationIssueOptions{Replace: true}, func(ctx context.Context, e org.InvitationCreationEvent) (*org.InvitationChanges, error) {
				return nil, peer.SetActiveOrganization(ctx, owner.ID, owner.UserID, nil)
			})
			must(err)
			if created.Resent || created.Invitation.ID != raw.ID || created.Organization.ID != group.ID {
				t.Fatal("explicit organization changed during preparation")
			}
			var status string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "status" FROM "invitation" WHERE "id"=?`), draft.ID).Scan(&status))
			if status != "canceled" {
				t.Fatal("successful preparation left both replacement grants live")
			}
			result, err := store.IssuePreparedInvitation(ctx, adminGrant, admin, org.InvitationIssueOptions{}, func(ctx context.Context, e org.InvitationCreationEvent) (*org.InvitationChanges, error) {
				_, err := peer.db.ExecContext(ctx, peer.bind(`UPDATE "member" SET "role"='member' WHERE "id"=?`), "admin")
				return nil, err
			})
			if result != nil || !errors.Is(err, org.ErrInviteDenied) {
				t.Fatal("inviter lost authority during preparation", err)
			}
			result, err = store.IssuePreparedInvitation(ctx, newGrant("last"), owner, org.InvitationIssueOptions{}, func(ctx context.Context, e org.InvitationCreationEvent) (*org.InvitationChanges, error) {
				_, err := peer.db.ExecContext(ctx, peer.bind(`DELETE FROM "session" WHERE "id"=?`), owner.ID)
				return nil, err
			})
			if result != nil || !errors.Is(err, org.ErrUnauthenticated) {
				t.Fatal("ended session committed its prepared invitation", err)
			}

		})
	}
}

func TestInvitationRoleAdmissionAcrossEngines(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			store, _, _, admin, group := invitationWriterFixture(t, dialect)
			inv := org.Invitation{ID: "proposal", OrganizationID: group.ID, InviterID: admin.UserID, Email: "guest@example.test", Role: "", Status: "pending", CreatedAt: group.CreatedAt, ExpiresAt: group.CreatedAt.Add(time.Hour)}
			hook := func(context.Context, org.InvitationCreationEvent) (*org.InvitationChanges, error) {
				t.Fatal("rejected invitation reached host preparation")
				return nil, nil
			}
			check := func(code string) {
				t.Helper()
				_, err := store.IssuePreparedInvitation(ctx, inv, admin, org.InvitationIssueOptions{}, hook)
				var failure *auth.APIError
				if !errors.As(err, &failure) || failure.Code != code {
					t.Fatalf("unexpected role decision: %v, want %s", err, code)
				}
			}
			check("ROLE_NOT_FOUND")
			_, err := store.db.ExecContext(ctx, store.bind(`UPDATE "member" SET "role"='member' WHERE "id"=?`), "admin")
			if err != nil {
				t.Fatal(err)
			}
			check("YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION")
			_, err = store.db.ExecContext(ctx, store.bind(`DELETE FROM "member" WHERE "id"=?`), "admin")
			if err != nil {
				t.Fatal(err)
			}
			check("MEMBER_NOT_FOUND")
		})
	}
}
