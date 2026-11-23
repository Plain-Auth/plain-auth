package sqlstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/authtest"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestInvitationDecisionHookRevalidation(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store, err := OpenWithOptions(t.Context(), dialect, organizationTestDSN(t, dialect), []string{"admin", "organization"}, schema.Options{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			app, err := authtest.New(auth.Options{Store: store, BaseURL: "https://org.example.test", Secret: strings.Repeat("s", 40)})
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				change   string
				decision org.InvitationDecision
				want     error
			}{
				{"organization", org.RejectInvitation, org.ErrInvitationDecisionChanged},
				{"email", org.RejectInvitation, org.ErrRecipient},
				{"unverify", org.RejectInvitation, org.ErrUnverified},
				{"concurrent-rejection", org.RejectInvitation, org.ErrInvitation},
				{"revoked", org.CancelInvitation, org.ErrUnauthenticated},
				{"delegated", org.CancelInvitation, org.ErrUnauthenticated},
				{"demoted", org.CancelInvitation, org.ErrCancelDenied},
				{"new-membership", org.CancelInvitation, org.ErrInvitationDecisionChanged},
				{"new-invitation", org.CancelInvitation, org.ErrInvitationDecisionChanged},
				{"detached-callback", org.CancelInvitation, nil},
			} {
				t.Run(tc.change, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel()
					must := func(err error) {
						t.Helper()
						if err != nil {
							t.Fatal(err)
						}
					}
					newSession := func() (auth.User, auth.Session) {
						t.Helper()
						u := authtest.NewUser()
						u.EmailVerified = true
						user, err := app.SaveUser(ctx, u)
						must(err)
						login, err := app.Login(ctx, user.ID)
						must(err)
						return user, login.Session
					}
					host, owner := newSession()
					guest, recipient := newSession()
					group := authtest.NewOrganization(tc.change)
					member := org.Member{ID: group.ID, OrganizationID: group.ID, UserID: host.ID, Role: "owner", CreatedAt: group.CreatedAt}
					must(store.CreateOrganization(ctx, group, member, owner.ID, false))
					inv, err := store.InviteOrganizationMember(ctx, org.Invitation{ID: group.ID, OrganizationID: group.ID, InviterID: host.ID, Email: guest.Email, Role: "member", Status: "pending", CreatedAt: group.CreatedAt, ExpiresAt: group.CreatedAt.Add(time.Hour)}, owner.ID, false)
					must(err)
					actor := owner
					if tc.decision == org.RejectInvitation {
						actor = recipient
					}
					calls := 0
					event, err := store.ObserveInvitationDecision(ctx, actor, inv.ID, tc.decision, true, func(ctx context.Context, e org.InvitationDecisionEvent) error {
						calls++
						if e.Actor.ID != actor.UserID || e.Invitation.ID != inv.ID || e.Organization.ID != group.ID || e.Invitation.Status != "pending" {
							t.Fatal("callback got the wrong invitation, actor or organization")
						}
						// Re-enter the same pool, including SQLite's single connection.
						write := func(q string, args ...any) error {
							_, err := store.db.ExecContext(ctx, store.bind(q), args...)
							return err
						}
						switch tc.change {
						case "organization":
							return write(`UPDATE "organization" SET "name"=? WHERE "id"=?`, "Renamed", group.ID)
						case "email":
							return write(`UPDATE "user" SET "email"=? WHERE "id"=?`, "changed@example.test", guest.ID)
						case "unverify":
							return write(`UPDATE "user" SET "emailVerified"=? WHERE "id"=?`, false, guest.ID)
						case "concurrent-rejection":
							_, err := store.RejectOrganizationInvitation(ctx, recipient, inv.ID, true)
							return err
						case "revoked":
							return write(`DELETE FROM "session" WHERE "id"=?`, actor.ID)
						case "delegated":
							return write(`UPDATE "session" SET "impersonatedBy"=? WHERE "id"=?`, guest.ID, actor.ID)
						case "demoted":
							return write(`UPDATE "member" SET "role"='member' WHERE "id"=?`, member.ID)
						case "new-membership":
							return write(`UPDATE "member" SET "id"=? WHERE "id"=?`, "new-"+member.ID, member.ID)
						case "new-invitation":
							return write(`UPDATE "invitation" SET "role"='admin' WHERE "id"=?`, inv.ID)
						case "detached-callback":
							e.Invitation.Email, e.Actor.Name, e.Organization.Name = "other@example.test", "Other", ""
						}
						return nil
					})
					if !errors.Is(err, tc.want) || calls != 1 {
						t.Fatalf("decision returned %v, expected %v, callback calls=%d", err, tc.want, calls)
					}
					var status string
					must(store.db.QueryRowContext(ctx, store.bind(`SELECT "status" FROM "invitation" WHERE "id"=?`), inv.ID).Scan(&status))
					if tc.want == nil {
						if event == nil || status != "canceled" || event.Invitation.Email != guest.Email || event.Actor.Name != host.Name || event.Organization.Name != group.Name {
							t.Fatal("host mutation changed the committed snapshot", event)
						}
					} else if event != nil || tc.change == "concurrent-rejection" && status != "rejected" || tc.change != "concurrent-rejection" && status != "pending" {
						t.Fatal("stale approval changed the invitation status", status)
					}
				})
			}
		})
	}
}
