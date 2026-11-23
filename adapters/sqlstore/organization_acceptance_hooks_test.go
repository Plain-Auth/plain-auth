package sqlstore

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/authtest"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

func TestInvitationAcceptanceHookAdmission(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store, peer, owner, _, group := invitationWriterFixture(t, dialect)
			for _, tc := range []struct {
				change string
				want   error
			}{
				{"full", org.ErrMemberLimit},
				{"session", org.ErrUnauthenticated},
				{"expiry", org.ErrInvitation},
				{"recipient", org.ErrRecipient},
				{"verification", org.ErrUnverified},
				{"rejected", org.ErrInvitation},
				{"role", org.ErrMembershipPolicyChanged},
				{"seat-taken", org.ErrMemberLimit},
				{"accept", nil},
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
					create := func() (auth.User, auth.Session) {
						t.Helper()
						u := authtest.NewUser()
						u.EmailVerified = true
						ss := auth.Session{ID: u.ID + "-s", Token: u.ID + "-t", UserID: u.ID, CreatedAt: u.CreatedAt, UpdatedAt: u.CreatedAt, ExpiresAt: group.CreatedAt.Add(time.Hour)}
						must(store.CreateUser(ctx, u, "", &auth.StoredSession{Session: ss}))
						return u, ss
					}
					guest, session := create()
					inv, err := store.InviteOrganizationMember(ctx, org.Invitation{ID: guest.ID, OrganizationID: group.ID, InviterID: owner.UserID, Email: guest.Email, Role: "member", Status: "pending", CreatedAt: group.CreatedAt, ExpiresAt: group.CreatedAt.Add(time.Hour)}, owner.ID, false)
					must(err)
					var resolutions, calls int
					scoped, err := store.WithMembershipLimit(org.MembershipLimit{Resolve: func(ctx context.Context, u auth.User, g org.Organization) (int, error) {
						resolutions++
						var count int
						err := store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "member" WHERE "organizationId"=?`), g.ID).Scan(&count)
						if tc.change == "full" {
							return count, err
						}
						return count + 1, err
					}})
					must(err)
					event, err := scoped.ObserveInvitationAcceptance(ctx, session, inv.ID, true, func(ctx context.Context, e org.InvitationDecisionEvent) error {
						calls++
						if resolutions != 1 || e.Member != nil || e.Actor.ID != guest.ID || e.Organization.ID != group.ID || e.Invitation.Status != "pending" {
							t.Fatal("unexpected acceptance preparation", e)
						}
						// Independent writes must be possible while the host hook runs.
						write := func(q string, args ...any) error {
							_, err := peer.db.ExecContext(ctx, peer.bind(q), args...)
							return err
						}
						switch tc.change {
						case "session":
							return write(`DELETE FROM "session" WHERE "id"=?`, session.ID)
						case "expiry":
							return write(`UPDATE "invitation" SET "expiresAt"=? WHERE "id"=?`, peer.date(group.CreatedAt), inv.ID)
						case "recipient":
							return write(`UPDATE "user" SET "email"=? WHERE "id"=?`, "changed@example.test", guest.ID)
						case "verification":
							return write(`UPDATE "user" SET "emailVerified"=? WHERE "id"=?`, false, guest.ID)
						case "rejected":
							_, err := peer.RejectOrganizationInvitation(ctx, session, inv.ID, true)
							return err
						case "role":
							return write(`UPDATE "invitation" SET "role"='admin' WHERE "id"=?`, inv.ID)
						case "seat-taken":
							other, _ := create()
							return peer.AddOrganizationMember(ctx, org.Member{ID: other.ID, OrganizationID: group.ID, Role: "member", UserID: other.ID, CreatedAt: group.CreatedAt}, "")
						}
						return nil
					})
					wantCalls := 1
					if tc.change == "full" {
						wantCalls = 0
					}
					if !errors.Is(err, tc.want) || resolutions != 1 || calls != wantCalls {
						t.Fatalf("acceptance returned %v, want %v; resolver=%d before=%d", err, tc.want, resolutions, calls)
					}
					var status string
					var members int
					must(store.db.QueryRowContext(ctx, store.bind(`SELECT "status" FROM "invitation" WHERE "id"=?`), inv.ID).Scan(&status))
					must(store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "member" WHERE "userId"=? AND "organizationId"=?`), guest.ID, group.ID).Scan(&members))
					if tc.want == nil {
						if members != 1 || status != "accepted" || event == nil || event.Member == nil || event.Member.UserID != guest.ID || event.Invitation.Status != status {
							t.Fatal("acceptance did not return the committed membership")
						}
					} else if event != nil || members != 0 || tc.change == "rejected" && status != "rejected" || tc.change != "rejected" && status != "pending" {
						t.Fatal("unsuccessful acceptance changed the grant or membership", status, members)
					}
				})
			}
		})
	}
}
