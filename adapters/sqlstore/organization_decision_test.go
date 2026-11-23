package sqlstore

import (
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestInvitationRejectionSerializesWithAcceptance(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			store, err := OpenWithOptions(ctx, dialect, dsn, []string{"organization"}, schema.Options{})
			must(err)
			t.Cleanup(func() { store.Close() })
			peer, err := Open(ctx, dialect, dsn)
			must(err)
			t.Cleanup(func() { peer.Close() })

			now := time.Now().UTC().Truncate(time.Millisecond)
			newAccount := func(id string) auth.Session {
				t.Helper()
				user := auth.User{ID: id, Name: id, Email: strings.ToLower(id) + "@example.test", EmailVerified: true, CreatedAt: now, UpdatedAt: now}
				session := auth.Session{ID: id + "-session", UserID: id, Token: id + "-token", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}
				must(store.CreateUser(ctx, user, "", &auth.StoredSession{Session: session}))
				return session
			}
			host := newAccount("Host")
			guest := newAccount("Guest")
			group := org.Organization{ID: "Org", Name: "Org", Slug: "org", CreatedAt: now}
			must(store.CreateOrganization(ctx, group, org.Member{ID: "owner", UserID: host.UserID, Role: "owner", OrganizationID: group.ID, CreatedAt: now}, host.ID, false))
			invite, err := store.InviteOrganizationMember(ctx, org.Invitation{ID: "Pending", Email: "guest@example.test", InviterID: host.UserID, OrganizationID: group.ID, Status: "pending", Role: "member", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, host.ID, false)
			must(err)
			wrong := guest
			wrong.ID = host.ID
			if _, err := store.RejectOrganizationInvitation(ctx, wrong, invite.ID, true); !errors.Is(err, org.ErrUnauthenticated) {
				t.Fatal("mismatched session consumed an invitation", err)
			}
			if _, err := store.RejectOrganizationInvitation(ctx, guest, "pending", true); !errors.Is(err, org.ErrInvitation) {
				t.Fatal("case-folded invitation ID was accepted", err)
			}

			start := make(chan struct{})
			accepted, rejected := make(chan error, 1), make(chan error, 1)
			go func() {
				<-start
				_, _, err := store.AcceptOrganizationInvitation(ctx, invite.ID, guest.ID, auth.User{ID: guest.UserID}, now, true)
				accepted <- err
			}()
			go func() {
				<-start
				_, err := peer.RejectOrganizationInvitation(ctx, guest, invite.ID, true)
				rejected <- err
			}()
			close(start)
			acceptErr, rejectErr := <-accepted, <-rejected
			var status string
			var members int
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "status",(SELECT COUNT(*) FROM "member" WHERE "organizationId"=? AND "userId"=?) FROM "invitation" WHERE "id"=?`), group.ID, guest.UserID, invite.ID).Scan(&status, &members))
			if status == "accepted" && acceptErr == nil && errors.Is(rejectErr, org.ErrInvitation) && members == 1 {
				return
			}
			if status != "rejected" || rejectErr != nil || !errors.Is(acceptErr, org.ErrInvitation) || members != 0 {
				t.Fatalf("inconsistent invitation decision: status=%s members=%d accept=%v reject=%v", status, members, acceptErr, rejectErr)
			}
		})
	}
}
