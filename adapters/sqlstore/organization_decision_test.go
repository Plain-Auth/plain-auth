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

func TestInvitationDecisionsSerializeWithAcceptance(t *testing.T) {
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
			switch status {
			case "accepted":
				if acceptErr != nil || !errors.Is(rejectErr, org.ErrInvitation) || members != 1 {
					t.Fatalf("inconsistent acceptance: members=%d accept=%v reject=%v", members, acceptErr, rejectErr)
				}
			case "rejected":
				if rejectErr != nil || !errors.Is(acceptErr, org.ErrInvitation) || members != 0 {
					t.Fatalf("inconsistent rejection: members=%d accept=%v reject=%v", members, acceptErr, rejectErr)
				}
			default:
				t.Fatalf("invitation decision was lost: status=%s accept=%v reject=%v", status, acceptErr, rejectErr)
			}

			second := newAccount("Second")
			invite.ID, invite.Email, invite.Status = "OtherGrant", "second@example.test", "pending"
			_, err = store.InviteOrganizationMember(ctx, invite, host.ID, false)
			must(err)
			start = make(chan struct{})
			canceled := make(chan error, 1)
			go func() {
				<-start
				_, _, err := store.AcceptOrganizationInvitation(ctx, invite.ID, second.ID, auth.User{ID: second.UserID}, now, false)
				accepted <- err
			}()
			go func() {
				<-start
				_, err := peer.CancelOrganizationInvitation(ctx, host, invite.ID)
				canceled <- err
			}()
			close(start)
			acceptErr = <-accepted
			must(<-canceled)
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "status",(SELECT COUNT(*) FROM "member" WHERE "organizationId"=? AND "userId"=?) FROM "invitation" WHERE "id"=?`), group.ID, second.UserID, invite.ID).Scan(&status, &members))
			if status != "canceled" || (acceptErr == nil && members != 1) || (acceptErr != nil && (!errors.Is(acceptErr, org.ErrInvitation) || members != 0)) {
				t.Fatalf("cancellation did not preserve the serialized admission: status=%s members=%d accept=%v", status, members, acceptErr)
			}

			last := newAccount("Boundary")
			invite.ID, invite.Email, invite.Status, invite.ExpiresAt = "AtDeadline", "boundary@example.test", "pending", now.Add(time.Minute)
			_, err = store.InviteOrganizationMember(ctx, invite, host.ID, false)
			must(err)
			recipient := auth.User{ID: last.UserID}
			if _, _, err := store.AcceptOrganizationInvitation(ctx, invite.ID, last.ID, recipient, invite.ExpiresAt.Add(time.Millisecond), true); !errors.Is(err, org.ErrInvitation) {
				t.Fatal("accepted an invitation past its expiry", err)
			}
			atDeadline, _, err := store.AcceptOrganizationInvitation(ctx, invite.ID, last.ID, recipient, invite.ExpiresAt, true)
			must(err)
			if atDeadline.Status != "accepted" {
				t.Fatal("pending invitation could not be accepted at its exact deadline")
			}
		})
	}
}
