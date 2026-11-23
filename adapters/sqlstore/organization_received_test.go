package sqlstore

import (
	"errors"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestRecipientInvitationMailbox(t *testing.T) {
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
			service, err := org.NewService(org.Options{Store: store})
			must(err)
			now := time.Now().UTC().Truncate(time.Millisecond)
			const first = "first@example.test"
			const second = "second@example.test"
			for _, u := range []auth.User{
				{ID: "Receiver", Name: "Receiver", Email: first, CreatedAt: now, UpdatedAt: now},
				{ID: "Host", Name: "Host", Email: "host@example.test", CreatedAt: now, UpdatedAt: now},
			} {
				must(store.CreateUser(ctx, u, "", &auth.StoredSession{Session: auth.Session{ID: u.ID + "-session", Token: u.ID + "-token", UserID: u.ID, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}))
			}
			group := org.Organization{ID: "office", Name: first, Slug: "office", CreatedAt: now}
			must(store.CreateOrganization(ctx, group, org.Member{ID: "owner", OrganizationID: group.ID, UserID: "Host", Role: "owner", CreatedAt: now}, "Host-session", false))
			for _, email := range []string{first, second} {
				_, err := store.InviteOrganizationMember(ctx, org.Invitation{ID: email, OrganizationID: group.ID, InviterID: "Host", Email: email, Role: "owner", Status: "pending", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, "Host-session", false)
				must(err)
			}
			detail := func(id string, verified bool) (*org.InvitationDetails, error) {
				return store.OrganizationInvitation(ctx, "Receiver-session", "Receiver", id, verified, false)
			}
			view, err := detail(first, false)
			must(err)
			if view.InviterEmail != "host@example.test" || view.OrganizationSlug != "office" || view.OrganizationName != first {
				t.Fatal("invitation details lost its current sender or destination", view)
			}
			if view, err := detail(first, true); view != nil || !errors.Is(err, org.ErrInvitationAccountUnverified) {
				t.Fatal("unverified recipient bypassed the invitation detail policy", err)
			}
			if view, err := detail(second, true); view != nil || !errors.Is(err, org.ErrRecipient) {
				t.Fatal("nonrecipient read another mailbox's invitation", err)
			}
			if view, err := detail("FIRST@example.test", false); view != nil || !errors.Is(err, org.ErrInvitation) {
				t.Fatal("inexact invitation ID was accepted", err)
			}
			trusted, err := service.ListInvitationsForEmail(ctx, "FIRST@EXAMPLE.TEST")
			must(err)
			if len(trusted) != 1 || trusted[0].OrganizationName != first || trusted[0].Email != first {
				t.Fatal("trusted mailbox lookup did not normalize the address and return its invitation")
			}
			if _, err := service.ListInvitationsForEmail(ctx, ""); !errors.Is(err, org.ErrInvitationEmailRequired) {
				t.Fatal("trusted lookup accepted a missing email", err)
			}
			inbox := func() ([]org.ReceivedInvitation, error) {
				return store.ListReceivedInvitations(ctx, "Receiver-session", "Receiver", false)
			}
			if items, err := inbox(); items != nil || !errors.Is(err, org.ErrInvitationAccountUnverified) {
				t.Fatal("unverified mailbox disclosed invitations", err)
			}
			exec := func(q string, args ...any) {
				t.Helper()
				_, err := store.db.ExecContext(ctx, store.bind(q), args...)
				must(err)
			}
			exec(`UPDATE "user" SET "emailVerified"=? WHERE "id"='Receiver'`, true)
			if items, err := store.ListReceivedInvitations(ctx, "Receiver-session", "receiver", false); items != nil || !errors.Is(err, org.ErrInvitationEmailRequired) {
				t.Fatal("session accepted inexact user", err)
			}
			// Rename the organization and switch the user's mailbox in the same transaction.
			// Every response must observe both updates together.
			done := make(chan error, 1)
			go func() {
				for i := 0; i < 40; i++ {
					email := first
					if i%2 == 0 {
						email = second
					}
					tx, err := peer.db.BeginTx(ctx, nil)
					if err != nil {
						done <- err
						return
					}
					_, err = tx.ExecContext(ctx, peer.bind(`UPDATE "user" SET "email"=? WHERE "id"='Receiver'`), email)
					if err == nil {
						_, err = tx.ExecContext(ctx, peer.bind(`UPDATE "organization" SET "name"=? WHERE "id"='office'`), email)
					}
					if err != nil {
						tx.Rollback()
						done <- err
						return
					}
					if err = tx.Commit(); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			for range 40 {
				items, err := inbox()
				must(err)
				if len(items) != 1 || items[0].Email != items[0].OrganizationName {
					t.Fatal("inbox used different snapshots for the verified mailbox and invitation", items)
				}
			}
			must(<-done)
			exec(`UPDATE "invitation" SET "expiresAt"=? WHERE "id"=?`, store.date(now.Add(-time.Minute)), first)
			if view, err := detail(first, true); view != nil || !errors.Is(err, org.ErrInvitation) {
				t.Fatal("expired invitation details were returned", err)
			}
			exec(`UPDATE "invitation" SET "expiresAt"=? WHERE "id"=?`, store.date(now.Add(time.Hour)), first)
			exec(`DELETE FROM "member" WHERE "id"='owner'`)
			if view, err := detail(first, true); view != nil || !errors.Is(err, org.ErrInviterRemoved) {
				t.Fatal("removed inviter disclosed details", err)
			}
			exec(`DELETE FROM "session" WHERE "id"='Receiver-session'`)
			if items, err := inbox(); items != nil || !errors.Is(err, org.ErrInvitationEmailRequired) {
				t.Fatal("revoked session disclosed recipient invitations", err)
			}
		})
	}
}
