package sqlstore

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
)

func TestInvitationLimitReservesTheLastSlot(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store, peer, owner, admin, group := invitationWriterFixture(t, dialect)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			entered := make(chan struct{}, 2)
			proceed := make(chan struct{})
			policy := org.InvitationLimit{Resolve: func(ctx context.Context, in org.InvitationLimitInput) (int, error) {
				if in.Member.UserID != in.User.ID || in.Member.OrganizationID != group.ID || in.Organization.ID != group.ID {
					return 0, errors.New("incorrect invitation quota scope")
				}
				var seats int
				if err := store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "member" WHERE "organizationId"=?`), group.ID).Scan(&seats); err != nil {
					return 0, err
				}
				entered <- struct{}{}
				select {
				case <-proceed:
					return 1, nil
				case <-ctx.Done():
					return 0, ctx.Err()
				}
			}}
			one, err := store.WithOrganizationInvitationLimit(policy)
			must(err)
			two, err := peer.WithOrganizationInvitationLimit(policy)
			must(err)
			var releasedAt time.Time
			issue := func(s org.Store, actor auth.Session, id string) error {
				now := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Minute)
				grant, err := s.InviteOrganizationMember(ctx, org.Invitation{ID: id, InviterID: actor.UserID, OrganizationID: group.ID, Email: id + "@example.test", Status: "pending", Role: "member", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, actor.ID, false)
				if err == nil && (grant.CreatedAt.Before(releasedAt) || !grant.ExpiresAt.Equal(grant.CreatedAt.Add(time.Hour))) {
					return errors.New("time spent resolving the quota consumed the invitation lifetime")
				}
				return err
			}
			results := make(chan error, 2)
			go func() { results <- issue(one, owner, "one") }()
			go func() { results <- issue(two, admin, "two") }()
			for range 2 {
				select {
				case <-entered:
				case err := <-results:
					t.Fatalf("issuer finished before the resolver was released: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			releasedAt = time.Now().UTC().Truncate(time.Millisecond)
			close(proceed)
			first, second := <-results, <-results
			if !((first == nil && errors.Is(second, org.ErrInvitationLimit)) || (second == nil && errors.Is(first, org.ErrInvitationLimit))) {
				t.Fatalf("competing issuers did not share the last invitation slot: %v / %v", first, second)
			}

			zero, err := store.WithOrganizationInvitationLimit(org.InvitationLimit{Maximum: 0})
			must(err)
			var originalID, email string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "id","email" FROM "invitation" WHERE "organizationId"=? AND "status"='pending'`), group.ID).Scan(&originalID, &email))
			inv := org.Invitation{ID: "replacement", OrganizationID: group.ID, InviterID: owner.UserID, Email: email, Role: "member", Status: "pending", CreatedAt: group.CreatedAt, ExpiresAt: group.CreatedAt.Add(time.Hour)}
			_, err = zero.(org.InvitationReplacementStore).ReplaceOrganizationInvitation(ctx, inv, owner.ID)
			if !errors.Is(err, org.ErrInvitationLimit) {
				t.Fatal("replacement bypassed the new quota", err)
			}
			var status string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "status" FROM "invitation" WHERE "id"=?`), originalID).Scan(&status))
			if status != "pending" {
				t.Fatal("denied replacement did not restore the prior grant")
			}

			for _, tc := range []struct {
				change string
				want   error
			}{
				{"denied", org.ErrInvitationLimit}, {"rename", org.ErrInvitationLimitChanged}, {"membership", org.ErrInvitationLimitChanged}, {"demote", org.ErrInviteDenied}, {"revoked", org.ErrUnauthenticated},
			} {
				t.Run(tc.change, func(t *testing.T) {
					calls := 0
					scoped, err := store.WithOrganizationInvitationLimit(org.InvitationLimit{Resolve: func(ctx context.Context, in org.InvitationLimitInput) (int, error) {
						calls++
						switch tc.change {
						case "denied":
							return 0, nil
						case "rename":
							_, err := peer.db.ExecContext(ctx, peer.bind(`UPDATE "organization" SET "name"=? WHERE "id"=?`), "renamed", group.ID)
							return 5, err
						case "membership":
							_, err := peer.db.ExecContext(ctx, peer.bind(`UPDATE "member" SET "id"=? WHERE "id"=?`), "replacement", in.Member.ID)
							return 5, err
						case "demote":
							_, err := peer.db.ExecContext(ctx, peer.bind(`UPDATE "member" SET "role"='member' WHERE "id"=?`), in.Member.ID)
							return 5, err
						default:
							_, err := peer.db.ExecContext(ctx, peer.bind(`DELETE FROM "session" WHERE "id"=?`), owner.ID)
							return 5, err
						}
					}})
					must(err)
					actor := admin
					if tc.change == "revoked" {
						actor = owner
					}
					err = issue(scoped, actor, tc.change)
					if !errors.Is(err, tc.want) || calls != 1 {
						t.Fatalf("changed quota inputs produced %v, calls=%d", err, calls)
					}
				})
			}
			var n int
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "invitation" WHERE "organizationId"=?`), group.ID).Scan(&n))
			if n != 1 {
				t.Fatal("quota failure persisted an invitation", n)
			}
		})
	}
}
