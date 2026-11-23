package sqlstore

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

// Run the member removal hooks around POST /organization/remove-member.
func TestOrganizationMemberRemovalHooks(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			code := func(err error, status int, want string) {
				t.Helper()
				var problem *auth.APIError
				if !errors.As(err, &problem) || problem.Status != status || problem.Code != want {
					t.Fatalf("want %d %s, got %v", status, want, err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			store, err := OpenWithOptions(ctx, dialect, dsn, []string{"organization"}, schema.Options{})
			must(err)
			t.Cleanup(func() { store.Close() })
			peer, err := Open(ctx, dialect, dsn)
			must(err)
			t.Cleanup(func() { peer.Close() })
			count := func(q string, args ...any) int {
				t.Helper()
				var n int
				must(store.db.QueryRowContext(ctx, store.bind(q), args...).Scan(&n))
				return n
			}
			now := time.Now().UTC().Truncate(time.Millisecond)
			account := func(id string) auth.Session {
				t.Helper()
				user := auth.User{ID: id, Name: id, Email: id + "@example.test", CreatedAt: now, UpdatedAt: now}
				session := auth.StoredSession{Session: auth.Session{ID: id + "-s", Token: id + "-t", UserID: id, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
				must(store.CreateUser(ctx, user, "", &session))
				return session.Session
			}
			ada, lin, max, sam := account("Ada"), account("Lin"), account("Max"), account("Sam")
			group := org.Organization{ID: "Acme", Name: "Acme", Slug: "acme", CreatedAt: now}
			must(store.CreateOrganization(ctx, group, org.Member{ID: "ada-m", UserID: ada.UserID, OrganizationID: group.ID, Role: "owner", CreatedAt: now}, ada.ID, false))
			for _, m := range []org.Member{{ID: "lin-m", UserID: lin.UserID, Role: "admin"}, {ID: "max-m", UserID: max.UserID, Role: "member"}, {ID: "sam-m", UserID: sam.UserID, Role: "member"}} {
				m.OrganizationID, m.CreatedAt = group.ID, now
				must(store.AddOrganizationMember(ctx, m, ""))
			}
			var mu sync.Mutex
			var events []string
			record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
			seen := func() string { mu.Lock(); defer mu.Unlock(); s := strings.Join(events, ","); events = nil; return s }
			var beforeErr, afterErr error
			var duringBefore func() error
			service, err := org.NewService(org.Options{
				Store: store,
				BeforeRemoveMember: func(_ context.Context, in org.MemberRemoval) error {
					record("before:" + in.Member.ID + ":" + in.Member.Role + ":" + in.User.Email + ":" + in.Organization.Slug)
					if duringBefore != nil {
						if err := duringBefore(); err != nil {
							return err
						}
					}
					return beforeErr
				},
				AfterRemoveMember: func(_ context.Context, in org.MemberRemoval) error {
					record("after:" + in.Member.ID + ":" + in.User.ID)
					return afterErr
				},
			})
			must(err)
			adaHTTP, linHTTP := organizationRoleClient(t, store, service, ada), organizationRoleClient(t, store, service, lin)

			// Both hooks see the member, their account and the organization.
			removed, err := adaHTTP.RemoveOrganizationMember(ctx, "max-m", group.ID)
			must(err)
			if got := seen(); got != "before:max-m:member:max@example.test:acme,after:max-m:Max" || removed.ID != "max-m" || removed.User != nil {
				t.Fatal("unexpected removal hooks or result", got, removed)
			}
			if count(`SELECT COUNT(*) FROM "member" WHERE "id"='max-m'`) != 0 {
				t.Fatal("the member was not removed")
			}

			// A before-hook error cancels the removal.
			beforeErr = errors.New("transfer the member's projects first")
			if _, err = adaHTTP.RemoveOrganizationMember(ctx, "sam@example.test", group.ID); err == nil {
				t.Fatal("the before hook did not cancel the removal")
			}
			beforeErr = nil
			if seen() != "before:sam-m:member:sam@example.test:acme" || count(`SELECT COUNT(*) FROM "member" WHERE "id"='sam-m'`) != 1 {
				t.Fatal("a cancelled removal changed the membership")
			}

			// Refused removals never reach the hooks.
			_, err = organizationRoleClient(t, store, service, sam).RemoveOrganizationMember(ctx, "lin-m", group.ID)
			code(err, 401, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER")
			_, err = linHTTP.RemoveOrganizationMember(ctx, "ada-m", group.ID)
			code(err, 400, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER")
			_, err = adaHTTP.RemoveOrganizationMember(ctx, "missing-m", group.ID)
			code(err, 400, "MEMBER_NOT_FOUND")
			if got := seen(); got != "" {
				t.Fatal("a refused removal reached the hooks", got)
			}

			// The removal rechecks the caller's permission after the before hook.
			duringBefore = func() error {
				_, err := peer.db.ExecContext(ctx, peer.bind(`UPDATE "member" SET "role"='member' WHERE "id"='lin-m'`))
				return err
			}
			_, err = linHTTP.RemoveOrganizationMember(ctx, "sam-m", group.ID)
			code(err, 401, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER")
			duringBefore = nil
			seen()
			if count(`SELECT COUNT(*) FROM "member" WHERE "id"='sam-m'`) != 1 {
				t.Fatal("a demoted caller removed the member")
			}

			// Removal by email returns the account, and an after-hook error keeps the removal.
			afterErr = errors.New("audit sink unavailable")
			if _, err = adaHTTP.RemoveOrganizationMember(ctx, "sam@example.test", group.ID); err == nil {
				t.Fatal("lost the after-hook error")
			}
			afterErr = nil
			if seen() != "before:sam-m:member:sam@example.test:acme,after:sam-m:Sam" || count(`SELECT COUNT(*) FROM "member" WHERE "id"='sam-m'`) != 0 {
				t.Fatal("an after-hook error restored the member")
			}
			must(store.AddOrganizationMember(ctx, org.Member{ID: "sam-2", UserID: sam.UserID, OrganizationID: group.ID, Role: "member", CreatedAt: now}, ""))
			removed, err = adaHTTP.RemoveOrganizationMember(ctx, "SAM@example.test", group.ID)
			must(err)
			if removed.ID != "sam-2" || removed.User == nil || removed.User.Email != "sam@example.test" {
				t.Fatal("removal by email lost the account", removed)
			}
			seen()
		})
	}
}
