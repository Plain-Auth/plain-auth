package sqlstore

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

// Run the member addition hooks for an organization's creator and for
// trusted grants, and skip them for grants that cannot proceed.
func TestOrganizationMemberAdditionHooks(t *testing.T) {
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
			store, err := OpenWithOptions(ctx, dialect, dsn, []string{"organization-teams"}, schema.Options{})
			must(err)
			t.Cleanup(func() { store.Close() })
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
			ada, lin, max := account("Ada"), account("Lin"), account("Max")

			var mu sync.Mutex
			var events []string
			record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
			seen := func() string { mu.Lock(); defer mu.Unlock(); return strings.Join(events, ",") }
			reset := func() { mu.Lock(); events = nil; mu.Unlock() }
			var override *org.MemberOverride
			var beforeErr error
			options := org.Options{
				Store: store, Teams: &org.TeamOptions{}, MembershipLimit: org.MembershipLimit{Maximum: 3},
				BeforeAddMember: func(_ context.Context, in org.BeforeMemberAddition) (*org.MemberOverride, error) {
					record("before-add:" + in.Member.UserID + ":" + in.Member.Role + ":" + in.User.Email + ":" + in.Organization.Slug)
					if in.Member.OrganizationID != in.Organization.ID {
						return nil, errors.New("member and organization disagree")
					}
					return override, beforeErr
				},
				AfterAddMember: func(_ context.Context, in org.AfterMemberAddition) error {
					record("after-add:" + in.Member.UserID + ":" + in.Member.Role)
					return nil
				},
				AfterCreateOrganization: func(_ context.Context, in org.AfterOrganizationCreation) error {
					record("after-create:" + in.Member.Role)
					return nil
				},
			}
			service, err := org.NewService(options)
			must(err)

			// The creator's membership runs both hooks, and its override is saved.
			override = &org.MemberOverride{Roles: []string{"owner", "billing"}}
			created, err := organizationRoleClient(t, store, service, ada).CreateOrganization(ctx, client.CreateOrganizationRequest{Name: "Acme", Slug: "acme"})
			must(err)
			if got := seen(); got != "before-add:Ada:owner:ada@example.test:acme,after-add:Ada:owner,billing,after-create:owner,billing" {
				t.Fatal("unexpected creation hook order or input", got)
			}
			if created.Members[0].Role != "owner,billing" || count(`SELECT COUNT(*) FROM "member" WHERE "userId"=? AND "role"='owner,billing'`, ada.UserID) != 1 {
				t.Fatal("the creator's override was not saved", created.Members)
			}

			// A trusted grant runs the hooks with the member's profile and organization.
			reset()
			override = &org.MemberOverride{Roles: []string{"admin"}}
			member, err := service.AddMember(ctx, org.AddMemberRequest{OrganizationID: created.ID, UserID: lin.UserID, Roles: []string{"member"}})
			must(err)
			if got := seen(); got != "before-add:Lin:member:lin@example.test:acme,after-add:Lin:admin" || member.Role != "admin" {
				t.Fatal("unexpected trusted grant hooks", got, member.Role)
			}
			if count(`SELECT COUNT(*) FROM "member" WHERE "userId"=? AND "role"='admin'`, lin.UserID) != 1 {
				t.Fatal("the trusted override was not saved")
			}

			// Grants that cannot proceed never reach the hooks.
			reset()
			_, err = service.AddMember(ctx, org.AddMemberRequest{OrganizationID: created.ID, UserID: lin.UserID, Roles: []string{"member"}})
			code(err, 400, "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION")
			_, err = service.AddMember(ctx, org.AddMemberRequest{OrganizationID: created.ID, UserID: "missing", Roles: []string{"member"}})
			code(err, 400, "USER_NOT_FOUND")
			_, err = service.AddMember(ctx, org.AddMemberRequest{OrganizationID: "missing", UserID: max.UserID, Roles: []string{"member"}})
			code(err, 400, "ORGANIZATION_NOT_FOUND")
			_, err = service.AddMember(ctx, org.AddMemberRequest{OrganizationID: created.ID, UserID: max.UserID, Roles: []string{"member"}, TeamID: "missing"})
			code(err, 400, "TEAM_NOT_FOUND")
			if got := seen(); got != "" {
				t.Fatal("a refused grant reached the hooks", got)
			}

			// A before-hook error cancels the grant.
			override, beforeErr = nil, errors.New("seat purchase required")
			if _, err = service.AddMember(ctx, org.AddMemberRequest{OrganizationID: created.ID, UserID: max.UserID, Roles: []string{"member"}}); !errors.Is(err, beforeErr) {
				t.Fatal("lost the before-hook error", err)
			}
			beforeErr = nil
			if count(`SELECT COUNT(*) FROM "member" WHERE "userId"=?`, max.UserID) != 0 {
				t.Fatal("a cancelled grant stored the membership")
			}

			// A full organization is refused before the hooks run.
			_, err = service.AddMember(ctx, org.AddMemberRequest{OrganizationID: created.ID, UserID: max.UserID, Roles: []string{"member"}})
			must(err)
			extra := account("Extra")
			reset()
			_, err = service.AddMember(ctx, org.AddMemberRequest{OrganizationID: created.ID, UserID: extra.UserID, Roles: []string{"member"}})
			code(err, 403, "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED")
			if got := seen(); got != "" {
				t.Fatal("a full organization reached the hooks", got)
			}
		})
	}
}
