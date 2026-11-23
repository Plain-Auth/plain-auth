package sqlstore

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/schema"
)

// Run the team membership hooks around add-team-member and remove-team-member.
func TestOrganizationTeamMemberHooks(t *testing.T) {
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
			ada, lin, max, outsider := account("Ada"), account("Lin"), account("Max"), account("Outsider")
			group := org.Organization{ID: "Acme", Name: "Acme", Slug: "acme", CreatedAt: now}
			must(store.CreateOrganization(ctx, group, org.Member{ID: "ada-m", UserID: ada.UserID, OrganizationID: group.ID, Role: "owner", CreatedAt: now}, ada.ID, true))
			for _, s := range []auth.Session{lin, max} {
				must(store.AddOrganizationMember(ctx, org.Member{ID: s.UserID + "-m", UserID: s.UserID, OrganizationID: group.ID, Role: "member", CreatedAt: now}, ""))
			}
			var mu sync.Mutex
			var events []string
			describe := func(kind string, in org.TeamMembershipChange) string {
				return kind + ":" + in.Member.UserID + ":" + in.User.Email + ":" + in.Team.Name + ":" + in.Organization.Slug
			}
			record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
			seen := func() string { mu.Lock(); defer mu.Unlock(); s := strings.Join(events, ","); events = nil; return s }
			var beforeErr error
			one := 1
			service, err := org.NewService(org.Options{
				Store: store, Teams: &org.TeamOptions{MaximumMembersPerTeam: &one},
				BeforeAddTeamMember: func(_ context.Context, in org.TeamMembershipChange) error {
					record(describe("before-add", in))
					return beforeErr
				},
				AfterAddTeamMember: func(_ context.Context, in org.TeamMembershipChange) error {
					record(describe("after-add", in) + ":" + in.Member.ID)
					return nil
				},
				BeforeRemoveTeamMember: func(_ context.Context, in org.TeamMembershipChange) error {
					record(describe("before-remove", in))
					return beforeErr
				},
				AfterRemoveTeamMember: func(_ context.Context, in org.TeamMembershipChange) error {
					record(describe("after-remove", in))
					return nil
				},
			})
			must(err)
			design, err := service.Store().(org.TeamStore).CreateTeam(ctx, org.TeamActor{UserID: ada.UserID, SessionID: ada.ID}, group.ID, "Design")
			must(err)
			adaHTTP := organizationRoleClient(t, store, service, ada)
			add := func(sdk *client.Client, user string) (*org.TeamMember, error) {
				return sdk.AddTeamMember(ctx, client.TeamMembershipRequest{OrganizationID: group.ID, TeamID: design.ID, UserID: user})
			}
			remove := func(sdk *client.Client, user string) error {
				return sdk.RemoveTeamMember(ctx, client.TeamMembershipRequest{OrganizationID: group.ID, TeamID: design.ID, UserID: user})
			}

			// Both add hooks see the membership, the member's account, the team and the organization.
			joined, err := add(adaHTTP, lin.UserID)
			must(err)
			if got := seen(); got != "before-add:Lin:lin@example.test:Design:acme,after-add:Lin:lin@example.test:Design:acme:"+joined.ID {
				t.Fatal("unexpected add hooks", got)
			}
			// Repeating the add returns the membership without the hooks.
			again, err := add(adaHTTP, lin.UserID)
			must(err)
			if again.ID != joined.ID || seen() != "" {
				t.Fatal("a repeated add ran the hooks")
			}
			// The team member limit is checked after the before hook.
			_, err = add(adaHTTP, max.UserID)
			code(err, 403, "TEAM_MEMBER_LIMIT_REACHED")
			if got := seen(); got != "before-add:Max:max@example.test:Design:acme" {
				t.Fatal("the full team skipped the before hook or ran the after hook", got)
			}

			// Refused changes never reach the hooks.
			_, err = add(adaHTTP, outsider.UserID)
			code(err, 400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
			_, err = add(organizationRoleClient(t, store, service, max), max.UserID)
			code(err, 403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER")
			code(remove(adaHTTP, max.UserID), 400, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM")
			if got := seen(); got != "" {
				t.Fatal("a refused team change reached the hooks", got)
			}

			// A before-hook error cancels the removal.
			beforeErr = errors.New("reassign the member's tickets first")
			if err = remove(adaHTTP, lin.UserID); err == nil {
				t.Fatal("the before hook did not cancel the removal")
			}
			beforeErr = nil
			if seen() != "before-remove:Lin:lin@example.test:Design:acme" || count(`SELECT COUNT(*) FROM "teamMember" WHERE "teamId"=?`, design.ID) != 1 {
				t.Fatal("a cancelled removal changed the team")
			}
			must(remove(adaHTTP, lin.UserID))
			if got := seen(); got != "before-remove:Lin:lin@example.test:Design:acme,after-remove:Lin:lin@example.test:Design:acme" {
				t.Fatal("unexpected removal hooks", got)
			}
			if count(`SELECT COUNT(*) FROM "teamMember" WHERE "teamId"=?`, design.ID) != 0 {
				t.Fatal("the member was not removed")
			}
		})
	}
}
