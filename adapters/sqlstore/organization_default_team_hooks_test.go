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

// Run the team creation hooks for the default team created with an organization.
func TestOrganizationDefaultTeamHooks(t *testing.T) {
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
			ada, grace := account("Ada"), account("Grace")
			var mu sync.Mutex
			var events []string
			record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
			seen := func() string { mu.Lock(); defer mu.Unlock(); s := strings.Join(events, ","); events = nil; return s }
			var beforeErr error
			options := func(disable bool) org.Options {
				return org.Options{
					Store: store, Teams: &org.TeamOptions{DisableDefaultTeam: disable},
					BeforeCreateTeam: func(_ context.Context, in org.TeamChange) (*org.TeamOverride, error) {
						record("before-team:" + in.Team.ID + ":" + in.Team.Name + ":" + in.User.ID + ":" + in.Organization.Slug)
						name := in.Team.Name + " HQ"
						return &org.TeamOverride{Name: &name}, beforeErr
					},
					AfterCreateTeam: func(_ context.Context, in org.TeamChange) error {
						record("after-team:" + in.Team.Name + ":" + in.User.ID)
						return nil
					},
					AfterAddMember:          func(_ context.Context, in org.AfterMemberAddition) error { record("after-member"); return nil },
					AfterCreateOrganization: func(context.Context, org.AfterOrganizationCreation) error { record("after-organization"); return nil },
				}
			}
			service, err := org.NewService(options(false))
			must(err)

			// The default team runs the team hooks between the member and organization hooks.
			created, err := organizationRoleClient(t, store, service, ada).CreateOrganization(ctx, client.CreateOrganizationRequest{Name: "Acme", Slug: "acme"})
			must(err)
			if got := seen(); got != "before-team::Acme:Ada:acme,after-member,after-team:Acme HQ:Ada,after-organization" {
				t.Fatal("unexpected default team hooks", got)
			}
			var teamID string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "id" FROM "team" WHERE "organizationId"=? AND "name"='Acme HQ'`), created.ID).Scan(&teamID))
			if count(`SELECT COUNT(*) FROM "teamMember" WHERE "teamId"=? AND "userId"=?`, teamID, ada.UserID) != 1 ||
				count(`SELECT COUNT(*) FROM "session" WHERE "id"=? AND "activeTeamId"=?`, ada.ID, teamID) != 1 {
				t.Fatal("the renamed default team was not joined and selected")
			}

			// Trusted creation runs the same hooks for the named user.
			_, err = service.CreateOrganization(ctx, org.CreateOrganizationRequest{UserID: grace.UserID, Name: "Server", Slug: "server"})
			must(err)
			if got := seen(); got != "before-team::Server:Grace:server,after-member,after-team:Server HQ:Grace,after-organization" {
				t.Fatal("unexpected trusted default team hooks", got)
			}

			// A failing default team hook stores no organization.
			beforeErr = errors.New("team naming service unavailable")
			if _, err = service.CreateOrganization(ctx, org.CreateOrganizationRequest{UserID: grace.UserID, Name: "Failed", Slug: "failed"}); !errors.Is(err, beforeErr) {
				t.Fatal("lost the default team hook error", err)
			}
			beforeErr = nil
			seen()
			if count(`SELECT COUNT(*) FROM "organization" WHERE "slug"='failed'`) != 0 {
				t.Fatal("a cancelled default team left its organization")
			}

			// Without a default team the team hooks do not run during creation.
			bare, err := org.NewService(options(true))
			must(err)
			_, err = bare.CreateOrganization(ctx, org.CreateOrganizationRequest{UserID: grace.UserID, Name: "Bare", Slug: "bare"})
			must(err)
			if got := seen(); got != "after-member,after-organization" {
				t.Fatal("a disabled default team ran the team hooks", got)
			}
		})
	}
}
