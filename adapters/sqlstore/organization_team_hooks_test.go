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

// Run the team create, update and delete hooks over HTTP and from trusted
// server code.
func TestOrganizationTeamHooks(t *testing.T) {
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
			ada, max := account("Ada"), account("Max")
			group := org.Organization{ID: "Acme", Name: "Acme", Slug: "acme", CreatedAt: now}
			must(store.CreateOrganization(ctx, group, org.Member{ID: "ada-m", UserID: ada.UserID, OrganizationID: group.ID, Role: "owner", CreatedAt: now}, ada.ID, true))
			must(store.AddOrganizationMember(ctx, org.Member{ID: "max-m", UserID: max.UserID, OrganizationID: group.ID, Role: "member", CreatedAt: now}, ""))

			var mu sync.Mutex
			var events []string
			describe := func(kind string, in org.TeamChange) string {
				user := "server"
				if in.User != nil {
					user = in.User.Email
				}
				return kind + ":" + in.Team.ID + ":" + in.Team.Name + ":" + user + ":" + in.Organization.Slug
			}
			record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
			seen := func() string { mu.Lock(); defer mu.Unlock(); s := strings.Join(events, ","); events = nil; return s }
			var override *org.TeamOverride
			var beforeErr error
			service, err := org.NewService(org.Options{
				Store: store, Teams: &org.TeamOptions{},
				BeforeCreateTeam: func(_ context.Context, in org.TeamChange) (*org.TeamOverride, error) {
					record(describe("before-create", in))
					return override, beforeErr
				},
				AfterCreateTeam: func(_ context.Context, in org.TeamChange) error { record(describe("after-create", in)); return nil },
				BeforeUpdateTeam: func(_ context.Context, in org.BeforeTeamUpdate) (*org.TeamOverride, error) {
					record(describe("before-update", in.TeamChange) + "->" + *in.Updates.Name)
					return override, beforeErr
				},
				AfterUpdateTeam: func(_ context.Context, in org.TeamChange) error { record(describe("after-update", in)); return nil },
				BeforeDeleteTeam: func(_ context.Context, in org.TeamChange) error {
					record(describe("before-delete", in))
					return beforeErr
				},
				AfterDeleteTeam: func(_ context.Context, in org.TeamChange) error { record(describe("after-delete", in)); return nil },
			})
			must(err)
			adaHTTP := organizationRoleClient(t, store, service, ada)

			// Creation hooks see the proposed team and the creator, and can rename it.
			name := "Design"
			override = &org.TeamOverride{Name: &name}
			design, err := adaHTTP.CreateTeam(ctx, "Draft", group.ID)
			must(err)
			if got := seen(); got != "before-create::Draft:ada@example.test:acme,after-create:"+design.ID+":Design:ada@example.test:acme" || design.Name != "Design" {
				t.Fatal("unexpected creation hooks", got, design)
			}
			override = nil
			support, err := service.CreateTeam(ctx, org.CreateTeamRequest{OrganizationID: group.ID, Name: "Support"})
			must(err)
			if got := seen(); got != "before-create::Support:server:acme,after-create:"+support.ID+":Support:server:acme" {
				t.Fatal("unexpected trusted creation hooks", got)
			}

			// Update hooks see the current team and the requested name.
			name = "Product Design"
			override = &org.TeamOverride{Name: &name}
			updated, err := adaHTTP.UpdateTeam(ctx, design.ID, "Design Ops", group.ID)
			must(err)
			if got := seen(); got != "before-update:"+design.ID+":Design:ada@example.test:acme->Design Ops,after-update:"+design.ID+":Product Design:ada@example.test:acme" || updated.Name != "Product Design" {
				t.Fatal("unexpected update hooks", got, updated)
			}
			override = nil

			// Refused changes never reach the hooks.
			maxHTTP := organizationRoleClient(t, store, service, max)
			_, err = maxHTTP.CreateTeam(ctx, "Rogue", group.ID)
			code(err, 403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION")
			_, err = maxHTTP.UpdateTeam(ctx, design.ID, "Rogue", group.ID)
			code(err, 403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM")
			code(maxHTTP.RemoveTeam(ctx, design.ID, group.ID), 403, "YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION")
			code(adaHTTP.RemoveTeam(ctx, "missing", group.ID), 400, "TEAM_NOT_FOUND")
			if got := seen(); got != "" {
				t.Fatal("a refused team change reached the hooks", got)
			}

			// A before-hook error cancels creation, update and removal.
			beforeErr = errors.New("change freeze")
			_, createErr := adaHTTP.CreateTeam(ctx, "Frozen", group.ID)
			_, updateErr := adaHTTP.UpdateTeam(ctx, design.ID, "Frozen", group.ID)
			deleteErr := adaHTTP.RemoveTeam(ctx, support.ID, group.ID)
			beforeErr = nil
			if createErr == nil || updateErr == nil || deleteErr == nil || len(strings.Split(seen(), ",")) != 3 {
				t.Fatal("a failing before hook did not cancel the change", createErr, updateErr, deleteErr)
			}
			if count(`SELECT COUNT(*) FROM "team" WHERE "organizationId"=?`, group.ID) != 2 || count(`SELECT COUNT(*) FROM "team" WHERE "name"='Frozen'`) != 0 {
				t.Fatal("a cancelled team change was saved")
			}

			// Removal hooks see the team being removed.
			must(adaHTTP.RemoveTeam(ctx, support.ID, group.ID))
			if got := seen(); got != "before-delete:"+support.ID+":Support:ada@example.test:acme,after-delete:"+support.ID+":Support:ada@example.test:acme" {
				t.Fatal("unexpected removal hooks", got)
			}
			code(adaHTTP.RemoveTeam(ctx, design.ID, group.ID), 400, "UNABLE_TO_REMOVE_LAST_TEAM")
			if got := seen(); got != "" {
				t.Fatal("removing the final team reached the hooks", got)
			}
			if _, err := org.NewService(org.Options{Store: store, AfterCreateTeam: func(context.Context, org.TeamChange) error { return nil }}); err == nil {
				t.Fatal("accepted team hooks without teams")
			}
		})
	}
}
