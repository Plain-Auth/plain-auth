package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/schema"
)

// Resolve an empty team organization to the session's selection, ignore
// client timestamps, and remove teams from trusted server code.
func TestOrganizationTeamScopeAndTrustedRemoval(t *testing.T) {
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
			ada, lin := account("Ada"), account("Lin")
			group := org.Organization{ID: "Acme", Name: "Acme", Slug: "acme", CreatedAt: now}
			must(store.CreateOrganization(ctx, group, org.Member{ID: "ada-m", UserID: ada.UserID, OrganizationID: group.ID, Role: "owner", CreatedAt: now}, ada.ID, false))
			must(store.AddOrganizationMember(ctx, org.Member{ID: "lin-m", UserID: lin.UserID, OrganizationID: group.ID, Role: "member", CreatedAt: now}, ""))
			var removed []string
			service, err := org.NewService(org.Options{
				Store: store, Teams: &org.TeamOptions{},
				BeforeDeleteTeam: func(_ context.Context, in org.TeamChange) error {
					if in.User != nil {
						removed = append(removed, "before:"+in.Team.Name+":"+in.User.ID)
					} else {
						removed = append(removed, "before:"+in.Team.Name+":server")
					}
					return nil
				},
			})
			must(err)
			teams := service.Store().(org.TeamStore)
			actor := org.TeamActor{UserID: ada.UserID, SessionID: ada.ID}
			design, err := teams.CreateTeam(ctx, actor, group.ID, "Design")
			must(err)
			support, err := teams.CreateTeam(ctx, actor, group.ID, "Support")
			must(err)
			ops, err := teams.CreateTeam(ctx, actor, group.ID, "Ops")
			must(err)
			_, err = teams.AddTeamMember(ctx, actor, group.ID, support.ID, lin.UserID)
			must(err)
			adaHTTP := organizationRoleClient(t, store, service, ada)

			// An empty organizationId selects the session's active organization.
			var updated org.Team
			must(adaHTTP.Do(ctx, http.MethodPost, "/organization/update-team", map[string]any{
				"teamId": design.ID, "data": map[string]any{"name": "Product", "organizationId": "", "createdAt": "2001-01-01T00:00:00Z", "updatedAt": "2001-01-01T00:00:00Z"},
			}, &updated))
			// Client-supplied timestamps are ignored.
			if updated.Name != "Product" || !updated.CreatedAt.Equal(design.CreatedAt) || updated.UpdatedAt == nil || updated.UpdatedAt.Year() < 2026 {
				t.Fatal("unexpected team update", updated)
			}
			must(adaHTTP.Do(ctx, http.MethodPost, "/organization/remove-team", map[string]any{"teamId": ops.ID, "organizationId": ""}, nil))
			if count(`SELECT COUNT(*) FROM "team" WHERE "id"=?`, ops.ID) != 0 || strings.Join(removed, ",") != "before:Ops:Ada" {
				t.Fatal("an empty organizationId did not use the active organization", removed)
			}

			// Listing another member's teams without organizationId uses the active organization.
			listed, err := adaHTTP.ListUserTeams(ctx, "", lin.UserID)
			must(err)
			if len(listed) != 1 || listed[0].ID != support.ID {
				t.Fatal("unexpected teams for another member", listed)
			}

			// Trusted removal needs no session but keeps the final-team rule.
			removed = nil
			_, err = store.db.ExecContext(ctx, store.bind(`UPDATE "session" SET "activeTeamId"=? WHERE "id"=?`), support.ID, lin.ID)
			must(err)
			must(service.RemoveTeam(ctx, org.RemoveTeamRequest{OrganizationID: group.ID, TeamID: support.ID}))
			if strings.Join(removed, ",") != "before:Support:server" || count(`SELECT COUNT(*) FROM "teamMember" WHERE "teamId"=?`, support.ID) != 0 ||
				count(`SELECT COUNT(*) FROM "session" WHERE "activeTeamId"=?`, support.ID) != 0 {
				t.Fatal("trusted removal left memberships, selections or skipped the hook", removed)
			}
			code(service.RemoveTeam(ctx, org.RemoveTeamRequest{OrganizationID: group.ID, TeamID: design.ID}), 400, "UNABLE_TO_REMOVE_LAST_TEAM")
			code(service.RemoveTeam(ctx, org.RemoveTeamRequest{OrganizationID: group.ID, TeamID: "missing"}), 400, "TEAM_NOT_FOUND")
			code(service.RemoveTeam(ctx, org.RemoveTeamRequest{TeamID: design.ID}), 400, "NO_ACTIVE_ORGANIZATION")
			code(service.RemoveTeam(ctx, org.RemoveTeamRequest{OrganizationID: "missing", TeamID: design.ID}), 400, "ORGANIZATION_NOT_FOUND")
			code(service.RemoveTeam(ctx, org.RemoveTeamRequest{OrganizationID: group.ID}), 400, "VALIDATION_ERROR")
		})
	}
}
