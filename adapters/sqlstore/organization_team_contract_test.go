package sqlstore

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/access"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

// Check each team permission on its own with custom roles, and select, list,
// join and leave teams by explicit ID over HTTP.
func TestOrganizationTeamContract(t *testing.T) {
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
			now := time.Now().UTC().Truncate(time.Millisecond)
			account := func(id string) auth.Session {
				t.Helper()
				user := auth.User{ID: id, Name: id, Email: id + "@example.test", CreatedAt: now, UpdatedAt: now}
				session := auth.StoredSession{Session: auth.Session{ID: id + "-s", Token: id + "-t", UserID: id, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
				must(store.CreateUser(ctx, user, "", &session))
				return session.Session
			}
			roles := org.DefaultRoles()
			roles["builder"] = access.Statements{"team": {"create"}}
			roles["editor"] = access.Statements{"team": {"update"}}
			roles["remover"] = access.Statements{"team": {"delete"}}
			service, err := org.NewService(org.Options{Store: store, Roles: roles, Teams: &org.TeamOptions{}})
			must(err)
			ada := account("Ada")
			acme := org.Organization{ID: "Acme", Name: "Acme", Slug: "acme", CreatedAt: now}
			other := org.Organization{ID: "Other", Name: "Other", Slug: "other", CreatedAt: now}
			for _, group := range []org.Organization{acme, other} {
				must(service.Store().CreateOrganization(ctx, group, org.Member{ID: group.ID + "-ada", UserID: ada.UserID, OrganizationID: group.ID, Role: "owner", CreatedAt: now}, ada.ID, false))
			}
			member := func(id, role string) *client.Client {
				t.Helper()
				s := account(id)
				must(store.AddOrganizationMember(ctx, org.Member{ID: id + "-m", UserID: s.UserID, OrganizationID: acme.ID, Role: role, CreatedAt: now}, ""))
				_, err := store.db.ExecContext(ctx, store.bind(`UPDATE "session" SET "activeOrganizationId"=? WHERE "id"=?`), acme.ID, s.ID)
				must(err)
				return organizationRoleClient(t, store, service, s)
			}
			builder, editor, remover := member("Builder", "builder"), member("Editor", "editor"), member("Remover", "remover")
			adaHTTP := organizationRoleClient(t, store, service, ada)
			teams := service.Store().(org.TeamStore)
			ownerActor := org.TeamActor{UserID: ada.UserID, SessionID: ada.ID}
			design, err := teams.CreateTeam(ctx, ownerActor, acme.ID, "Design")
			must(err)
			support, err := teams.CreateTeam(ctx, ownerActor, acme.ID, "Support")
			must(err)
			outside, err := teams.CreateTeam(ctx, ownerActor, other.ID, "Outside")
			must(err)

			// team:create alone permits creation and nothing else.
			built, err := builder.CreateTeam(ctx, "Built", acme.ID)
			must(err)
			_, err = builder.UpdateTeam(ctx, built.ID, "Renamed", acme.ID)
			code(err, 403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM")
			code(builder.RemoveTeam(ctx, built.ID, acme.ID), 403, "YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION")
			// team:update alone permits renaming and nothing else.
			_, err = editor.CreateTeam(ctx, "Denied", acme.ID)
			code(err, 403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION")
			renamed, err := editor.UpdateTeam(ctx, built.ID, "Renamed", acme.ID)
			must(err)
			code(editor.RemoveTeam(ctx, built.ID, acme.ID), 403, "YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION")
			// team:delete alone permits removal and nothing else.
			_, err = remover.CreateTeam(ctx, "Denied", acme.ID)
			code(err, 403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION")
			_, err = remover.UpdateTeam(ctx, built.ID, "Denied", acme.ID)
			code(err, 403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM")
			must(remover.RemoveTeam(ctx, renamed.ID, acme.ID))

			// An explicit organizationId lists that organization's teams.
			listed, err := adaHTTP.ListOrganizationTeams(ctx, other.ID)
			must(err)
			found := false
			for _, team := range listed {
				if team.OrganizationID != other.ID {
					t.Fatal("list-teams returned another organization's team", team)
				}
				found = found || team.ID == outside.ID
			}
			if !found {
				t.Fatal("list-teams ignored the explicit organization", listed)
			}

			// add-team-member adds the named user to the named team.
			for _, id := range []string{"Builder", "Editor"} {
				joined, err := adaHTTP.AddTeamMember(ctx, client.TeamMembershipRequest{OrganizationID: acme.ID, TeamID: design.ID, UserID: id})
				must(err)
				if joined.TeamID != design.ID || joined.UserID != id {
					t.Fatal("unexpected team membership", joined)
				}
			}
			_, err = adaHTTP.AddTeamMember(ctx, client.TeamMembershipRequest{OrganizationID: acme.ID, TeamID: support.ID, UserID: "Remover"})
			must(err)

			// set-active-team selects a team by ID, and list-team-members reads an explicit team.
			selected, err := builder.SetActiveTeam(ctx, &design.ID)
			must(err)
			var active *string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "activeTeamId" FROM "session" WHERE "id"='Builder-s'`)).Scan(&active))
			if selected == nil || selected.ID != design.ID || active == nil || *active != design.ID {
				t.Fatal("set-active-team did not select the team", selected, active)
			}
			members, err := builder.ListTeamMembers(ctx, "")
			must(err)
			ids := []string{}
			for _, m := range members {
				ids = append(ids, m.UserID)
			}
			slices.Sort(ids)
			if !slices.Equal(ids, []string{"Builder", "Editor"}) {
				t.Fatal("list-team-members did not read the active team", ids)
			}
			_, err = builder.ListTeamMembers(ctx, support.ID)
			code(err, 400, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM")
			others, err := remover.ListTeamMembers(ctx, support.ID)
			must(err)
			if len(others) != 1 || others[0].UserID != "Remover" {
				t.Fatal("list-team-members ignored the explicit team", others)
			}

			// remove-team-member removes only the named user from the named team.
			must(adaHTTP.RemoveTeamMember(ctx, client.TeamMembershipRequest{OrganizationID: acme.ID, TeamID: design.ID, UserID: "Editor"}))
			members, err = builder.ListTeamMembers(ctx, design.ID)
			must(err)
			if len(members) != 1 || members[0].UserID != "Builder" {
				t.Fatal("remove-team-member removed the wrong membership", members)
			}
		})
	}
}
