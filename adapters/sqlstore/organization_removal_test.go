package sqlstore

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestOrganizationMemberRemoval(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			wantCode := func(err error, code string) {
				t.Helper()
				var p *auth.APIError
				if !errors.As(err, &p) || p.Code != code {
					t.Fatalf("want %s, got %v", code, err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"admin", "organization-teams"})
			must(err)
			s, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(err)
			defer s.Close()
			bare, err := Open(ctx, dialect, dsn)
			must(err)
			defer bare.Close()
			teams, err := s.WithOrganizationTeams(org.TeamOptions{})
			must(err)
			writer := teams.(org.MemberWriter)
			now := time.Now().UTC().Truncate(time.Millisecond)
			user := func(id string) {
				t.Helper()
				ss := auth.StoredSession{Session: auth.Session{ID: id + "-s", Token: id + "-t", UserID: id, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
				must(s.CreateUser(ctx, auth.User{ID: id, Name: id, Email: strings.ToLower(id) + "@example.test", CreatedAt: now, UpdatedAt: now}, "", &ss))
			}
			for _, id := range []string{"Owner", "Admin", "Peer", "Other", "Later"} {
				user(id)
			}
			extra := func(id, session string) {
				must(s.CreateSession(ctx, auth.StoredSession{Session: auth.Session{ID: session, Token: session + "-t", UserID: id, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}))
			}
			extra("Peer", "Peer-other")
			extra("Peer", "Peer-second")
			group := func(id string) {
				must(s.CreateOrganization(ctx, org.Organization{ID: id, Name: id, Slug: strings.ToLower(id), CreatedAt: now}, org.Member{ID: id + "-Owner", UserID: "Owner", Role: "owner", OrganizationID: id, CreatedAt: now}, "Owner-s", false))
			}
			group("Acme")
			group("Second")
			grant := func(group, user, role, team string) org.Member {
				t.Helper()
				m := org.Member{ID: group + "-" + user, UserID: user, Role: role, OrganizationID: group, CreatedAt: now}
				must(writer.AddOrganizationMember(ctx, m, team))
				return m
			}
			team := func(group string) *org.Team {
				t.Helper()
				v, err := teams.CreateTeam(ctx, org.TeamActor{UserID: "Owner", SessionID: "Owner-s"}, group, "Shared")
				must(err)
				return v
			}
			mainTeam, secondTeam := team("Acme"), team("Second")
			grant("Acme", "Admin", "admin,member", "")
			peer := grant("Acme", "Peer", "member", mainTeam.ID)
			secondPeer := grant("Second", "Peer", "member", secondTeam.ID)
			grant("Acme", "Other", "member", mainTeam.ID)
			selectTeam := func(session string, team *org.Team) {
				must(s.SetActiveOrganization(ctx, session, "Peer", &team.OrganizationID))
				_, err := teams.SetActiveTeam(ctx, org.TeamActor{UserID: "Peer", SessionID: session}, &team.ID)
				must(err)
			}
			selectTeam("Peer-s", mainTeam)
			selectTeam("Peer-second", mainTeam)
			selectTeam("Peer-other", secondTeam)
			service, err := org.New(org.Options{Store: bare})
			must(err)
			server := httptest.NewUnstartedServer(nil)
			base := "http://" + server.Listener.Addr().String()
			authn, err := auth.New(auth.Options{Store: bare, BaseURL: base, Secret: strings.Repeat("s", 32), Plugins: []auth.Plugin{service}})
			must(err)
			server.Config.Handler = authn
			server.Start()
			defer server.Close()
			sdk := func(token string) *client.Client {
				t.Helper()
				jar, _ := cookiejar.New(nil)
				u, _ := url.Parse(base)
				jar.SetCookies(u, []*http.Cookie{authn.SessionCookie(token, true)})
				c, err := client.New(base, &http.Client{Jar: jar})
				must(err)
				return c
			}
			admin := sdk("Admin-t")
			extra("Admin", "Admin-revoked")
			must(s.DeleteSession(ctx, "Admin-revoked-t"))
			_, err = bare.RemoveOrganizationMember(ctx, "Admin", "Admin-revoked-t", "Acme", peer.ID)
			wantCode(err, "UNAUTHORIZED")
			extra("Admin", "Admin-delegated")
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "session" SET "impersonatedBy"=? WHERE "token"=?`), "Owner", "Admin-delegated-t")
			must(err)
			_, err = bare.RemoveOrganizationMember(ctx, "Admin", "Admin-delegated-t", "Acme", peer.ID)
			wantCode(err, "UNAUTHORIZED")
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "user" SET "banned"=? WHERE "id"=?`), true, "Admin")
			must(err)
			_, err = bare.RemoveOrganizationMember(ctx, "Admin", "Admin-t", "Acme", peer.ID)
			if err == nil {
				t.Fatal("banned actor used an existing session to remove a member")
			}
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "user" SET "banned"=? WHERE "id"=?`), false, "Admin")
			must(err)
			_, err = admin.RemoveOrganizationMember(ctx, peer.ID, "")
			wantCode(err, "NO_ACTIVE_ORGANIZATION")
			_, err = bare.RemoveOrganizationMember(ctx, "Admin", "admin-t", "Acme", peer.ID)
			wantCode(err, "UNAUTHORIZED")
			_, err = bare.RemoveOrganizationMember(ctx, "admin", "Admin-t", "Acme", peer.ID)
			wantCode(err, "UNAUTHORIZED")
			_, err = admin.RemoveOrganizationMember(ctx, secondPeer.ID, "Acme")
			wantCode(err, "MEMBER_NOT_FOUND")
			_, err = admin.RemoveOrganizationMember(ctx, strings.ToLower(peer.ID), "Acme")
			wantCode(err, "MEMBER_NOT_FOUND")
			_, err = admin.RemoveOrganizationMember(ctx, peer.ID, "acme")
			wantCode(err, "MEMBER_NOT_FOUND")
			_, err = admin.RemoveOrganizationMember(ctx, "Acme-Owner", "Acme")
			wantCode(err, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER")
			_, err = sdk("Peer-t").RemoveOrganizationMember(ctx, "Acme-Other", "Acme")
			wantCode(err, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER")
			selected := "Acme"
			must(s.SetActiveOrganization(ctx, "Admin-s", "Admin", &selected))
			removed, err := admin.RemoveOrganizationMember(ctx, "PEER@EXAMPLE.TEST", "")
			must(err)
			if removed.ID != peer.ID || removed.User == nil || removed.User.ID != "Peer" || removed.User.Email != "peer@example.test" {
				t.Fatalf("email removal result %+v", removed)
			}
			for _, check := range []struct {
				id   string
				team *org.Team
			}{{"Peer-s", nil}, {"Peer-second", nil}, {"Peer-other", secondTeam}} {
				var group, team *string
				must(s.db.QueryRowContext(ctx, s.bind(`SELECT "activeOrganizationId","activeTeamId" FROM "session" WHERE "id"=?`), check.id).Scan(&group, &team))
				if check.team == nil && (group != nil || team != nil) || check.team != nil && (group == nil || *group != check.team.OrganizationID || team == nil || *team != check.team.ID) {
					t.Fatalf("incorrect session selection on %s: %v %v", check.id, group, team)
				}
			}
			for _, team := range []*org.Team{mainTeam, secondTeam} {
				var count, actual int
				must(s.db.QueryRowContext(ctx, s.bind(`SELECT t."memberCount",(SELECT COUNT(*) FROM "teamMember" WHERE "teamId"=t."id") FROM "team" t WHERE t."id"=?`), team.ID).Scan(&count, &actual))
				if count != 1 || actual != count {
					t.Fatalf("physical team cleanup lost seat counts: %d %d", count, actual)
				}
			}
			_, err = bare.RemoveOrganizationMember(ctx, "Peer", "Peer-t", "Acme", "Acme-Other")
			wantCode(err, "MEMBER_NOT_FOUND")
			left, err := sdk("Peer-other-t").LeaveOrganization(ctx, "Second")
			must(err)
			if left.ID != secondPeer.ID || left.User == nil || left.User.Name != "Peer" {
				t.Fatalf("self-leave result %+v", left)
			}
			other, err := admin.RemoveOrganizationMember(ctx, "Acme-Other", "Acme")
			must(err)
			if other.User != nil {
				t.Fatal("ID removal included user")
			}
			_, err = bare.LeaveOrganization(ctx, "Owner", "Owner-t", "Acme")
			wantCode(err, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER")
			grant("Acme", "Later", "admin,owner", "")
			// Imported memberships can have whitespace around a comma-separated role.
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "member" SET "role"=? WHERE "id"=?`), "admin, owner", "Acme-Later")
			must(err)
			gate := make(chan struct{})
			result := make(chan error, 2)
			go func() { <-gate; _, err := s.LeaveOrganization(ctx, "Owner", "Owner-t", "Acme"); result <- err }()
			go func() { <-gate; _, err := bare.LeaveOrganization(ctx, "Later", "Later-t", "Acme"); result <- err }()
			close(gate)
			a, b := <-result, <-result
			if a != nil {
				a, b = b, a
			}
			must(a)
			wantCode(b, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER")
			var count int
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "member" WHERE "organizationId"=? AND "role" LIKE '%owner%'`), "Acme").Scan(&count))
			if count != 1 {
				t.Fatalf("concurrent departures left %d owners", count)
			}
			group("Opposed")
			grant("Opposed", "Later", "owner", "")
			start := make(chan struct{})
			go func() {
				<-start
				_, err := s.RemoveOrganizationMember(ctx, "Owner", "Owner-t", "Opposed", "Opposed-Later")
				result <- err
			}()
			go func() {
				<-start
				_, err := bare.RemoveOrganizationMember(ctx, "Later", "Later-t", "Opposed", "Opposed-Owner")
				result <- err
			}()
			close(start)
			a, b = <-result, <-result
			if a != nil {
				a, b = b, a
			}
			must(a)
			wantCode(b, "MEMBER_NOT_FOUND")
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "member" WHERE "organizationId"=?`), "Opposed").Scan(&count))
			if count != 1 {
				t.Fatalf("competing owner removals left %d memberships", count)
			}
		})
	}
}
