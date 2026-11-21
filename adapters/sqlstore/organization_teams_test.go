package sqlstore

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/client"
	org "github.com/Stonewrit/stonewrit-auth/plugins/organization"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

func TestTeamAccountsAcrossEngines(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			denied := func(err error, code string) {
				t.Helper()
				var api *authn.APIError
				if !errors.As(err, &api) || api.Code != code {
					t.Fatalf("expected %s, got %v", code, err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"organization-teams"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(err)
			defer store.Close()
			other, err := Open(ctx, dialect, dsn)
			must(err)
			defer other.Close()
			capacity := 2
			options := org.TeamOptions{MaximumTeams: 3, MaximumMembersPerTeam: &capacity}
			start := func(s *Store) *httptest.Server {
				server := httptest.NewUnstartedServer(nil)
				base := "http://" + server.Listener.Addr().String()
				p, err := org.New(org.Options{Store: s, Teams: &options})
				must(err)
				limit := false
				handler, err := authn.New(authn.Options{Store: s, BaseURL: base, Secret: "team-organization-fixture-000000000", RateLimit: &limit, EmailAndPassword: true, Plugins: []authn.Plugin{p, {ID: "test-selection-cookie", OnSessionCookie: func(event authn.SessionCookieEvent) {
					if event.Route == "/organization/set-active-team" {
						event.Header.Set("X-Selection-Cookie", event.Cookie.Name)
					}
				}}}})
				must(err)
				server.Config.Handler = handler
				server.Start()
				t.Cleanup(server.Close)
				return server
			}
			a, b := start(store), start(other)
			browsers := map[string]*http.Client{}
			login := func(server *httptest.Server, email string) (*client.Client, authn.User) {
				jar, err := cookiejar.New(nil)
				must(err)
				browsers[email] = &http.Client{Jar: jar}
				c, err := client.New(server.URL, browsers[email])
				must(err)
				persistent := email != "peer@example.test"
				res, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: email, Email: email, Password: "teams-fixture-password", RememberMe: &persistent})
				must(err)
				return c, res.User
			}
			owner, ownerUser := login(a, "owner@example.test")
			peer, peerUser := login(b, "peer@example.test")
			admin, adminUser := login(b, "admin@example.test")
			otherUser, foreigner := login(b, "other@example.test")
			out := org.Organization{}
			must(owner.Do(ctx, "POST", "/organization/create", map[string]string{"name": "Studio", "slug": "studio"}, &out))
			group := out.ID
			defaultTeams, err := owner.ListOrganizationTeams(ctx, "")
			must(err)
			if len(defaultTeams) != 1 || defaultTeams[0].Name != "Studio" {
				t.Fatal("missing default team")
			}
			first := defaultTeams[0]
			session, err := owner.GetSession(ctx)
			must(err)
			if session.Session.ActiveTeamID == nil || *session.Session.ActiveTeamID != first.ID {
				t.Fatal("creator's default team not active")
			}
			team, err := owner.CreateTeam(ctx, "Reporting", group)
			must(err)
			updated, err := owner.UpdateTeam(ctx, team.ID, "Research", group)
			must(err)
			if updated.Name != "Research" || updated.UpdatedAt == nil {
				t.Fatal("updated team metadata")
			}
			third, err := owner.CreateTeam(ctx, "Archive", group)
			must(err)
			_, err = owner.CreateTeam(ctx, "FULL", group)
			denied(err, "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS")
			denied(owner.RemoveTeam(ctx, first.ID, group), "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM")
			_, err = owner.SetActiveTeam(ctx, &team.ID)
			denied(err, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM")
			must(otherUser.Do(ctx, "POST", "/organization/create", map[string]string{"name": "Other", "slug": "other"}, &out))
			foreign, err := otherUser.ListOrganizationTeams(ctx, "")
			must(err)
			_, err = owner.UpdateTeam(ctx, foreign[0].ID, "invalid", group)
			denied(err, "TEAM_NOT_FOUND")
			_, err = owner.AddTeamMember(ctx, client.TeamMembershipRequest{TeamID: team.ID, UserID: foreigner.ID})
			denied(err, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
			invite := func(person authn.User, role string, teams any) (org.Invitation, error) {
				var inv org.Invitation
				err := owner.Do(ctx, "POST", "/organization/invite-member", map[string]any{"email": person.Email, "role": role, "teamId": teams}, &inv)
				return inv, err
			}
			_, err = invite(peerUser, "member", foreign[0].ID)
			denied(err, "TEAM_NOT_FOUND")
			_, err = invite(peerUser, "member", []string{team.ID + "," + third.ID})
			denied(err, "INVALID_TEAM_ID")
			// Removing one of two pending team IDs leaves an acceptable, single-team invitation.
			pending, err := invite(peerUser, "member", []string{team.ID, third.ID})
			must(err)
			must(owner.RemoveTeam(ctx, third.ID, group))
			err = peer.Do(ctx, "POST", "/organization/accept-invitation", map[string]string{"invitationId": pending.ID}, nil)
			must(err)
			signed, err := peer.GetSession(ctx)
			must(err)
			if signed.Session.ActiveTeamID == nil || *signed.Session.ActiveTeamID != team.ID {
				t.Fatal("single surviving invited team not active")
			}
			// Re-selecting the current team reissues the active cookie through the same hooks and preserves browser-only sign-in.
			for _, browser := range []struct {
				client     *http.Client
				url        string
				persistent bool
			}{{browsers[ownerUser.Email], a.URL, true}, {browsers[peerUser.Email], b.URL, false}} {
				r, err := http.NewRequestWithContext(ctx, http.MethodPost, browser.url+"/api/auth/organization/set-active-team", strings.NewReader("{}"))
				must(err)
				r.Header.Set("Origin", browser.url)
				r.Header.Set("Content-Type", "application/json")
				response, err := browser.client.Do(r)
				must(err)
				response.Body.Close()
				if response.StatusCode != 200 || response.Header.Get("X-Selection-Cookie") != "authn.session_token" {
					t.Fatal("team selection did not emit its session cookie hook")
				}
				cookies := response.Cookies()
				if len(cookies) != 1 || cookies[0].HttpOnly != true || (cookies[0].MaxAge > 0) != browser.persistent {
					t.Fatal("team selection changed persistence")
				}
			}
			teams, err := peer.ListUserTeams(ctx, "", "")
			must(err)
			if len(teams) != 1 || teams[0].ID != team.ID {
				t.Fatal("invite granted unintended team")
			}
			_, err = peer.ListUserTeams(ctx, group, ownerUser.ID)
			denied(err, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER")
			member, err := owner.AddTeamMember(ctx, client.TeamMembershipRequest{TeamID: team.ID, UserID: peerUser.ID})
			must(err)
			again, err := owner.AddTeamMember(ctx, client.TeamMembershipRequest{TeamID: team.ID, UserID: peerUser.ID})
			must(err)
			if member.ID != again.ID {
				t.Fatal("repeat added duplicate membership")
			}
			var key string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "membershipKey" FROM "teamMember" WHERE "id"=?`), member.ID).Scan(&key))
			sum := sha256.Sum256([]byte(`["` + team.ID + `","` + peerUser.ID + `"]`))
			if key != base64.RawURLEncoding.EncodeToString(sum[:]) {
				t.Fatal("incorrect persisted membership key")
			}
			adminInvite, err := invite(adminUser, "admin", nil)
			must(err)
			must(admin.Do(ctx, "POST", "/organization/accept-invitation", map[string]string{"invitationId": adminInvite.ID}, nil))
			// Two server instances race to admit different organization members to the last seat.
			type attempt struct {
				id  string
				err error
			}
			results := make(chan attempt, 2)
			var syncer sync.WaitGroup
			for _, pair := range []struct {
				c  *client.Client
				id string
			}{{owner, ownerUser.ID}, {admin, adminUser.ID}} {
				syncer.Go(func() {
					_, err := pair.c.AddTeamMember(ctx, client.TeamMembershipRequest{TeamID: team.ID, UserID: pair.id})
					results <- attempt{pair.id, err}
				})
			}
			syncer.Wait()
			close(results)
			var winner string
			for r := range results {
				if r.err == nil {
					if winner != "" {
						t.Fatal("oversubscribed team capacity")
					}
					winner = r.id
				} else {
					denied(r.err, "TEAM_MEMBER_LIMIT_REACHED")
				}
			}
			if winner == "" {
				t.Fatal("no winner for available seat")
			}
			members, err := peer.ListTeamMembers(ctx, "")
			must(err)
			var count int
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "memberCount" FROM "team" WHERE "id"=?`), team.ID).Scan(&count))
			if count != 2 || len(members) != 2 {
				t.Fatal("persistent count and valid memberships disagree")
			}
			// An existing pending invitation must remain usable if a concurrent membership fills its team.
			waiting, waitUser := login(b, "waiting@example.test")
			waitInvite, err := invite(waitUser, "member", first.ID)
			must(err)
			_, err = owner.AddTeamMember(ctx, client.TeamMembershipRequest{TeamID: first.ID, UserID: adminUser.ID})
			must(err)
			err = waiting.Do(ctx, "POST", "/organization/accept-invitation", map[string]string{"invitationId": waitInvite.ID}, nil)
			denied(err, "TEAM_MEMBER_LIMIT_REACHED")
			var pendingStatus string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "status" FROM "invitation" WHERE "id"=?`), waitInvite.ID).Scan(&pendingStatus))
			if pendingStatus != "pending" {
				t.Fatal("capacity failure consumed invitation")
			}
			var partial int
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "member" WHERE "userId"=? AND "organizationId"=?`), waitUser.ID, group).Scan(&partial))
			if partial != 0 {
				t.Fatal("capacity failure created partial membership")
			}
			must(owner.RemoveTeamMember(ctx, client.TeamMembershipRequest{TeamID: first.ID, UserID: adminUser.ID}))
			must(waiting.Do(ctx, "POST", "/organization/accept-invitation", map[string]string{"invitationId": waitInvite.ID}, nil))
			// The viewer can query their own teams across multiple organizations, but a different user's list requires management permission.
			personal := org.Organization{}
			must(peer.Do(ctx, "POST", "/organization/create", map[string]string{"name": "Personal", "slug": "personal"}, &personal))
			all, err := peer.ListUserTeams(ctx, "", "")
			must(err)
			if len(all) != 2 {
				t.Fatal("implicit own team list failed across organizations")
			}
			one, err := peer.ListUserTeams(ctx, group, "")
			must(err)
			if len(one) != 1 || one[0].OrganizationID != group {
				t.Fatal("explicit team list escaped organization")
			}
			others, err := admin.ListUserTeams(ctx, group, peerUser.ID)
			must(err)
			if len(others) != 1 || others[0].ID != team.ID {
				t.Fatal("admin failed to list organization member teams")
			}
			must(peer.Do(ctx, "POST", "/organization/set-active", map[string]string{"organizationId": group}, nil))
			_, err = peer.SetActiveTeam(ctx, &team.ID)
			must(err)
			must(owner.RemoveTeamMember(ctx, client.TeamMembershipRequest{TeamID: team.ID, UserID: peerUser.ID}))
			signed, err = peer.GetSession(ctx)
			must(err)
			if signed.Session.ActiveTeamID != nil {
				t.Fatal("removing member retained active team")
			}
			_, err = peer.ListTeamMembers(ctx, team.ID)
			denied(err, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM")
			must(owner.RemoveTeam(ctx, team.ID, group))
			_, err = owner.SetActiveTeam(ctx, nil)
			must(err)
			denied(owner.RemoveTeam(ctx, first.ID, group), "UNABLE_TO_REMOVE_LAST_TEAM")
		})
	}
}

func TestTeamExplicitConfiguration(t *testing.T) {
	ctx := t.Context()
	dsn := organizationTestDSN(t, "sqlite")
	base, err := Open(ctx, "sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	if _, err = org.New(org.Options{Store: base, Teams: &org.TeamOptions{}}); err == nil {
		t.Fatal("missing team schema accepted")
	}
	ddl, err := schema.Generate("sqlite", []string{"organization-teams"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenWithSchema(ctx, "sqlite", dsn, ddl)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	service, err := s.WithOrganizationTeams(org.TeamOptions{DisableDefaultTeam: true, AllowRemovingAllTeams: true})
	if err != nil {
		t.Fatal(err)
	}
	u := testUser("owner")
	ss := testSession(u, "owner")
	ss.ExpiresAt = time.Now().Add(time.Hour)
	if err := s.CreateUser(ctx, u, "hash", &ss); err != nil {
		t.Fatal(err)
	}
	group := org.Organization{ID: "g", Name: "G", Slug: "g", CreatedAt: u.CreatedAt}
	a := org.TeamActor{UserID: u.ID, SessionID: ss.ID}
	if err := service.CreateOrganization(ctx, group, org.Member{ID: "m", OrganizationID: group.ID, UserID: u.ID, Role: "owner", CreatedAt: u.CreatedAt}, a.SessionID, false); err != nil {
		t.Fatal(err)
	}
	list, err := service.ListTeams(ctx, a, group.ID)
	if err != nil || len(list) != 0 {
		t.Fatal("default team disabled", err)
	}
	last, err := service.CreateTeam(ctx, a, group.ID, "Only")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RemoveTeam(ctx, a, group.ID, last.ID); err != nil {
		t.Fatal("last team removal enabled", err)
	}
	if err := s.DeleteSession(ctx, ss.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateTeam(ctx, a, group.ID, "Late"); !errors.Is(err, org.ErrUnauthenticated) {
		t.Fatal("revoked actor retained mutation permission", err)
	}
}
