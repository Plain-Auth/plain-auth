package sqlstore

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestMixedOrganizationTeamNodes(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			open := func(profile string) *Store {
				t.Helper()
				ddl, err := schema.Generate(dialect, []string{profile})
				must(err)
				s, err := OpenWithSchema(ctx, dialect, dsn, ddl)
				must(err)
				t.Cleanup(func() { s.Close() })
				return s
			}
			node := func(s *Store, opts *org.TeamOptions) *auth.Auth {
				t.Helper()
				plugin, err := org.New(org.Options{Store: s, Teams: opts})
				must(err)
				off := false
				a, err := auth.New(auth.Options{Store: s, BaseURL: "http://org.example.test", Secret: strings.Repeat("f", 32), RateLimit: &off, Plugins: []auth.Plugin{plugin}})
				must(err)
				return a
			}
			plainStore := open("organization")
			plain := node(plainStore, nil)
			fullStore := open("organization-teams")
			maximum := 1
			opts := org.TeamOptions{MaximumMembersPerTeam: &maximum, DisableDefaultTeam: true}
			full := node(fullStore, &opts)
			teams, err := fullStore.WithOrganizationTeams(opts)
			must(err)
			now := time.Now().UTC().Truncate(time.Millisecond)
			for _, id := range []string{"Owner", "Peer", "Filler", "Regular"} {
				must(fullStore.CreateUser(ctx, auth.User{ID: id, Name: id, Email: strings.ToLower(id) + "@example.test", CreatedAt: now, UpdatedAt: now}, "", &auth.StoredSession{Session: auth.Session{ID: id + "-s", UserID: id, Token: id + "-t", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}))
			}
			for _, pair := range [][2]string{{"Main", "Owner"}, {"Second", "Peer"}} {
				group, user := pair[0], pair[1]
				must(plainStore.CreateOrganization(ctx, org.Organization{ID: group, Name: group, Slug: strings.ToLower(group), CreatedAt: now}, org.Member{ID: "owner-" + group, OrganizationID: group, UserID: user, Role: "owner", CreatedAt: now}, user+"-s", false))
			}
			actor := org.TeamActor{UserID: "Owner", SessionID: "Owner-s"}
			team, err := teams.CreateTeam(ctx, actor, "Main", "Support")
			must(err)
			post := func(t *testing.T, n *auth.Auth, who, route string, body map[string]any, status int, code string) {
				t.Helper()
				payload, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest("POST", "http://org.example.test/api/auth/organization/"+route, bytes.NewReader(payload))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", "http://org.example.test")
				req.AddCookie(n.SessionCookie(who+"-t", true))
				w := httptest.NewRecorder()
				n.ServeHTTP(w, req)
				if w.Code != status {
					t.Fatalf("%s expected %d, got %d %s", route, status, w.Code, w.Body.String())
				}
				if code != "" {
					var result auth.APIError
					if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
						t.Fatal(err)
					}
					if result.Code != code {
						t.Fatalf("%s expected %s got %s", route, code, result.Code)
					}
				}
			}
			invite := func(id, who string, withTeam bool) {
				t.Helper()
				i := org.Invitation{ID: id, InviterID: "Owner", OrganizationID: "Main", Email: strings.ToLower(who) + "@example.test", Role: "member", Status: "pending", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
				if withTeam {
					i.TeamID = &team.ID
				}
				_, err := teams.InviteOrganizationMember(ctx, i, "Owner-s", false)
				must(err)
			}
			invite("TeamInvite", "Peer", true)
			must(teams.(org.MemberWriter).AddOrganizationMember(ctx, org.Member{ID: "filler-grant", UserID: "Filler", OrganizationID: "Main", Role: "member", CreatedAt: now}, team.ID))
			verifyPending := func() {
				t.Helper()
				var status string
				var memberships int
				must(plainStore.db.QueryRowContext(ctx, plainStore.bind(`SELECT "status",(SELECT COUNT(*) FROM "member" WHERE "userId"=? AND "organizationId"=?) FROM "invitation" WHERE "id"=?`), "Peer", "Main", "TeamInvite").Scan(&status, &memberships))
				if status != "pending" || memberships != 0 {
					t.Fatal("team policy failure consumed the invitation or granted membership")
				}
			}
			accept := map[string]any{"invitationId": "TeamInvite"}
			post(t, plain, "Regular", "accept-invitation", accept, 403, "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION")
			post(t, plain, "Peer", "accept-invitation", accept, 409, "ORGANIZATION_TEAM_POLICY_REQUIRED")
			verifyPending()
			post(t, full, "Peer", "accept-invitation", accept, 403, "TEAM_MEMBER_LIMIT_REACHED")
			verifyPending()
			must(teams.RemoveTeamMember(ctx, actor, "Main", team.ID, "Filler"))
			post(t, full, "Peer", "accept-invitation", accept, 200, "")
			check := func(group *string, selected *string) {
				t.Helper()
				var g, teamID *string
				must(plainStore.db.QueryRowContext(ctx, plainStore.bind(`SELECT "activeOrganizationId","activeTeamId" FROM "session" WHERE "id"=?`), "Peer-s").Scan(&g, &teamID))
				equal := func(a, b *string) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
				if !equal(g, group) || !equal(teamID, selected) {
					t.Fatal("mixed-node session selection differs from the requested organization and team")
				}
			}
			main, second := "Main", "Second"
			check(&main, &team.ID)
			post(t, plain, "Peer", "set-active", map[string]any{"organizationId": main}, 200, "")
			check(&main, &team.ID)
			post(t, plain, "Peer", "set-active", map[string]any{"organizationId": second}, 200, "")
			check(&second, nil)
			post(t, plain, "Peer", "set-active", map[string]any{"organizationId": main}, 200, "")
			check(&main, nil)
			post(t, full, "Peer", "set-active-team", map[string]any{"teamId": team.ID}, 200, "")
			check(&main, &team.ID)
			post(t, plain, "Peer", "set-active", map[string]any{"organizationId": nil}, 200, "")
			check(nil, nil)
			invite("PlainInvite", "Regular", false)
			t.Run("invitation IDs use byte-exact equality", func(t *testing.T) {
				post(t, plain, "Regular", "accept-invitation", map[string]any{"invitationId": "plaininvite"}, 400, "INVITATION_NOT_FOUND")
				var status string
				var grants int
				if err := plainStore.db.QueryRowContext(ctx, plainStore.bind(`SELECT "status",(SELECT COUNT(*) FROM "member" WHERE "organizationId"=? AND "userId"=?) FROM "invitation" WHERE "id"=?`), main, "Regular", "PlainInvite").Scan(&status, &grants); err != nil {
					t.Fatal(err)
				}
				if status != "pending" || grants != 0 {
					t.Fatalf("case-changed invitation ID affected stored state: %s, %d", status, grants)
				}
			})
			post(t, plain, "Regular", "accept-invitation", map[string]any{"invitationId": "PlainInvite"}, 200, "")
			var n int
			must(plainStore.db.QueryRowContext(ctx, plainStore.bind(`SELECT COUNT(*) FROM "member" WHERE "organizationId"=? AND "userId"=?`), main, "Regular").Scan(&n))
			if n != 1 {
				t.Fatal("plain node did not accept the untargeted invitation")
			}
		})
	}
}
