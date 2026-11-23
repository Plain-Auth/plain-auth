package sqlstore

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/schema"
)

// Exercise the normal JSON API from two independent HTTP clients. The host
// installs only organizations and teams and serves no frontend routes.
func TestOrganizationAndTeamSelectionHTTP(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			store, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), []string{"organization-teams"}, schema.Options{})
			must(err)
			t.Cleanup(func() { store.Close() })
			organizations, err := org.New(org.Options{Store: store, Teams: &org.TeamOptions{}})
			must(err)
			server := httptest.NewUnstartedServer(nil)
			origin := "http://" + server.Listener.Addr().String()
			off := false
			api, err := auth.New(auth.Options{Store: store, Plugins: []auth.Plugin{organizations}, BaseURL: origin, Secret: "ordinary-org-switch-0123456789-abcdefghijk", EmailAndPassword: true, RateLimit: &off})
			must(err)
			server.Config.Handler = api
			server.Start()
			t.Cleanup(server.Close)
			newClient := func() *http.Client {
				jar, err := cookiejar.New(nil)
				must(err)
				return &http.Client{Jar: jar, Transport: server.Client().Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			}
			send := func(c *http.Client, method, path string, body any, status int) json.RawMessage {
				t.Helper()
				var data []byte
				if body != nil {
					var err error
					data, err = json.Marshal(body)
					must(err)
				}
				req, err := http.NewRequestWithContext(ctx, method, origin+"/api/auth/"+path, bytes.NewReader(data))
				must(err)
				if body != nil {
					req.Header.Set("Content-Type", "application/json")
				}
				if method == "POST" {
					req.Header.Set("Origin", origin)
				}
				res, err := c.Do(req)
				must(err)
				defer res.Body.Close()
				raw, err := io.ReadAll(res.Body)
				must(err)
				if res.StatusCode != status || res.Header.Get("Location") != "" || !strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") || !json.Valid(raw) {
					t.Fatalf("%s returned %d, expected %d JSON", path, res.StatusCode, status)
				}
				return raw
			}
			one, two := newClient(), newClient()
			login := map[string]string{"email": "member@api.example", "password": "local session selection", "name": "Member"}
			send(one, "POST", "sign-up/email", login, 200)
			send(two, "POST", "sign-in/email", login, 200)
			create := func(slug string) string {
				t.Helper()
				var g org.Organization
				must(json.Unmarshal(send(one, "POST", "organization/create", map[string]string{"slug": slug, "name": slug}, 200), &g))
				return g.ID
			}
			first, second := create("a-group"), create("b-group")
			set := func(c *http.Client, route, key string, id any, status int) string {
				t.Helper()
				response := send(c, "POST", "organization/"+route, map[string]any{key: id}, status)
				if string(bytes.TrimSpace(response)) == "null" {
					return ""
				}
				var result struct {
					ID, Code string
					Redirect bool
				}
				must(json.Unmarshal(response, &result))
				if result.Redirect {
					t.Fatal("ordinary selection instructed navigation")
				}
				if status != 200 {
					return result.Code
				}
				return result.ID
			}
			session := func(c *http.Client, group, team string) {
				t.Helper()
				var result struct {
					Session struct{ ActiveOrganizationID, ActiveTeamID string }
				}
				must(json.Unmarshal(send(c, "GET", "get-session", nil, 200), &result))
				if result.Session.ActiveOrganizationID != group || result.Session.ActiveTeamID != team {
					t.Fatal("unexpected active organization or team on this session")
				}
			}
			session(two, "", "")
			if set(one, "set-active", "organizationId", first, 200) != first {
				t.Fatal("expected selected organization")
			}
			var teams []org.Team
			must(json.Unmarshal(send(one, "GET", "organization/list-teams", nil, 200), &teams))
			if len(teams) != 1 {
				t.Fatal("missing member team")
			}
			team := teams[0].ID
			if set(one, "set-active-team", "teamId", team, 200) != team {
				t.Fatal("expected selected team")
			}
			for path, id := range map[string]string{"organization/set-active": first, "organization/set-active-team": team} {
				var selected struct{ ID string }
				must(json.Unmarshal(send(one, "POST", path, nil, 200), &selected))
				if selected.ID != id {
					t.Fatal("empty POST did not return the session selection", path)
				}
			}
			session(one, first, team)
			set(two, "set-active", "organizationId", second, 200)
			if set(two, "set-active-team", "teamId", team, 400) != "TEAM_NOT_FOUND" {
				t.Fatal("team from a different organization selected")
			}
			session(two, second, "")
			set(one, "set-active", "organizationId", first, 200)
			session(one, first, team)
			set(one, "set-active-team", "teamId", nil, 200)
			session(one, first, "")
			set(one, "set-active-team", "teamId", team, 200)
			set(one, "set-active", "organizationId", second, 200)
			session(one, second, "")
			set(one, "set-active", "organizationId", nil, 200)
			session(one, "", "")
			session(two, second, "")
			sdk, err := client.New(origin, two)
			must(err)
			page, err := sdk.ListOrganizationMembers(ctx, org.MemberListQuery{OrganizationSlug: "a-group", Limit: 1, SortBy: "userId", FilterField: "role", FilterOperator: "in", FilterValues: []string{"", "owner"}})
			must(err)
			if page.Total != 1 || len(page.Members) != 1 || page.Members[0].OrganizationID != first || page.Members[0].User.Email != login["email"] {
				t.Fatal("Go directory client lost its filter or tenant selection", page)
			}
			full, err := sdk.FullOrganization(ctx, org.FullOrganizationQuery{OrganizationID: second, OrganizationSlug: "a-group", MembersLimit: 1})
			must(err)
			if full == nil || full.ID != first || len(full.Members) != 1 || full.Members[0].User.Email != login["email"] || len(full.Teams) != 1 || full.Teams[0].ID != team || full.Invitations == nil {
				t.Fatal("Go full organization client returned the wrong session view", full)
			}
			inviteList, err := sdk.ListOrganizationInvitations(ctx, first)
			must(err)
			if inviteList == nil || len(inviteList) != 0 {
				t.Fatal("Go invitation client failed to read an empty organization list")
			}
			_, err = store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "emailVerified"=? WHERE "email"=?`), true, login["email"])
			must(err)
			received, err := sdk.ListUserInvitations(ctx)
			must(err)
			if received == nil || len(received) != 0 {
				t.Fatal("Go client failed to read the verified recipient's empty inbox")
			}
			emptySDK, err := client.New(origin, one)
			must(err)
			unselected, err := emptySDK.FullOrganization(ctx, org.FullOrganizationQuery{})
			must(err)
			if unselected != nil {
				t.Fatal("Go client did not preserve the null selection")
			}
			active, err := sdk.ActiveOrganizationMember(ctx)
			must(err)
			if active.OrganizationID != second || active.ID == "" || active.Role != "owner" || active.UserID != active.User.ID || active.User.Email != login["email"] || active.CreatedAt.IsZero() {
				t.Fatal("membership did not match the calling session")
			}
			_, err = store.db.ExecContext(ctx, store.bind(`UPDATE "member" SET "role"='admin,member' WHERE "organizationId"=? AND "userId"=?`), first, active.UserID)
			must(err)
			for _, tc := range []struct {
				query org.MemberRoleQuery
				want  string
			}{
				{org.MemberRoleQuery{}, "owner"},
				{org.MemberRoleQuery{OrganizationID: first}, "admin,member"},
				{org.MemberRoleQuery{OrganizationID: second, OrganizationSlug: "a-group", UserID: active.UserID}, "admin,member"},
			} {
				role, err := sdk.OrganizationMemberRole(ctx, tc.query)
				must(err)
				if role != tc.want {
					t.Fatalf("role lookup returned %q, want %q", role, tc.want)
				}
			}
			outsider := newClient()
			send(outsider, "POST", "sign-up/email", map[string]string{"email": "other@api.example", "name": "Other", "password": login["password"]}, 200)
			guestSDK, err := client.New(origin, outsider)
			must(err)
			var issued org.Invitation
			must(json.Unmarshal(send(two, "POST", "organization/invite-member", map[string]any{"email": "other@api.example", "role": "member", "organizationId": second}, 200), &issued))
			detail, err := guestSDK.OrganizationInvitation(ctx, issued.ID)
			must(err)
			if detail.ID != issued.ID || detail.OrganizationID != second || detail.InviterEmail != login["email"] || detail.OrganizationSlug != "b-group" {
				t.Fatal("Go client lost invitation details", detail)
			}
			var forbidden struct{ Code string }
			must(json.Unmarshal(send(outsider, "GET", "organization/get-active-member-role?organizationId="+second+"&userId="+active.UserID, nil, 403), &forbidden))
			if forbidden.Code != org.ErrRoleReadDenied.Code {
				t.Fatal("role disclosed to an outsider", forbidden.Code)
			}
			code := func(c *http.Client, status int, expected string) {
				t.Helper()
				var body struct{ Code string }
				must(json.Unmarshal(send(c, "GET", "organization/get-active-member?organizationId="+second, nil, status), &body))
				if body.Code != expected {
					t.Fatalf("active member error = %q, want %q", body.Code, expected)
				}
			}
			code(one, 400, "NO_ACTIVE_ORGANIZATION")
			_, err = store.db.ExecContext(ctx, store.bind(`DELETE FROM "member" WHERE "id"=?`), active.ID)
			must(err)
			code(two, 400, "MEMBER_NOT_FOUND")
			send(two, "POST", "sign-out", nil, 200)
			code(two, 401, "UNAUTHORIZED")
		})
	}
}
