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
			send := func(c *http.Client, path string, body any, status int) json.RawMessage {
				t.Helper()
				var data []byte
				method := "GET"
				if body != nil {
					method = "POST"
					var err error
					data, err = json.Marshal(body)
					must(err)
				}
				req, err := http.NewRequestWithContext(ctx, method, origin+"/api/auth/"+path, bytes.NewReader(data))
				must(err)
				if body != nil {
					req.Header.Set("Content-Type", "application/json")
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
			send(one, "sign-up/email", login, 200)
			send(two, "sign-in/email", login, 200)
			create := func(slug string) string {
				t.Helper()
				var g org.Organization
				must(json.Unmarshal(send(one, "organization/create", map[string]string{"slug": slug, "name": slug}, 200), &g))
				return g.ID
			}
			first, second := create("a-group"), create("b-group")
			set := func(c *http.Client, route, key string, id any, status int) string {
				t.Helper()
				response := send(c, "organization/"+route, map[string]any{key: id}, status)
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
				must(json.Unmarshal(send(c, "get-session", nil, 200), &result))
				if result.Session.ActiveOrganizationID != group || result.Session.ActiveTeamID != team {
					t.Fatal("unexpected active organization or team on this session")
				}
			}
			session(two, "", "")
			if set(one, "set-active", "organizationId", first, 200) != first {
				t.Fatal("expected selected organization")
			}
			var teams []org.Team
			must(json.Unmarshal(send(one, "organization/list-teams", nil, 200), &teams))
			if len(teams) != 1 {
				t.Fatal("missing member team")
			}
			team := teams[0].ID
			if set(one, "set-active-team", "teamId", team, 200) != team {
				t.Fatal("expected selected team")
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
		})
	}
}
