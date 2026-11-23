package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestBrowserPostLoginSelection(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			const base = "https://issuer.example.test"
			const callback = "https://reports.example.test/return"
			s, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), []string{"oauth-provider", "organization-teams"}, schema.Options{})
			must(err)
			t.Cleanup(func() { s.Close() })
			groups, err := org.New(org.Options{Store: s, Teams: &org.TeamOptions{}})
			must(err)
			var personal, force, fail bool
			var checks int
			var lastContinuation bool
			var referenceScopes []string
			options := op.Options{Scopes: []string{"reports", "email"}, Authorization: op.BrowserAuthorizationOptions{
				ConsentPage: "/consent",
				PostLogin: &op.PostLoginOptions{Page: "/choose-team?theme=light", ShouldRedirect: func(_ context.Context, a op.PostLoginContext) (bool, error) {
					checks++
					lastContinuation = a.IsContinuation
					if a.Session.UserID != a.User.ID || a.User.ID == "" || a.Headers.Get("Cookie") == "" || len(a.Scopes) == 0 {
						t.Fatal("missing policy context")
					}
					if fail {
						return false, errors.New("host lookup unavailable")
					}
					return !personal && (a.Session.ActiveTeamID == nil || force && !a.IsContinuation), nil
				}},
				ConsentReference: func(_ context.Context, a op.RegistrationAccess, scopes []string) (string, error) {
					referenceScopes = slices.Clone(scopes)
					if personal {
						return "", nil
					}
					if a.Session.ActiveOrganizationID == nil {
						return "", errors.New("select an organization")
					}
					return *a.Session.ActiveOrganizationID, nil
				},
			}}
			issuer, err := op.New(options)
			must(err)
			off := false
			h, err := auth.New(auth.Options{BaseURL: base, Store: s, Secret: "post-login-local-0123456789-abcdefghijk", EmailAndPassword: true, RateLimit: &off, Plugins: []auth.Plugin{groups, issuer}})
			must(err)
			jar, err := cookiejar.New(nil)
			must(err)
			browser := &http.Client{Jar: jar, Transport: guestTransport{h}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			sdk, err := client.New(base, browser)
			must(err)
			user, err := sdk.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "select@post-login.test", Password: "local organization selection"})
			must(err)
			_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO "oauthClient" ("id","clientId","applicationType","redirectUris","tokenEndpointAuthMethod","scopes") VALUES ('post','app','web',?,'none',?)`), `["https://reports.example.test/return"]`, `["reports","email"]`)
			must(err)
			create := func(name string) string {
				t.Helper()
				var g org.Organization
				must(sdk.Do(ctx, "POST", "/organization/create", map[string]string{"name": name, "slug": name}, &g))
				return g.ID
			}
			first := create("first")
			teams, err := sdk.ListOrganizationTeams(ctx, first)
			must(err)
			if len(teams) != 1 {
				t.Fatal("expected creator's default team")
			}
			team := teams[0].ID
			_, err = sdk.SetActiveTeam(ctx, nil)
			must(err)
			q := url.Values{"client_id": {"app"}, "redirect_uri": {callback}, "response_type": {"code"}, "state": {"state"}, "scope": {"reports email"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}}
			begin := func() string {
				t.Helper()
				var res struct{ URL string }
				must(sdk.Do(ctx, "GET", "/oauth2/authorize?"+q.Encode(), nil, &res))
				return res.URL
			}
			fields := func(raw, path string) url.Values {
				t.Helper()
				u, err := url.Parse(raw)
				must(err)
				if u.Path != path {
					t.Fatal("unexpected destination", u.Path)
				}
				v, err := h.VerifyOAuthPageQuery(u.RawQuery)
				must(err)
				if v.Has("theme") {
					t.Fatal("page preferences escaped the form")
				}
				return v
			}
			problem := func(err error, status int) {
				t.Helper()
				var e *auth.APIError
				if !errors.As(err, &e) || e.Status != status {
					t.Fatal("unexpected status", err)
				}
			}
			choose := fields(begin(), "/choose-team")
			if choose.Has("ba_pl") || lastContinuation {
				t.Fatal("new request already cleared post-login")
			}
			bad := choose.Encode() + "&state=other"
			var next struct{ URL string }
			err = sdk.Do(ctx, "POST", "/organization/set-active-team", map[string]string{"teamId": team, "oauth_query": bad}, &next)
			problem(err, 400)
			session, err := sdk.GetSession(ctx)
			must(err)
			if session.Session.ActiveTeamID != nil {
				t.Fatal("invalid signed form changed selected team")
			}
			target, err := sdk.ContinueOAuthPostLogin(ctx, choose.Encode())
			must(err)
			fields(target, "/choose-team")
			if !lastContinuation {
				t.Fatal("explicit continuation failed to recheck selection")
			}
			must(sdk.Do(ctx, "POST", "/organization/set-active-team", map[string]string{"teamId": team, "oauth_query": choose.Encode()}, &next))
			approval := fields(next.URL, "/consent")
			if lastContinuation || approval.Get("ba_pl") != session.Session.ID || !slices.Equal(referenceScopes, []string{"reports", "email"}) {
				t.Fatal("team switch failed to reach bound consent")
			}
			for _, selection := range []struct{ path, field, id string }{
				{"set-active", "organizationId", first}, {"set-active-team", "teamId", team},
			} {
				body, err := json.Marshal(map[string]string{selection.field: selection.id, "oauth_query": choose.Encode()})
				must(err)
				req, err := http.NewRequestWithContext(ctx, "POST", base+"/api/auth/organization/"+selection.path, bytes.NewReader(body))
				must(err)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", base)
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Accept", "text/html")
				reply, err := browser.Do(req)
				must(err)
				reply.Body.Close()
				if reply.StatusCode != http.StatusFound {
					t.Fatal("signed selection navigation failed", selection.path, reply.StatusCode)
				}
				consent := fields(reply.Header.Get("Location"), "/consent")
				if consent.Get("ba_pl") != session.Session.ID {
					t.Fatal("selection navigation lost its session", selection.path)
				}
			}
			count := checks
			force = true
			target, err = sdk.ContinueOAuthPostLogin(ctx, approval.Encode())
			must(err)
			fields(target, "/consent")
			if checks != count {
				t.Fatal("matching clearance repeated the host policy")
			}
			second := create("second")
			if second == first {
				t.Fatal("missing separate organizations")
			}
			_, err = sdk.ContinueOAuthPostLogin(ctx, approval.Encode())
			problem(err, 400)
			_, err = sdk.DecideOAuthConsent(ctx, approval.Encode(), true, []string{"reports"})
			problem(err, 400)
			must(sdk.Do(ctx, "POST", "/organization/set-active", map[string]string{"organizationId": first}, nil))
			target, err = sdk.DecideOAuthConsent(ctx, approval.Encode(), true, []string{"reports"})
			must(err)
			u, err := url.Parse(target)
			must(err)
			if u.Query().Get("code") == "" || !slices.Equal(referenceScopes, []string{"reports"}) {
				t.Fatal("grant lost selected scopes")
			}
			fail = true
			err = sdk.Do(ctx, "GET", "/oauth2/authorize?"+q.Encode(), nil, &next)
			problem(err, 500)
			fail = false

			// A personal grant is independent of every organization-specific
			// grant for this user and client, regardless of their number.
			personal = true
			q.Set("prompt", "none")
			q.Set("scope", "reports")
			tx, err := s.db.BeginTx(ctx, nil)
			must(err)
			defer tx.Rollback()
			now := s.date(time.Now().UTC())
			insert := s.bind(`INSERT INTO "oauthConsent" ("id","userId","clientId","referenceId","scopes","requestedUserInfoClaims","createdAt","updatedAt") VALUES (?,?,'app',?,?,'[]',?,?)`)
			for i := 0; i < 105; i++ {
				id := fmt.Sprintf("group-%03d", i)
				_, err = tx.ExecContext(ctx, insert, id, user.User.ID, id, `["reports"]`, now, now)
				must(err)
			}
			must(tx.Commit())
			hasCode := func(want bool) {
				t.Helper()
				u, err := url.Parse(begin())
				must(err)
				if u.Query().Has("code") != want || !want && u.Query().Get("error") != "consent_required" {
					t.Fatal("personal consent lookup selected the wrong grant")
				}
			}
			hasCode(false)
			_, err = s.db.ExecContext(ctx, insert, "empty", user.User.ID, "", `["reports"]`, now, now)
			must(err)
			hasCode(true)
			_, err = s.db.ExecContext(ctx, insert, "null", user.User.ID, nil, `["email"]`, now, now)
			must(err)
			hasCode(false)
			q.Set("scope", "email")
			hasCode(true)
		})
	}
}
