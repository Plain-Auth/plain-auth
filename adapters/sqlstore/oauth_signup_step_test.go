package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestBrowserSignupPolicy(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			s, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), []string{"oauth-provider"}, schema.Options{})
			must(err)
			t.Cleanup(func() { s.Close() })
			const base = "https://accounts.example.test"
			const callback = "https://reports.example.test/return"
			check := func(_ context.Context, a op.RegistrationAccess, scopes []string) (*op.SignupStep, error) {
				if a.User.ID == "" || a.User.ID != a.Session.UserID || a.Headers.Get("Cookie") == "" {
					t.Fatal("policy did not receive the active browser owner")
				}
				switch a.User.Name {
				case "Untrusted":
					return &op.SignupStep{Page: "https://external.example.test/setup"}, nil
				case "Unavailable":
					return nil, errors.New("private onboarding service unavailable")
				case "Missing":
					return &op.SignupStep{}, nil
				case "Custom":
					if !slices.Equal(scopes, []string{"reports"}) {
						t.Fatalf("policy lost narrowed scopes %v", scopes)
					}
					return &op.SignupStep{Page: "/finish?theme=dark"}, nil
				}
				return nil, nil
			}
			newHost := func(loginPage string) (*auth.Auth, *client.Client) {
				p, err := op.New(op.Options{Scopes: []string{"reports", "email"}, Authorization: op.BrowserAuthorizationOptions{
					LoginPage: loginPage, ConsentPage: "/approve", CheckSignup: check,
				}})
				must(err)
				off := false
				h, err := auth.New(auth.Options{BaseURL: base, Secret: "local-signup-policy-0123456789-abcdefghijk", Store: s, EmailAndPassword: true, RateLimit: &off, Plugins: []auth.Plugin{p}})
				must(err)
				sdk, err := client.New(base, &http.Client{Transport: guestTransport{h}})
				must(err)
				return h, sdk
			}
			h, sdk := newHost("/login")
			_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO "oauthClient" ("id","clientId","applicationType","redirectUris","tokenEndpointAuthMethod","scopes") VALUES ('row','app','web',?,'none',?)`), `["https://reports.example.test/return"]`, `["reports","email"]`)
			must(err)
			signup := func(browser *client.Client, email, name string) {
				t.Helper()
				_, err := browser.SignUpEmail(ctx, client.SignUpRequest{Name: name, Email: email, Password: "local onboarding password"})
				must(err)
			}
			signup(sdk, "test@signup.example", "Missing")
			setName := func(name string) {
				t.Helper()
				must(sdk.Do(ctx, "POST", "/update-user", map[string]string{"name": name}, nil))
			}
			q := url.Values{"client_id": {"app"}, "redirect_uri": {callback}, "scope": {"reports email"}, "prompt": {"consent"},
				"response_type": {"code"}, "state": {"original"}, "code_challenge_method": {"S256"}, "code_challenge": {"challenge"}}
			authorize := func(browser *client.Client) string {
				t.Helper()
				var result struct{ URL string }
				must(browser.Do(ctx, "GET", "/oauth2/authorize?"+q.Encode(), nil, &result))
				return result.URL
			}
			signedPage := func(target, path string) string {
				t.Helper()
				u, err := url.Parse(target)
				must(err)
				if u.Path != path || u.Query().Get("state") != "original" || u.Query().Has("code") {
					t.Fatal("wrong host page", u.Path)
				}
				fields, err := h.VerifyOAuthPageQuery(u.RawQuery)
				must(err)
				return fields.Encode()
			}
			problem := func(err error, status int) {
				t.Helper()
				var e *auth.APIError
				if !errors.As(err, &e) || e.Status != status {
					t.Fatal("unexpected status", err)
				}
			}
			count := func(query string, args ...any) int {
				t.Helper()
				var n int
				must(s.db.QueryRowContext(ctx, s.bind(query), args...).Scan(&n))
				return n
			}
			const codes = `SELECT COUNT(*) FROM "verification" WHERE "value" LIKE ?`
			const codeMatch = `%"type":"authorization_code"%`
			const consents = `SELECT COUNT(*) FROM "oauthConsent" WHERE "clientId"='app'`
			step := signedPage(authorize(sdk), "/login")
			target, err := sdk.ContinueOAuthSignup(ctx, step)
			must(err)
			signedPage(target, "/login")
			setName("Ready")
			target, err = sdk.ContinueOAuthSignup(ctx, step)
			must(err)
			approval := signedPage(target, "/approve")

			setName("Untrusted")
			_, err = sdk.DecideOAuthConsent(ctx, approval, true, []string{"reports"})
			problem(err, 403)
			setName("Unavailable")
			_, err = sdk.DecideOAuthConsent(ctx, approval, true, []string{"reports"})
			problem(err, 500)
			if count(codes, codeMatch) != 0 || count(consents) != 0 {
				t.Fatal("failed signup policy changed approval or code storage")
			}
			setName("Custom")
			_, other := newHost("")
			signup(other, "other@signup.example", "Custom")
			_, err = other.DecideOAuthConsent(ctx, approval, true, []string{"reports"})
			problem(err, 400)
			target, err = sdk.DecideOAuthConsent(ctx, approval, true, []string{"reports"})
			must(err)
			custom := signedPage(target, "/finish")
			if count(codes, codeMatch) != 0 || count(consents) != 1 {
				t.Fatal("deferred approval must save the grant without issuing a code")
			}
			_, err = sdk.DecideOAuthConsent(ctx, approval, true, []string{"reports"})
			problem(err, 400)
			_, err = sdk.ContinueOAuthAccountSelection(ctx, custom)
			problem(err, 400)
			target, err = other.ContinueOAuthSignup(ctx, custom)
			must(err)
			signedPage(target, "/finish") // This host uses only the dynamic page.
			setName("Ready")
			target, err = sdk.ContinueOAuthSignup(ctx, custom)
			must(err)
			returned, err := url.Parse(target)
			must(err)
			if returned.Host != "reports.example.test" || returned.Query().Get("code") == "" || count(codes, codeMatch) != 1 {
				t.Fatal("completed owner did not receive an authorization code")
			}
		})
	}
}
