package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestOAuthRememberedAccountSelection(t *testing.T) {
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
			const origin = "https://accounts.example.test"
			const callback = "https://app.example.test/callback"
			const password = "choose a remembered browser account"
			policyChecks := 0
			policy := op.AccountSelectionOptions{
				Page: "/choose?display=compact",
				ShouldRedirect: func(_ context.Context, a op.RegistrationAccess, scopes []string) (bool, error) {
					policyChecks++
					if a.User.ID != a.Session.UserID || a.User.ID == "" || a.Headers.Get("Cookie") == "" || !slices.Equal(scopes, []string{"reports"}) {
						t.Fatal("host selection policy lost its account, headers or scopes")
					}
					return true, nil
				},
			}
			multi, err := auth.NewMultiSession(auth.MultiSessionOptions{})
			must(err)
			newHost := func(selectAccount op.AccountSelectionOptions) (*auth.Auth, *client.Client) {
				t.Helper()
				oauth, err := op.New(op.Options{Scopes: []string{"reports"}, Authorization: op.BrowserAuthorizationOptions{
					LoginPage: "/login", ConsentPage: "/consent", SelectAccount: selectAccount,
				}})
				must(err)
				off := false
				h, err := auth.New(auth.Options{BaseURL: origin, Secret: "account-selection-local-0123456789-abcdefghijk", EmailAndPassword: true, Store: s, RateLimit: &off, Plugins: []auth.Plugin{oauth, multi}})
				must(err)
				sdk, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
				must(err)
				return h, sdk
			}
			h, sdk := newHost(policy)
			_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO "oauthClient" ("id","clientId","applicationType","redirectUris","tokenEndpointAuthMethod","scopes") VALUES ('registered','app','web',?,'none',?)`), `["https://app.example.test/callback"]`, `["reports"]`)
			must(err)
			start := func(browser *client.Client, prompt string) *url.URL {
				t.Helper()
				q := url.Values{"response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {callback}, "scope": {"reports"},
					"state": {"chosen"}, "code_challenge": {"challenge"}, "code_challenge_method": {"S256"}}
				if prompt != "" {
					q.Set("prompt", prompt)
				}
				var result struct{ URL string }
				must(browser.Do(ctx, "GET", "/oauth2/authorize?"+q.Encode(), nil, &result))
				dest, err := url.Parse(result.URL)
				must(err)
				return dest
			}
			_, noChooser := newHost(op.AccountSelectionOptions{})
			unsupported := start(noChooser, "select_account")
			if unsupported.Path != "/api/auth/error" || unsupported.Query().Get("error") != "unsupported_prompt_select_account" || unsupported.Query().Has("state") {
				t.Fatal("unsupported explicit prompt left the issuer error page")
			}
			alice, err := sdk.SignUpEmail(ctx, client.SignUpRequest{Name: "Alice", Email: "alice@chooser.test", Password: password})
			must(err)
			bob, err := sdk.SignUpEmail(ctx, client.SignUpRequest{Name: "Bob", Email: "bob@chooser.test", Password: password})
			must(err)
			accounts, err := sdk.ListDeviceSessions(ctx)
			must(err)
			if len(accounts) != 2 {
				t.Fatal("missing remembered accounts", len(accounts))
			}
			chooser := start(sdk, "select_account consent")
			if chooser.Path != "/choose" || chooser.Query().Get("display") != "compact" || policyChecks != 0 {
				t.Fatal("explicit prompt did not go directly to the configured chooser")
			}
			fields, err := h.VerifyOAuthPageQuery(chooser.RawQuery)
			must(err)
			signed := fields.Encode()
			newActive, err := sdk.SetActiveSession(ctx, *alice.Token)
			must(err)
			if newActive.User.ID != alice.User.ID || newActive.User.ID == bob.User.ID {
				t.Fatal("multi-session did not activate the chosen account")
			}
			if _, err := sdk.ContinueOAuthSignup(ctx, signed); err == nil {
				t.Fatal("chooser query accepted by the signup continuation")
			}
			if _, err := sdk.ContinueOAuthAccountSelection(ctx, h.SignOAuthQuery(fields, time.Now().Add(-time.Second))); err == nil {
				t.Fatal("accepted an expired chooser")
			}
			target, err := sdk.ContinueOAuthAccountSelection(ctx, signed)
			must(err)
			consent, err := url.Parse(target)
			must(err)
			if consent.Path != "/consent" || consent.Query().Get("prompt") != "consent" || policyChecks != 0 {
				t.Fatal("selection looped or lost forced consent")
			}
			approved, err := h.VerifyOAuthPageQuery(consent.RawQuery)
			must(err)
			target, err = sdk.DecideOAuthConsent(ctx, approved.Encode(), true, nil)
			must(err)
			redirect, err := url.Parse(target)
			must(err)
			if redirect.Query().Get("code") == "" || redirect.Query().Get("state") != "chosen" || policyChecks != 0 {
				t.Fatal("consent did not finish for the chosen account")
			}
			var owner string
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "userId" FROM "oauthConsent" WHERE "clientId"=?`), "app").Scan(&owner))
			if owner != alice.User.ID {
				t.Fatal("grant was not saved for the chosen account")
			}
			if silent := start(sdk, "none"); silent.Query().Get("error") != "account_selection_required" || policyChecks != 1 {
				t.Fatal("silent requests bypassed host account selection")
			}
			chooser = start(sdk, "")
			if chooser.Path != "/choose" || policyChecks != 2 {
				t.Fatal("host policy did not open the chooser")
			}
			fields, err = h.VerifyOAuthPageQuery(chooser.RawQuery)
			must(err)
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "oauthClient" SET "id"='recreated' WHERE "id"='registered'`))
			must(err)
			target, err = sdk.ContinueOAuthAccountSelection(ctx, fields.Encode())
			must(err)
			redirect, err = url.Parse(target)
			must(err)
			if redirect.Path != "/api/auth/error" || redirect.Query().Get("error") != "invalid_client" || policyChecks != 2 {
				t.Fatal("recreated client inherited the chooser")
			}
			policy.Page = ""
			_, fallback := newHost(policy)
			_, err = fallback.SignInEmail(ctx, client.SignInRequest{Email: "alice@chooser.test", Password: password})
			must(err)
			if u := start(fallback, ""); u.Path != "/login" || policyChecks != 3 {
				t.Fatal("implicit chooser did not fall back to the host login page")
			}
			policy.ShouldRedirect = func(context.Context, op.RegistrationAccess, []string) (bool, error) {
				return false, errors.New("selection policy failed")
			}
			_, failing := newHost(policy)
			_, err = failing.SignInEmail(ctx, client.SignInRequest{Email: "alice@chooser.test", Password: password})
			must(err)
			err = failing.Do(ctx, "GET", "/oauth2/authorize?response_type=code&client_id=app&scope=reports&redirect_uri="+url.QueryEscape(callback)+"&code_challenge=challenge&code_challenge_method=S256", nil, nil)
			var api *auth.APIError
			if !errors.As(err, &api) || api.Status != 500 {
				t.Fatal("host policy error did not stop authorization", err)
			}
		})
	}
}
