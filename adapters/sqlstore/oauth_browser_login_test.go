package sqlstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/plugins/twofactor"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestBrowserLoginContinuation(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			s, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), []string{"oauth-provider", "two-factor"}, schema.Options{})
			must(err)
			t.Cleanup(func() { s.Close() })
			const base = "https://auth.example.test"
			const callback = "https://reports.example.test/callback"
			const secret = "local-browser-signin-0123456789-abcdefghijk"
			p, err := op.New(op.Options{Scopes: []string{"read"}, Authorization: op.BrowserAuthorizationOptions{LoginPage: "/login?lang=en", ConsentPage: "/approve"}})
			must(err)
			guard := auth.Plugin{ID: "test-host-policy", OnRequest: func(c auth.RequestContext) error {
				if c.Path == "/oauth2/authorize" && c.Request.Header.Get("X-Block-Authorize") != "" {
					return &auth.APIError{Status: 403, Code: "HOST_POLICY", Message: "Blocked by host"}
				}
				return nil
			}}
			off := false
			cfg := auth.Options{Store: s, Plugins: []auth.Plugin{p, twofactor.New(twofactor.Options{SkipVerificationOnEnable: true}), guard}, BaseURL: base, Secret: secret, RateLimit: &off, EmailAndPassword: true}
			h, err := auth.New(cfg)
			must(err)
			_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO "oauthClient" ("id","clientId","applicationType","redirectUris","tokenEndpointAuthMethod","scopes","skipConsent") VALUES ('row','app','web',?,'none',?,?)`), `["https://reports.example.test/callback"]`, `["read"]`, true)
			must(err)
			q := url.Values{"response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {callback}, "scope": {"read"}, "state": {"test-state"}, "prompt": {"login"}, "max_age": {"0"}, "code_challenge_method": {"S256"}, "code_challenge": {"challenge"}}
			start := func() string {
				w := httptest.NewRecorder()
				r := httptest.NewRequest("GET", base+"/api/auth/oauth2/authorize?"+q.Encode(), nil)
				h.ServeHTTP(w, r)
				page, err := url.Parse(w.Header().Get("Location"))
				must(err)
				if w.Code != 302 || page.Path != "/login" || page.Query().Get("lang") != "en" {
					t.Fatal("missing host login page", w.Code)
				}
				signed, err := h.VerifyOAuthPageQuery(page.RawQuery)
				must(err)
				if signed.Has("lang") {
					t.Fatal("unsigned host field reached continuation")
				}
				return signed.Encode()
			}
			post := func(host *auth.Auth, path string, body map[string]any, headers http.Header, prior *http.Cookie) *httptest.ResponseRecorder {
				raw, err := json.Marshal(body)
				must(err)
				r := httptest.NewRequest("POST", base+"/api/auth/"+path, bytes.NewReader(raw))
				r.Header = headers.Clone()
				if r.Header == nil {
					r.Header = make(http.Header)
				}
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", base)
				w := httptest.NewRecorder()
				if prior != nil {
					w.Header().Add("Set-Cookie", prior.String())
				}
				host.ServeHTTP(w, r)
				return w
			}
			browser, err := client.New(base, &http.Client{Transport: guestTransport{h}})
			must(err)
			const password = "a sufficiently long password"
			alice, err := browser.SignUpEmail(ctx, client.SignUpRequest{Name: "Alice", Email: "alice@example.test", Password: password})
			must(err)
			signed := start()
			bob, err := browser.SignUpEmail(ctx, client.SignUpRequest{Name: "Bob", Email: "bob@example.test", Password: password, OAuthQuery: signed})
			must(err)
			if !bob.Redirect || bob.URL == "" {
				t.Fatal("SDK did not receive an authorization redirect")
			}
			codeURL, err := url.Parse(bob.URL)
			must(err)
			if codeURL.Host != "reports.example.test" || codeURL.Query().Get("code") == "" || codeURL.Query().Get("state") != "test-state" {
				t.Fatal("missing code after signup")
			}
			who, err := browser.GetSession(ctx)
			must(err)
			var raw string
			sum := sha256.Sum256([]byte(codeURL.Query().Get("code")))
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "value" FROM "verification" WHERE "identifier"=?`), base64.RawURLEncoding.EncodeToString(sum[:])).Scan(&raw))
			var grant struct {
				UserID, SessionID string
				Query             map[string]string
			}
			must(json.Unmarshal([]byte(raw), &grant))
			if who == nil || who.User.ID == alice.User.ID || who.User.ID != grant.UserID || grant.SessionID != who.Session.ID || grant.Query["prompt"] != "" {
				t.Fatal("authorization used the prior browser account or stale prompt")
			}
			q.Set("prompt", "create")
			q.Del("max_age")
			signupQuery := start()
			if w := post(h, "oauth2/continue", map[string]any{"created": true, "oauth_query": signupQuery}, nil, nil); w.Code != 401 {
				t.Fatal("account creation continued without a browser session", w.Code)
			}
			if w := post(h, "oauth2/continue", map[string]any{"created": false, "oauth_query": signupQuery}, nil, nil); w.Code != 400 {
				t.Fatal("account creation accepted an unfinished step", w.Code)
			}
			location, err := browser.ContinueOAuthSignup(ctx, signupQuery)
			must(err)
			next, err := url.Parse(location)
			must(err)
			if next.Host != codeURL.Host || next.Query().Get("code") == "" || next.Query().Get("state") != q.Get("state") {
				t.Fatal("Go client did not continue the authenticated signup")
			}
			q.Set("prompt", "login")
			q.Set("max_age", "0")
			body := map[string]any{"email": "bob@example.test", "password": password, "oauth_query": start()}
			blocked := post(h, "sign-in/email", body, http.Header{"X-Block-Authorize": {"yes"}}, nil)
			if blocked.Code != 403 || !strings.Contains(blocked.Body.String(), "HOST_POLICY") {
				t.Fatal("resumed request bypassed issuer hook", blocked.Code)
			}
			nav := post(h, "sign-in/email", body, http.Header{"Accept": {"text/html"}}, nil)
			u, err := url.Parse(nav.Header().Get("Location"))
			must(err)
			if nav.Code != 302 || u.Host != "reports.example.test" || u.Query().Get("code") == "" {
				t.Fatal("browser navigation did not receive the application callback")
			}
			// Verification suppresses automatic sessions. An unrelated Set-Cookie
			// from outer middleware and an incoming session must not authorize Bob.
			noAuto := cfg
			noAuto.DisableAutoSignIn = true
			closed, err := auth.New(noAuto)
			must(err)
			old := h.SessionCookie(*alice.Token, true)
			pending := post(closed, "sign-up/email", map[string]any{"name": "Pending", "email": "pending@example.test", "password": password, "oauth_query": start()}, http.Header{"Cookie": {old.Name + "=" + old.Value}}, old)
			var withheld map[string]any
			must(json.Unmarshal(pending.Body.Bytes(), &withheld))
			if pending.Code != 200 || withheld["url"] != nil || withheld["token"] != nil || withheld["user"] == nil {
				t.Fatal("signup without a new session resumed authorization")
			}
			factors, err := browser.EnableTOTP(ctx, password, "Example")
			must(err)
			signed = start()
			initial, err := browser.SignInEmail(ctx, client.SignInRequest{Email: "bob@example.test", Password: password, OAuthQuery: signed})
			must(err)
			if !initial.TwoFactorRedirect || initial.URL != "" {
				t.Fatal("primary password bypassed the pending second factor")
			}
			var verified struct{ URL string }
			err = browser.Do(ctx, "POST", "/two-factor/verify-backup-code", map[string]any{"code": factors.BackupCodes[0], "oauth_query": signed}, &verified)
			must(err)
			u, err = url.Parse(verified.URL)
			must(err)
			if u.Query().Get("code") == "" {
				t.Fatal("verified second factor failed to resume authorization")
			}
			// Re-entering an authorization route disabled by an instance's host
			// must still see the disabled path even with a valid signed login.
			signed = start()
			disabled := cfg
			disabled.DisabledPaths = []string{"/oauth2/authorize"}
			stopped, err := auth.New(disabled)
			must(err)
			body = map[string]any{"email": "alice@example.test", "password": password, "oauth_query": signed}
			if w := post(stopped, "sign-in/email", body, nil, nil); w.Code != 404 {
				t.Fatal("resumed a disabled authorization route", w.Code)
			}
			fields, err := h.VerifyOAuthQuery(signed)
			must(err)
			body["oauth_query"] = h.SignOAuthQuery(fields, time.Now().Add(-time.Second))
			if w := post(h, "sign-in/email", body, nil, nil); w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_signature") || len(w.Header().Values("Set-Cookie")) != 0 {
				t.Fatal("expired query reached credential handling")
			}
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "oauthClient" SET "id"='replacement' WHERE "id"='row'`))
			must(err)
			body["oauth_query"] = signed
			replaced := post(h, "sign-in/email", body, nil, nil)
			var local struct{ URL string }
			must(json.Unmarshal(replaced.Body.Bytes(), &local))
			u, err = url.Parse(local.URL)
			must(err)
			if u.Path != "/api/auth/error" || u.Query().Get("error") != "invalid_client" || u.Query().Has("code") {
				t.Fatal("replaced application inherited the original signed request")
			}
		})
	}
}
