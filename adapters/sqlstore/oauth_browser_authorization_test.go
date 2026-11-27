package sqlstore

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestBrowserAuthorization(t *testing.T) {
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
			open := func() *Store {
				t.Helper()
				s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
				must(err)
				t.Cleanup(func() { s.Close() })
				return s
			}
			s, peer := open(), open()
			write := func(q string, args ...any) {
				t.Helper()
				_, err := peer.db.ExecContext(ctx, peer.bind(q), args...)
				must(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			deadline := s.date(now.Add(time.Hour))
			write(`INSERT INTO "user" ("id","name","email","emailVerified","createdAt","updatedAt") VALUES ('owner','Owner','owner@example.test',?,?,?)`, true, s.date(now), s.date(now))
			write(`INSERT INTO "session" ("id","userId","token","createdAt","updatedAt","expiresAt") VALUES ('sid','owner','browser',?,?,?)`, s.date(now), s.date(now), deadline)
			const callbacks = `["http://127.0.0.1:3000/cb"]`
			for _, client := range []string{"app", "other"} {
				write(`INSERT INTO "oauthClient" ("id","clientId","applicationType","redirectUris","scopes","tokenEndpointAuthMethod","skipConsent") VALUES (?,?,'native',?,?,'none',?)`, client, client, callbacks, `["reports"]`, false)
			}
			write(`INSERT INTO "oauthConsent" ("id","clientId","userId","referenceId","scopes","createdAt","updatedAt") VALUES ('approval','app','owner','team',?,?,?)`, `["reports"]`, s.date(now), s.date(now))
			var onHash func()
			var redirectCheck func(string, []string, bool) (bool, error)
			var fixed bool
			digest := func(raw string) string {
				sum := sha256.Sum256([]byte(raw))
				return base64.RawURLEncoding.EncodeToString(sum[:])
			}
			p, err := op.New(op.Options{Scopes: []string{"reports"}, Authorization: op.BrowserAuthorizationOptions{
				CodeLifetime: 43 * time.Second,
				ValidateRedirectURI: func(_ context.Context, uri string, list []string, match bool) (bool, error) {
					if redirectCheck != nil {
						return redirectCheck(uri, list, match)
					}
					return match, nil
				},
				ConsentReference: func(_ context.Context, a op.RegistrationAccess, _ []string) (string, error) {
					if a.User.ID != "owner" {
						return "", auth.ErrNotFound
					}
					return "team", nil
				},
			}, Tokens: op.TokenOptions{HashAuthorizationCode: func(_ context.Context, raw string) (string, error) {
				if onHash != nil {
					onHash()
				}
				if fixed {
					return "fixed", nil
				}
				return "code-" + digest(raw), nil
			}}})
			must(err)
			const base = "https://issuer.example.test"
			host := func(s *Store) *auth.Auth {
				t.Helper()
				off := false
				h, err := auth.New(auth.Options{BaseURL: base, Secret: strings.Repeat("t", 40), Plugins: []auth.Plugin{p}, Store: s, RateLimit: &off})
				must(err)
				return h
			}
			h1, h2 := host(s), host(peer)
			const callback = "http://127.0.0.1:41234/cb"
			verifier := strings.Repeat("v", 64)
			callWithURI := func(h *auth.Auth, client, uri string) *httptest.ResponseRecorder {
				q := url.Values{"client_id": {client}, "response_type": {"code"}, "redirect_uri": {uri}, "prompt": {"none"}, "state": {"saved"}, "code_challenge": {digest(verifier)}, "code_challenge_method": {"S256"}}
				req := httptest.NewRequest("GET", base+"/api/auth/oauth2/authorize?"+q.Encode(), nil)
				req.AddCookie(h.SessionCookie("browser", true))
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				return out
			}
			call := func(h *auth.Auth, client string) *httptest.ResponseRecorder { return callWithURI(h, client, callback) }
			check := func(out *httptest.ResponseRecorder, code string, local bool) string {
				t.Helper()
				u, err := url.Parse(out.Header().Get("Location"))
				must(err)
				if out.Code != 302 || u.Query().Get("error") != code {
					t.Fatalf("unexpected authorize result: HTTP %d code %q", out.Code, u.Query().Get("error"))
				}
				if local {
					if u.Host != "issuer.example.test" || u.Path != "/api/auth/error" || u.Query().Has("state") {
						t.Fatal("untrusted client selected error destination")
					}
				} else if u.Host != "127.0.0.1:41234" || u.Path != "/cb" || u.Query().Get("state") != "saved" || u.Query().Get("iss") != base+"/api/auth" {
					t.Fatal("lost verified callback, state or issuer")
				}
				if (u.Query().Get("code") == "") != (code != "") {
					t.Fatal("unexpected authorization code presence")
				}
				return u.Query().Get("code")
			}
			onHash = func() {
				write(`UPDATE "oauthClient" SET "redirectUris"=? WHERE "clientId"='app'`, `["https://changed.example.test/cb"]`)
			}
			check(call(h1, "app"), "invalid_client", true)
			write(`UPDATE "oauthClient" SET "redirectUris"=? WHERE "clientId"='app'`, callbacks)
			onHash = func() { write(`UPDATE "oauthConsent" SET "referenceId"='other' WHERE "id"='approval'`) }
			check(call(h1, "app"), "consent_required", false)
			write(`UPDATE "oauthConsent" SET "referenceId"='team' WHERE "id"='approval'`)
			onHash = func() { write(`UPDATE "session" SET "expiresAt"=? WHERE "id"='sid'`, s.date(now)) }
			check(call(h1, "app"), "login_required", false)
			write(`UPDATE "session" SET "expiresAt"=? WHERE "id"='sid'`, deadline)
			onHash = nil
			var rows int
			must(peer.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+s.bind(`"verification"`)).Scan(&rows))
			if rows != 0 {
				t.Fatal("failed authorization persisted a verification record")
			}
			code := check(call(h1, "app"), "", false)
			var start, end time.Time
			var raw []byte
			must(peer.db.QueryRowContext(ctx, s.bind(`SELECT "createdAt","expiresAt","value" FROM "verification" WHERE "identifier"=?`), "code-"+digest(code)).Scan(&start, &end, &raw))
			var value struct {
				UserID, SessionID, ReferenceID string
				AuthTime                       int64
				Query                          map[string]string
			}
			must(json.Unmarshal(raw, &value))
			if end.Sub(start) != 43*time.Second || value.AuthTime != now.UnixMilli() || value.ReferenceID != "team" || value.UserID != "owner" || value.SessionID != "sid" || value.Query["redirect_uri"] != callback || value.Query["scope"] != "reports" {
				t.Fatal("stored code lost lifetime, scope, or bound browser context")
			}
			form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"app"}, "redirect_uri": {callback}, "code": {code}, "code_verifier": {verifier}}
			req := httptest.NewRequest("POST", base+"/api/auth/oauth2/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			out := httptest.NewRecorder()
			h2.ServeHTTP(out, req)
			if out.Code != 200 {
				t.Fatalf("peer failed to redeem code: HTTP %d", out.Code)
			}
			const alternate = "https://desktop.example.test/return"
			redirectCheck = func(uri string, registered []string, match bool) (bool, error) {
				if !slices.Equal(registered, []string{"http://127.0.0.1:3000/cb"}) {
					t.Fatal("redirect validator lost registered callbacks")
				}
				if uri == alternate && !match {
					return true, nil
				}
				if uri == callback && match {
					return true, auth.ErrNotFound
				}
				t.Fatal("unsafe or unexpected URI reached redirect validator")
				return false, nil
			}
			alternateResult := callWithURI(h1, "app", alternate)
			alternateURL, err := url.Parse(alternateResult.Header().Get("Location"))
			must(err)
			if alternateResult.Code != 302 || alternateURL.Host != "desktop.example.test" || alternateURL.Query().Get("code") == "" {
				t.Fatal("host-approved redirect did not receive the code")
			}
			check(call(h1, "app"), "invalid_redirect", true)
			// A callback with credentials passes the HTTPS policy but never
			// reaches the validator, so it fails the match.
			check(callWithURI(h1, "app", "https://user@example.test/cb"), "invalid_redirect", true)
			redirectCheck = nil
			// Operator-approved clients still need a browser session and valid PKCE.
			write(`UPDATE "oauthClient" SET "skipConsent"=? WHERE "clientId"='other'`, true)
			check(call(h2, "other"), "", false)
			fixed = true
			results := make(chan int, 2)
			for i, h := range []*auth.Auth{h1, h2} {
				id := []string{"app", "other"}[i]
				go func() { results <- call(h, id).Code }()
			}
			status := []int{<-results, <-results}
			slices.Sort(status)
			if !slices.Equal(status, []int{302, 500}) {
				t.Fatal("two nodes issued colliding codes", status)
			}
			must(peer.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "verification" WHERE "identifier"=?`), "fixed").Scan(&rows))
			if rows != 1 {
				t.Fatal("collision replaced the original grant")
			}
		})
	}
}

func TestBrowserAuthorizationRateLimit(t *testing.T) {
	s, err := OpenWithOptions(t.Context(), "sqlite", organizationTestDSN(t, "sqlite"), []string{"oauth-provider"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	for _, tc := range []struct {
		name string
		rule *auth.RateLimitRule
		max  int
	}{
		{"default", nil, 30}, {"custom", &auth.RateLimitRule{Window: time.Minute, Max: 2}, 2}, {"host", &auth.RateLimitRule{}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := op.New(op.Options{Authorization: op.BrowserAuthorizationOptions{RateLimit: tc.rule}})
			if err != nil {
				t.Fatal(err)
			}
			const base = "https://authorize.example.test"
			h, err := auth.New(auth.Options{BaseURL: base, Secret: strings.Repeat("t", 40), Plugins: []auth.Plugin{p}, Store: s, RateLimitDefault: &auth.RateLimitRule{Window: time.Minute, Max: 3}})
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i <= tc.max; i++ {
				method := []string{"GET", "POST"}[i%2]
				r := httptest.NewRequest(method, base+"/api/auth/oauth2/authorize", nil)
				r.Header.Set("Origin", base)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if i < tc.max && w.Code != 302 || i == tc.max && (w.Code != 429 || w.Header().Get("X-Retry-After") == "") {
					t.Fatalf("request %d %s returned %d", i, method, w.Code)
				}
			}
		})
	}
}
