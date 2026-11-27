package sqlstore

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// Authorization checks only the redirect's HTTPS policy before the
// registered match, as another runtime does, so a stored HTTPS loopback or
// path-less custom-scheme callback works. ValidateRedirectURI runs only for
// a callback whose syntax is safe and fails closed.
func TestAuthorizeRedirectTransport(t *testing.T) {
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
			write := func(q string, args ...any) {
				t.Helper()
				_, err := s.db.ExecContext(ctx, s.bind(q), args...)
				must(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			write(`INSERT INTO "user" ("id","name","email","emailVerified","createdAt","updatedAt") VALUES ('owner','Owner','owner@example.test',?,?,?)`, true, s.date(now), s.date(now))
			write(`INSERT INTO "session" ("id","userId","token","createdAt","updatedAt","expiresAt") VALUES ('sid','owner','browser',?,?,?)`, s.date(now), s.date(now), s.date(now.Add(time.Hour)))
			for _, c := range []struct{ id, app, uri string }{
				{"web-local", "web", "https://localhost/cb"}, {"native-custom", "native", "myapp:callback"},
				{"web-http", "web", "http://localhost:3000/cb"}, {"native-loop", "native", "http://127.0.0.1/cb"},
				{"web-intranet", "web", "http://intranet.example/cb"}, {"web-hook", "web", "https://app.example/cb"},
			} {
				write(`INSERT INTO "oauthClient" ("id","clientId","applicationType","redirectUris","scopes","tokenEndpointAuthMethod","skipConsent") VALUES (?,?,?,?,?,'none',?)`, c.id, c.id, c.app, `["`+c.uri+`"]`, `["reports"]`, true)
			}
			var hook func(string) (bool, error)
			var hooked []string
			const base = "https://issuer.example.test"
			host := func(withHook bool) *auth.Auth {
				t.Helper()
				opts := op.Options{Scopes: []string{"reports"}, Registration: op.RegistrationOptions{AllowHTTPRedirect: func(u *url.URL) bool { return u.Hostname() == "localhost" }}}
				if withHook {
					opts.Authorization.ValidateRedirectURI = func(_ context.Context, uri string, _ []string, _ bool) (bool, error) {
						hooked = append(hooked, uri)
						return hook(uri)
					}
				}
				p, err := op.New(opts)
				must(err)
				off := false
				h, err := auth.New(auth.Options{BaseURL: base, Secret: strings.Repeat("t", 40), Plugins: []auth.Plugin{p}, Store: s, RateLimit: &off})
				must(err)
				return h
			}
			plain, checked := host(false), host(true)
			sum := sha256.Sum256([]byte(strings.Repeat("v", 64)))
			authorize := func(h *auth.Auth, client, uri string) *url.URL {
				t.Helper()
				q := url.Values{"client_id": {client}, "response_type": {"code"}, "redirect_uri": {uri}, "prompt": {"none"}, "state": {"saved"},
					"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
				req := httptest.NewRequest("GET", base+"/api/auth/oauth2/authorize?"+q.Encode(), nil)
				req.AddCookie(h.SessionCookie("browser", true))
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				u, err := url.Parse(out.Header().Get("Location"))
				must(err)
				if out.Code != 302 {
					t.Fatal("authorization did not redirect", client, uri, out.Code, out.Body.String())
				}
				return u
			}
			issued := func(u *url.URL, uri string) bool {
				return strings.HasPrefix(u.String(), uri+"?") && u.Query().Get("code") != "" && u.Query().Get("state") == "saved"
			}
			refused := func(u *url.URL, code, description string) bool {
				return u.Host == "issuer.example.test" && u.Path == "/api/auth/error" && u.Query().Get("error") == code &&
					(description == "" || u.Query().Get("error_description") == description)
			}
			const insecure = "Redirect URI must use HTTPS (HTTP allowed only for loopback hosts)"
			for _, tc := range []struct{ client, uri string }{
				{"web-local", "https://localhost/cb"}, {"native-custom", "myapp:callback"},
				{"web-http", "http://localhost:3000/cb"}, {"native-loop", "http://127.0.0.1:5555/cb"},
			} {
				if u := authorize(plain, tc.client, tc.uri); !issued(u, tc.uri) {
					t.Fatal("a registered callback did not receive a code", tc.client, tc.uri, u)
				}
			}
			if u := authorize(plain, "web-http", "http://localhost:3001/cb"); !refused(u, "invalid_redirect", "") {
				t.Fatal("a web client's callback matched another port", u)
			}
			if u := authorize(plain, "native-loop", "http://localhost:5555/cb"); !refused(u, "invalid_redirect", "") {
				t.Fatal("a native loopback callback matched another loopback host name", u)
			}
			if u := authorize(plain, "web-intranet", "http://intranet.example/cb"); !refused(u, "invalid_request", insecure) {
				t.Fatal("an HTTP callback on a public host passed the transport check", u)
			}
			// The hook decides for a safe callback, never for an insecure or
			// malformed one, and an error fails closed.
			hook = func(string) (bool, error) { return true, nil }
			for _, uri := range []string{"https://127.0.0.1/cb", "myapp:callback"} {
				if u := authorize(checked, "web-hook", uri); !issued(u, uri) {
					t.Fatal("a callback the hook accepted did not receive a code", uri, u)
				}
			}
			hooked = nil
			if u := authorize(checked, "web-hook", "http://intranet.example/cb"); !refused(u, "invalid_request", insecure) || len(hooked) != 0 {
				t.Fatal("the hook overrode the HTTPS policy", u, hooked)
			}
			for _, uri := range []string{"https://app.example/cb#part", "https://user@app.example/cb", "javascript:alert(1)"} {
				if u := authorize(checked, "web-hook", uri); !refused(u, "invalid_redirect", "") || len(hooked) != 0 {
					t.Fatal("the hook judged an unsafe callback", uri, u, hooked)
				}
			}
			hook = func(string) (bool, error) { return true, errors.New("lookup failed") }
			if u := authorize(checked, "web-hook", "https://app.example/cb"); !refused(u, "invalid_redirect", "") || len(hooked) != 1 {
				t.Fatal("a failing hook did not fail closed", u, hooked)
			}
		})
	}
}
