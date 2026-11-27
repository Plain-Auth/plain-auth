package sqlstore

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

// A pushed authorization request is resolved through the host callback:
// every parameter but client_id comes from the stored request, the signed
// login page carries the resolved values, and an unknown URI, a missing
// client or a failing resolver never reaches the client.
func TestPushedAuthorizationRequests(t *testing.T) {
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
			const callback = "https://app.example/cb"
			write(`INSERT INTO "oauthClient" ("id","clientId","applicationType","redirectUris","scopes","tokenEndpointAuthMethod","skipConsent") VALUES ('app','app','web',?,?,'none',?)`, `["`+callback+`"]`, `["reports","extra"]`, true)
			verifier := strings.Repeat("v", 64)
			sum := sha256.Sum256([]byte(verifier))
			var asked []string
			p, err := op.New(op.Options{Scopes: []string{"reports", "extra"}, Authorization: op.BrowserAuthorizationOptions{LoginPage: "/login",
				RequestURIResolver: func(_ context.Context, requestURI, clientID string) (url.Values, error) {
					asked = append(asked, requestURI+" "+clientID)
					switch requestURI {
					case "urn:par:fail":
						return nil, errors.New("pushed request store unavailable")
					case "urn:par:good":
						return url.Values{"response_type": {"code"}, "redirect_uri": {callback}, "scope": {"reports"}, "state": {"pushed"}, "client_id": {"ignored"},
							"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "request_uri": {"urn:par:loop"}}, nil
					}
					return nil, nil
				}}})
			must(err)
			const base = "https://issuer.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: base, Secret: strings.Repeat("t", 40), Plugins: []auth.Plugin{p}, Store: s, RateLimit: &off})
			must(err)
			authorize := func(q url.Values, signedIn bool) *httptest.ResponseRecorder {
				req := httptest.NewRequest("GET", base+"/api/auth/oauth2/authorize?"+q.Encode(), nil)
				if signedIn {
					req.AddCookie(h.SessionCookie("browser", true))
				}
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				return out
			}
			location := func(out *httptest.ResponseRecorder) *url.URL {
				t.Helper()
				u, err := url.Parse(out.Header().Get("Location"))
				must(err)
				if out.Code != 302 {
					t.Fatal("authorization did not redirect", out.Code, out.Body.String())
				}
				return u
			}
			// URL parameters other than client_id are ignored.
			pushed := url.Values{"client_id": {"app"}, "request_uri": {"urn:par:good"}, "scope": {"extra"}, "state": {"url"}, "redirect_uri": {"https://evil.example/cb"}}
			u := location(authorize(pushed, true))
			if u.Scheme+"://"+u.Host+u.Path != callback || u.Query().Get("state") != "pushed" || u.Query().Get("code") == "" {
				t.Fatal("a pushed request did not issue a code to its stored callback", u)
			}
			form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"app"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier}, "redirect_uri": {callback}}
			req := httptest.NewRequest("POST", base+"/api/auth/oauth2/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			out := httptest.NewRecorder()
			h.ServeHTTP(out, req)
			var token struct{ Scope string }
			must(json.Unmarshal(out.Body.Bytes(), &token))
			if out.Code != 200 || token.Scope != "reports" {
				t.Fatal("the code did not carry the stored scope", out.Code, out.Body.String())
			}
			// The login page signs the resolved request, so resuming never
			// asks the resolver again.
			asked = nil
			page := location(authorize(pushed, false))
			signed, err := h.VerifyOAuthPageQuery(page.RawQuery)
			must(err)
			if page.Path != "/login" || signed.Has("request_uri") || signed.Get("scope") != "reports" || signed.Get("client_id") != "app" || len(asked) != 1 {
				t.Fatal("the login page did not carry the resolved request", page, signed, asked)
			}
			refused := func(u *url.URL, code, description string) bool {
				return u.Host == "issuer.example.test" && u.Path == "/api/auth/error" && u.Query().Get("error") == code && u.Query().Get("error_description") == description
			}
			if u := location(authorize(url.Values{"client_id": {"app"}, "request_uri": {"urn:par:gone"}}, true)); !refused(u, "invalid_request_uri", "request_uri is invalid or expired") {
				t.Fatal("an unknown pushed request was not refused", u)
			}
			asked = nil
			if u := location(authorize(url.Values{"request_uri": {"urn:par:good"}}, true)); !refused(u, "invalid_request", "client_id is required") || len(asked) != 0 {
				t.Fatal("a pushed request without a client was resolved", u, asked)
			}
			if out := authorize(url.Values{"client_id": {"app"}, "request_uri": {"urn:par:fail"}}, true); out.Code != 500 {
				t.Fatal("a failing resolver did not stop authorization", out.Code, out.Body.String())
			}
			asked = nil
			if u := location(authorize(url.Values{"client_id": {"app"}, "request_uri": {"urn:par:good", "urn:par:gone"}}, true)); !refused(u, "invalid_request", "request_uri must not appear more than once") || len(asked) != 0 {
				t.Fatal("a repeated request_uri was resolved", u, asked)
			}
			location(authorize(url.Values{"client_id": {"app"}, "request_uri": {"urn:par:gone"}}, true))
			if len(asked) != 1 || asked[0] != "urn:par:gone app" {
				t.Fatal("the resolver did not receive the URI and the URL's client", asked)
			}
			// Without a resolver a pushed request is not supported.
			plainPlugin, err := op.New(op.Options{Scopes: []string{"reports", "extra"}, Authorization: op.BrowserAuthorizationOptions{LoginPage: "/login"}})
			must(err)
			plain, err := auth.New(auth.Options{BaseURL: base, Secret: strings.Repeat("t", 40), Plugins: []auth.Plugin{plainPlugin}, Store: s, RateLimit: &off})
			must(err)
			req = httptest.NewRequest("GET", base+"/api/auth/oauth2/authorize?"+url.Values{"client_id": {"app"}, "request_uri": {"urn:par:good"}}.Encode(), nil)
			out = httptest.NewRecorder()
			plain.ServeHTTP(out, req)
			if u := location(out); !refused(u, "request_uri_not_supported", "request_uri not supported") {
				t.Fatal("a pushed request without a resolver was not refused as unsupported", u)
			}
		})
	}
}
