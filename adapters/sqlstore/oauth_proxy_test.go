package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/oauthproxy"
	"github.com/Plain-Org/plain-auth/schema"
	"golang.org/x/oauth2"
)

func proxyRequest(t *testing.T, host *auth.Auth, method, target string, body map[string]any, cookies []*http.Cookie, want int) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, target, bytes.NewReader(raw))
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", r.URL.Scheme+"://"+r.Host)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	host.ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("%s %s: got %d, want %d: %s", method, r.URL.Path, w.Code, want, w.Body.String())
	}
	return w
}

func TestOAuthProxyAcrossDeployments(t *testing.T) {
	const preview = "https://review.example.test"
	const production = "https://identity.example.test"
	const mount = "/identity"
	t.Setenv("AUTH_URL", "")
	const secret = "dedicated shared secret for a local preview"
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			issuer := newProfileIssuer(t)
			issuer.set("member", map[string]any{"locale": "fr"})
			configure := func(origin string) (*auth.Auth, *Store) {
				t.Helper()
				opts := oauthproxy.Options{ProductionURL: production, CurrentURL: origin, Secret: secret}
				if origin == production {
					opts.ProductionURL = "" // The instance public URL is the registered origin.
				}
				provider := issuer.provider()
				provider.RequireEmailVerification = origin == production
				provider.GetAccountFields = func(context.Context, auth.OAuthAccountFieldInput) (map[string]any, error) {
					return nil, errors.New("proxy invoked the provider account mapper")
				}
				resolve := provider.Resolve
				provider.Resolve = func(ctx context.Context, token *oauth2.Token, nonce string) (auth.OAuthProfile, error) {
					profile, err := resolve(ctx, token, nonce)
					profile.EmailVerified = profile.Subject != "unverified"
					domain := "social.test"
					if profile.Subject == "outsider" {
						domain = "elsewhere.test"
					}
					profile.Data = map[string]any{"hd": domain}
					return profile, err
				}
				var fields map[string]auth.UserField
				if origin == preview {
					// The preview has a public client ID and no provider secret.
					provider.GoogleHostedDomain = "social.test"
					provider.Config.ClientSecret = ""
					provider.ExchangeCode = func(context.Context, oauth2.Config, string, string, url.Values) (*oauth2.Token, error) {
						return nil, errors.New("preview attempted provider exchange")
					}
					fields = map[string]auth.UserField{"locale": {Type: auth.FieldString, Required: true}}
				}
				plugin, err := oauthproxy.New(opts)
				if err != nil {
					t.Fatal(err)
				}
				db, err := OpenWithAdditionalFields(t.Context(), dialect, organizationTestDSN(t, dialect), nil, schema.AdditionalFields{User: fields})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { db.Close() })
				off := false
				host, err := auth.New(auth.Options{Store: db, BaseURL: origin, BasePath: mount, Secret: "a separate environment credential " + origin, TrustedOrigins: []string{preview}, Plugins: []auth.Plugin{plugin}, RateLimit: &off, EmailAndPassword: true, SocialProviders: map[string]auth.OAuthProvider{"google": provider}, UserAdditionalFields: fields})
				if err != nil {
					t.Fatal(err)
				}
				return host, db
			}
			origin, previewStore := configure(preview)
			prod, prodStore := configure(production)
			begin := func(path string, session []*http.Cookie) (*url.URL, []*http.Cookie) {
				t.Helper()
				w := proxyRequest(t, origin, "POST", preview+mount+path, map[string]any{"provider": "google", "disableRedirect": true, "callbackURL": "/return", "newUserCallbackURL": "/welcome", "errorCallbackURL": "/error"}, session, 200)
				var resp struct{ URL string }
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatal(err)
				}
				authURL, err := url.Parse(resp.URL)
				if err != nil {
					t.Fatal(err)
				}
				if authURL.Query().Get("redirect_uri") != production+mount+"/callback/google" || authURL.Query().Get("code_challenge") == "" {
					t.Fatal("authorization used incorrect production callback or PKCE")
				}
				approve := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
				approved, err := approve.Get(authURL.String())
				if err != nil {
					t.Fatal(err)
				}
				approved.Body.Close()
				callback, err := approved.Location()
				if err != nil {
					t.Fatal(err)
				}
				return callback, append(w.Result().Cookies(), session...)
			}
			relay := func(callback *url.URL) *url.URL {
				t.Helper()
				w := proxyRequest(t, prod, "GET", callback.String(), nil, nil, 302)
				if len(w.Result().Cookies()) != 0 {
					t.Fatal("production issued a browser credential")
				}
				target, err := url.Parse(w.Header().Get("Location"))
				if err != nil {
					t.Fatal(err)
				}
				if target.Scheme+"://"+target.Host != preview || target.Path != mount+"/callback/google/oauth-proxy" || target.Query().Get("profile") == "" || w.Header().Get("Referrer-Policy") != "no-referrer" {
					t.Fatal("unexpected return path")
				}
				return target
			}
			for _, direct := range []struct {
				handler *auth.Auth
				origin  string
				skip    bool
			}{{prod, production, false}, {origin, preview, true}} {
				req := httptest.NewRequest("POST", direct.origin+mount+"/sign-in/social", strings.NewReader(`{"provider":"google","disableRedirect":true}`))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", direct.origin)
				if direct.skip {
					req.Header.Set("X-Skip-OAuth-Proxy", "1")
				}
				rec := httptest.NewRecorder()
				direct.handler.ServeHTTP(rec, req)
				var start struct{ URL string }
				if err := json.Unmarshal(rec.Body.Bytes(), &start); err != nil {
					t.Fatal(err)
				}
				location, err := url.Parse(start.URL)
				if err != nil || rec.Code != 200 || location.Query().Get("redirect_uri") != direct.origin+mount+"/callback/google" {
					t.Fatal("direct OAuth origin was not preserved", rec.Code, err)
				}
			}
			callback, browser := begin("/sign-in/social", nil)
			form := httptest.NewRequest("POST", production+mount+"/callback/google", strings.NewReader(callback.Query().Encode()))
			form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			prod.ServeHTTP(response, form)
			posted, err := url.Parse(response.Header().Get("Location"))
			if err != nil || response.Code != 302 || posted.String() != callback.String() {
				t.Fatal("form POST changed the registered callback")
			}
			target := relay(posted)
			if r := proxyRequest(t, origin, "GET", target.String(), nil, nil, 302); r.Header().Get("Location") != mount+"/error?error=state_mismatch" {
				t.Fatal("missing browser binding was accepted")
			}
			other := *target
			other.Path = mount + "/callback/other/oauth-proxy"
			if r := proxyRequest(t, origin, "GET", other.String(), nil, browser, 302); r.Header().Get("Location") != mount+"/error?error=provider_mismatch" {
				t.Fatal("provider mismatch was accepted")
			}
			w := proxyRequest(t, origin, "GET", target.String(), nil, browser, 302)
			if w.Header().Get("Location") != "/welcome" {
				t.Fatal("first registration landing", w.Header().Get("Location"))
			}
			if r := proxyRequest(t, origin, "GET", target.String(), nil, browser, 302); r.Header().Get("Location") != mount+"/error?error=state_mismatch" {
				t.Fatal("spent state was accepted")
			}
			var session []*http.Cookie
			for _, c := range w.Result().Cookies() {
				if c.MaxAge >= 0 {
					session = append(session, c)
				}
			}
			w = proxyRequest(t, origin, "GET", preview+mount+"/get-session", nil, session, 200)
			var view auth.SessionResult
			if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
				t.Fatal(err)
			}
			if field, ok := view.User.AdditionalField("locale"); !ok || field != "fr" || view.User.Email != "member@social.test" {
				t.Fatal("preview did not project the authenticated profile")
			}
			if _, err := prodStore.FindAccountUser(t.Context(), "member@social.test"); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("production unexpectedly has this account", err)
			}
			if rows, err := previewStore.ListSessions(t.Context(), view.User.ID); err != nil || len(rows) != 1 {
				t.Fatal("unexpected preview session count", len(rows), err)
			}

			// Returning sign-in also accepts the unqualified completion URL.
			callback, browser = begin("/sign-in/social", nil)
			target = relay(callback)
			target.Path = mount + "/oauth-proxy-callback"
			w = proxyRequest(t, origin, "GET", target.String(), nil, browser, 302)
			if w.Header().Get("Location") != "/return" {
				t.Fatal("returning login landing")
			}
			issuer.set("second", nil)
			callback, browser = begin("/link-social", session)
			target = relay(callback)
			w = proxyRequest(t, origin, "GET", target.String(), nil, browser, 302)
			if w.Header().Get("Location") != "/error?error=account_not_linked" {
				t.Fatal("link did not enforce the existing owner's email policy")
			}
			issuer.mu.Lock()
			issuer.identity.Email = "member@social.test"
			issuer.mu.Unlock()
			callback, browser = begin("/link-social", session)
			w = proxyRequest(t, origin, "GET", relay(callback).String(), nil, browser, 302)
			if w.Header().Get("Location") != "/return" {
				t.Fatal("link landing", w.Header().Get("Location"))
			}
			for _, cookie := range w.Result().Cookies() {
				if cookie.MaxAge >= 0 {
					t.Fatal("link issued another session")
				}
			}
			accounts, err := previewStore.ListUserAccounts(t.Context(), view.User.ID)
			if err != nil || len(accounts) != 2 {
				t.Fatal("expected both identities on the same preview account", len(accounts), err)
			}
			callback, browser = begin("/sign-in/social", nil)
			q := callback.Query()
			q.Del("code")
			q.Set("error", "access_denied")
			callback.RawQuery = q.Encode()
			w = proxyRequest(t, origin, "GET", relay(callback).String(), nil, browser, 302)
			if w.Header().Get("Location") != "/error?error=access_denied" {
				t.Fatal("authorization refusal lost the configured error URL")
			}
			issuer.set("outsider", map[string]any{"locale": "en"})
			callback, browser = begin("/sign-in/social", nil)
			w = proxyRequest(t, origin, "GET", relay(callback).String(), nil, browser, 401)
			if !strings.Contains(w.Body.String(), "INVALID_TOKEN") {
				t.Fatal("preview accepted a different hosted domain")
			}
			issuer.set("unverified", map[string]any{"locale": "en"})
			callback, browser = begin("/sign-in/social", nil)
			w = proxyRequest(t, origin, "GET", relay(callback).String(), nil, browser, 302)
			if w.Header().Get("Location") != "/error?error=email_not_verified" {
				t.Fatal("preview bypassed the production mailbox policy")
			}
			pending, err := previewStore.FindAccountUser(t.Context(), "unverified@social.test")
			if err != nil || pending.EmailVerified {
				t.Fatal("preview failed to retain the unverified account", err)
			}
			if rows, err := previewStore.ListSessions(t.Context(), pending.ID); err != nil || len(rows) != 0 {
				t.Fatal("preview created a session before verification", err)
			}
		})
	}
}
