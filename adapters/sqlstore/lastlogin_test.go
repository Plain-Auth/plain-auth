package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/plugins/emailotp"
	"github.com/Plain-Org/plain-auth/plugins/lastlogin"
	"github.com/Plain-Org/plain-auth/plugins/magiclink"
	"github.com/Plain-Org/plain-auth/plugins/oauthproxy"
	"github.com/Plain-Org/plain-auth/plugins/onetap"
	pk "github.com/Plain-Org/plain-auth/plugins/passkey"
	"github.com/Plain-Org/plain-auth/plugins/siwe"
	"github.com/Plain-Org/plain-auth/schema"
	"golang.org/x/oauth2"
)

func TestPersistedLastLoginMethod(t *testing.T) {
	type loginStore interface {
		auth.Store
		lastlogin.Store
	}
	for _, kind := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(kind, func(t *testing.T) {
			ctx := t.Context()
			var store loginStore
			if kind == "memory" {
				store = memory.New()
			} else {
				ddl, err := schema.Generate(kind, []string{"last-login-method"})
				if err != nil {
					t.Fatal(err)
				}
				db, err := OpenWithSchema(ctx, kind, organizationTestDSN(t, kind), ddl)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				store = db
			}
			const origin = "https://example.test"
			plugin := lastlogin.New(lastlogin.Options{Database: store, Allow: func(*http.Request, string) bool { return false }, Resolve: func(r *http.Request) string {
				if strings.HasSuffix(r.URL.Path, "/sign-in/email") {
					return "password"
				}
				return ""
			}})
			opts := auth.Options{BaseURL: origin, Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, Plugins: []auth.Plugin{plugin}}
			a, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			sign := func(path string) *http.Cookie {
				r := httptest.NewRequest("POST", origin+"/api/auth/"+path, strings.NewReader(`{"name":"Test","email":"mail@example.test","password":"fixture-password"}`))
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatal(w.Code, w.Body)
				}
				var session *http.Cookie
				for _, c := range w.Result().Cookies() {
					if strings.Contains(c.Name, "last_used_login_method") {
						t.Fatal("consent-gated cookie was emitted")
					}
					if strings.HasSuffix(c.Name, ".session_token") {
						session = c
					}
				}
				if session == nil {
					t.Fatal("missing session")
				}
				return session
			}
			read := func(a *auth.Auth, c *http.Cookie) auth.User {
				r := httptest.NewRequest("GET", origin+"/api/auth/get-session", nil)
				r.AddCookie(c)
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var row auth.SessionResult
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &row) != nil {
					t.Fatal("session read", w.Code, w.Body)
				}
				return row.User
			}
			first := sign("sign-up/email")
			user := read(a, first)
			if user.LastLoginMethod == nil || *user.LastLoginMethod != "email" {
				t.Fatal("missing persisted sign-up method")
			}
			second := sign("sign-in/email")
			again := read(a, first)
			if again.LastLoginMethod == nil || *again.LastLoginMethod != "password" {
				t.Fatal("second session did not update account method")
			}
			if err := store.DeleteSession(ctx, a.VerifySignedSessionToken(second.Value)); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveSessionLoginMethod(ctx, a.VerifySignedSessionToken(second.Value), "stale", time.Now()); err != nil {
				t.Fatal(err)
			}
			if method, err := store.UserLoginMethod(ctx, user.ID); err != nil || method != "password" {
				t.Fatal("revoked session changed the recorded method", err)
			}
			opts.Plugins = nil
			bare, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			if read(bare, first).LastLoginMethod != nil {
				t.Fatal("disabled plugin exposed login method")
			}
		})
	}
}

// Without Options.Database the plugin still sets the browser preference, but
// it stores nothing on the account, needs no lastLoginMethod column, and
// session reads leave the field out.
func TestLastLoginMethodWithoutDatabase(t *testing.T) {
	type loginStore interface {
		auth.Store
		lastlogin.Store
	}
	for _, kind := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(kind, func(t *testing.T) {
			const origin = "https://example.test"
			config := func(store auth.Store, plugin auth.Plugin) auth.Options {
				return auth.Options{BaseURL: origin, Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, Plugins: []auth.Plugin{plugin}}
			}
			open := func(profiles []string) *Store {
				t.Helper()
				ddl, err := schema.Generate(kind, profiles)
				if err != nil {
					t.Fatal(err)
				}
				db, err := OpenWithSchema(t.Context(), kind, organizationTestDSN(t, kind), ddl)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { db.Close() })
				return db
			}
			signUp := func(store auth.Store, email string) string {
				t.Helper()
				a, err := auth.New(config(store, lastlogin.New(lastlogin.Options{})))
				if err != nil {
					t.Fatal("the plugin without Database needed a schema change:", err)
				}
				r := httptest.NewRequest("POST", origin+"/api/auth/sign-up/email", strings.NewReader(`{"name":"Test","email":"`+email+`","password":"fixture-password"}`))
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var session, preference *http.Cookie
				for _, c := range w.Result().Cookies() {
					switch c.Name {
					case "__Secure-authn.session_token":
						session = c
					case "__Secure-authn.last_used_login_method":
						preference = c
					}
				}
				if w.Code != 200 || session == nil || preference == nil || preference.Value != "email" {
					t.Fatal("sign-up without Database lost the session or the preference", w.Code, w.Body)
				}
				r = httptest.NewRequest("GET", origin+"/api/auth/get-session", nil)
				r.AddCookie(session)
				w = httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var read struct{ User map[string]any }
				if err := json.Unmarshal(w.Body.Bytes(), &read); err != nil || read.User["id"] == nil {
					t.Fatal("session read", w.Code, w.Body)
				}
				if _, exposed := read.User["lastLoginMethod"]; exposed {
					t.Fatal("session read exposed lastLoginMethod without Database")
				}
				return read.User["id"].(string)
			}
			var store loginStore
			if kind == "memory" {
				store = memory.New()
			} else {
				bare := open(nil)
				if _, err := auth.New(config(bare, lastlogin.New(lastlogin.Options{Database: bare}))); err == nil || !strings.Contains(err.Error(), "last-login-method schema profile") {
					t.Fatal("Database accepted a store without the lastLoginMethod column:", err)
				}
				signUp(bare, "bare@example.test")
				store = open([]string{"last-login-method"})
			}
			id := signUp(store, "column@example.test")
			if method, err := store.UserLoginMethod(t.Context(), id); err != nil || method != "" {
				t.Fatal("sign-in stored a method on the account without Database", method, err)
			}
		})
	}
}

// loginPreference returns the response's login-method preference cookie.
func loginPreference(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Secure-authn.last_used_login_method" {
			return c
		}
	}
	return nil
}

// expectLoginMethod checks that the sign-in response w set the preference
// to method and that the session read and the account both name it.
func expectLoginMethod(t *testing.T, a *auth.Auth, store lastlogin.Store, origin string, w *httptest.ResponseRecorder, method string) {
	t.Helper()
	if p := loginPreference(w); p == nil || p.Value != method || p.HttpOnly {
		t.Fatalf("sign-in answered %d with preference %v, want %q", w.Code, p, method)
	}
	r := httptest.NewRequest("GET", origin+"/api/auth/get-session", nil)
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Secure-authn.session_token" && c.MaxAge > 0 {
			r.AddCookie(c)
		}
	}
	read := httptest.NewRecorder()
	a.ServeHTTP(read, r)
	var view auth.SessionResult
	if err := json.Unmarshal(read.Body.Bytes(), &view); err != nil || view.User.LastLoginMethod == nil || *view.User.LastLoginMethod != method {
		t.Fatalf("the session read after %q answered %d: %s", method, read.Code, read.Body)
	}
	if stored, err := store.UserLoginMethod(t.Context(), view.User.ID); err != nil || stored != method {
		t.Fatalf("the account holds %q, want %q (%v)", stored, method, err)
	}
}

// A provider callback records the provider ID as the preference and on the
// account, also when the OAuth proxy completes it at
// /callback/:id/oauth-proxy, and a refused callback records nothing.
func TestLastLoginMethodFromOAuthCallbacks(t *testing.T) {
	const site, production = "https://app.example.test", "https://login.example.test"
	provider := auth.OAuthProvider{
		Config: oauth2.Config{ClientID: "client", ClientSecret: "client-secret", Endpoint: oauth2.Endpoint{AuthURL: "https://id.example.test/authorize", TokenURL: "https://id.example.test/token"}},
		ExchangeCode: func(_ context.Context, _ oauth2.Config, code, _ string, _ url.Values) (*oauth2.Token, error) {
			if code != "direct" && code != "proxied" {
				return nil, errors.New("refused")
			}
			return &oauth2.Token{AccessToken: code}, nil
		},
		Resolve: func(_ context.Context, token *oauth2.Token, _ string) (auth.OAuthProfile, error) {
			return auth.OAuthProfile{Subject: token.AccessToken, Email: token.AccessToken + "@example.test", EmailVerified: true, Name: "Octo"}, nil
		},
	}
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ddl, err := schema.Generate(dialect, []string{"last-login-method"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(t.Context(), dialect, organizationTestDSN(t, dialect), ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			off := false
			deploy := func(base string, s auth.Store, plugins ...auth.Plugin) *auth.Auth {
				t.Helper()
				a, err := auth.New(auth.Options{BaseURL: base, Store: s, Secret: strings.Repeat("s", 32), RateLimit: &off, TrustedOrigins: []string{site},
					SocialProviders: map[string]auth.OAuthProvider{"github": provider}, Plugins: plugins})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			proxy := func(current string) auth.Plugin {
				t.Helper()
				p, err := oauthproxy.New(oauthproxy.Options{ProductionURL: production, CurrentURL: current, Secret: "shared proxy secret for this test"})
				if err != nil {
					t.Fatal(err)
				}
				return p
			}
			app := deploy(site, store, lastlogin.New(lastlogin.Options{Database: store}))
			preview := deploy(site, store, proxy(site), lastlogin.New(lastlogin.Options{Database: store}))
			// Production exchanges the code with its own store.
			productionDDL, err := schema.Generate("sqlite", nil)
			if err != nil {
				t.Fatal(err)
			}
			productionStore, err := OpenWithSchema(t.Context(), "sqlite", filepath.Join(t.TempDir(), "production.sqlite"), productionDDL)
			if err != nil {
				t.Fatal(err)
			}
			defer productionStore.Close()
			login := deploy(production, productionStore, proxy(production))
			start := func(a *auth.Auth) (string, []*http.Cookie) {
				t.Helper()
				r := httptest.NewRequest("POST", site+"/api/auth/sign-in/social", strings.NewReader(`{"provider":"github","callbackURL":"/home","disableRedirect":true}`))
				r.Header.Set("Origin", site)
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var started struct{ URL string }
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &started) != nil {
					t.Fatal("start", w.Code, w.Body)
				}
				u, err := url.Parse(started.URL)
				if err != nil {
					t.Fatal(err)
				}
				return u.Query().Get("state"), w.Result().Cookies()
			}
			callback := func(a *auth.Auth, base, code, state string, cookies []*http.Cookie) *httptest.ResponseRecorder {
				t.Helper()
				r := httptest.NewRequest("GET", base+"/api/auth/callback/github?"+url.Values{"code": {code}, "state": {state}}.Encode(), nil)
				for _, c := range cookies {
					r.AddCookie(c)
				}
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				if w.Code != http.StatusFound {
					t.Fatal("callback", w.Code, w.Body)
				}
				return w
			}
			state, cookies := start(app)
			if refused := callback(app, site, "refused", state, cookies); loginPreference(refused) != nil {
				t.Fatal("a failed provider callback published a login method")
			}
			state, cookies = start(app)
			direct := callback(app, site, "direct", state, cookies)
			expectLoginMethod(t, app, store, site, direct, "github")
			state, cookies = start(preview)
			relay := callback(login, production, "proxied", state, nil)
			location := relay.Header().Get("Location")
			if !strings.HasPrefix(location, site+"/api/auth/callback/github/oauth-proxy?") {
				t.Fatal("production sent the browser to", location)
			}
			r := httptest.NewRequest("GET", location, nil)
			for _, c := range cookies {
				r.AddCookie(c)
			}
			proxied := httptest.NewRecorder()
			preview.ServeHTTP(proxied, r)
			if proxied.Code != http.StatusFound {
				t.Fatal("the proxy completion answered", proxied.Code, proxied.Body)
			}
			expectLoginMethod(t, preview, store, site, proxied, "github")
		})
	}
}

// Signing in once through each plugin route the default resolution knows
// records its method as the preference, on the session read and on the
// account: google for One Tap, siwe, passkey, magic-link and email-otp.
func TestLastLoginMethodFromPluginSignIns(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			const origin, rp = "https://app.example.test", "app.example.test"
			ddl, err := schema.Generate(dialect, []string{"last-login-method", "passkey", "siwe"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(t.Context(), dialect, organizationTestDSN(t, dialect), ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			must := func(p auth.Plugin, err error) auth.Plugin {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
				return p
			}
			var link magiclink.Message
			var code emailotp.Message
			google := auth.OAuthProvider{
				Config: oauth2.Config{ClientID: "one-tap-client", Endpoint: oauth2.Endpoint{AuthURL: "https://accounts.example.test/authorize", TokenURL: "https://accounts.example.test/token"}},
				Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) {
					return auth.OAuthProfile{}, errors.New("One Tap uses only the ID token")
				},
				VerifyIDToken: func(_ context.Context, raw, nonce string) (auth.OAuthProfile, time.Time, error) {
					if raw != "tap-credential-"+nonce {
						return auth.OAuthProfile{}, time.Time{}, errors.New("unknown credential")
					}
					return auth.OAuthProfile{Subject: "tap", Email: "tap@example.test", EmailVerified: true, Name: "Tap"}, time.Now().Add(time.Hour), nil
				},
			}
			off := false
			a, err := auth.New(auth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
				SocialProviders: map[string]auth.OAuthProvider{"google": google},
				Plugins: []auth.Plugin{
					lastlogin.New(lastlogin.Options{Database: store}),
					onetap.New(onetap.Options{}),
					must(siwe.New(siwe.Options{Domain: rp})),
					must(pk.New(pk.Options{RPID: rp, RPName: "Test", Origins: []string{origin}})),
					must(magiclink.New(magiclink.Options{Send: func(_ context.Context, m magiclink.Message) error { link = m; return nil }})),
					must(emailotp.New(emailotp.Options{Send: func(_ context.Context, m emailotp.Message) error { code = m; return nil }})),
				}})
			if err != nil {
				t.Fatal(err)
			}
			send := func(method, target string, body any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
				t.Helper()
				var reader *strings.Reader
				if body == nil {
					reader = strings.NewReader("")
				} else {
					raw, _ := json.Marshal(body)
					reader = strings.NewReader(string(raw))
				}
				r := httptest.NewRequest(method, target, reader)
				r.Header.Set("Origin", origin)
				if body != nil {
					r.Header.Set("Content-Type", "application/json")
				}
				for _, c := range cookies {
					r.AddCookie(c)
				}
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				if w.Code != 200 && w.Code != http.StatusFound {
					t.Fatal(method, target, "answered", w.Code, w.Body)
				}
				return w
			}
			post := func(path string, body any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
				t.Helper()
				return send("POST", origin+"/api/auth"+path, body, cookies...)
			}
			field := func(w *httptest.ResponseRecorder, name string) string {
				t.Helper()
				var out map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
					t.Fatal(err)
				}
				value, _ := out[name].(string)
				return value
			}
			oneTapSignIn := func() *httptest.ResponseRecorder {
				nonce := post("/one-tap/nonce", map[string]any{})
				return post("/one-tap/callback", map[string]string{"idToken": "tap-credential-" + field(nonce, "nonce")}, nonce.Result().Cookies()...)
			}
			walletSignIn := func() *httptest.ResponseRecorder {
				signer := freshWallet(t)
				message := walletMessage(signer.address, rp, field(post("/siwe/nonce", map[string]any{}), "nonce"), 1)
				return post("/siwe/verify", map[string]string{"message": message, "signature": signer.sign(message)})
			}
			passkeySignIn := func() *httptest.ResponseRecorder {
				key := newSoftwareKey(t)
				res, err := a.SignUpEmail(t.Context(), auth.SignUpInput{Email: "key@example.test", Name: "Key", Password: "local sample passphrase"}, auth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				session := a.SessionCookie(res.Token, true)
				options := send("GET", origin+"/api/auth/passkey/generate-register-options", nil, session)
				var created struct {
					Challenge string
					User      struct{ ID string }
				}
				if err := json.Unmarshal(options.Body.Bytes(), &created); err != nil {
					t.Fatal(err)
				}
				key.handle = created.User.ID
				post("/passkey/verify-registration", map[string]any{"response": key.response(t, created.Challenge, origin, rp, 0, true), "name": "Laptop"}, append(options.Result().Cookies(), session)...)
				login := send("GET", origin+"/api/auth/passkey/generate-authenticate-options", nil)
				return post("/passkey/verify-authentication", map[string]any{"response": key.response(t, field(login, "challenge"), origin, rp, 1, false)}, login.Result().Cookies()...)
			}
			magicLinkSignIn := func() *httptest.ResponseRecorder {
				post("/sign-in/magic-link", map[string]string{"email": "link@example.test", "name": "Link", "callbackURL": "/home"})
				return send("GET", link.URL, nil)
			}
			emailOTPSignIn := func() *httptest.ResponseRecorder {
				post("/email-otp/send-verification-otp", map[string]string{"email": "otp@example.test", "type": "sign-in"})
				return post("/sign-in/email-otp", map[string]string{"email": "otp@example.test", "otp": code.OTP})
			}
			expectLoginMethod(t, a, store, origin, oneTapSignIn(), "google")
			expectLoginMethod(t, a, store, origin, walletSignIn(), "siwe")
			expectLoginMethod(t, a, store, origin, passkeySignIn(), "passkey")
			expectLoginMethod(t, a, store, origin, magicLinkSignIn(), "magic-link")
			expectLoginMethod(t, a, store, origin, emailOTPSignIn(), "email-otp")
		})
	}
}
