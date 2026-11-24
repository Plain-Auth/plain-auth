package goapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"golang.org/x/oauth2"
)

// countingFlows records how often a flow is written to the store.
type countingFlows struct {
	*sqlstore.Store
	saves atomic.Int32
}

func (s *countingFlows) SaveOAuthFlow(ctx context.Context, f auth.OAuthFlow, now time.Time) error {
	s.saves.Add(1)
	return s.Store.SaveOAuthFlow(ctx, f, now)
}

// singleUseProvider issues each authorization code once and checks PKCE.
func singleUseProvider(t *testing.T) *httptest.Server {
	type grant struct{ challenge, redirect string }
	var mu sync.Mutex
	codes := map[string]grant{}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			q := r.URL.Query()
			code := rand.Text()
			mu.Lock()
			codes[code] = grant{q.Get("code_challenge"), q.Get("redirect_uri")}
			mu.Unlock()
			target, _ := url.Parse(q.Get("redirect_uri"))
			target.RawQuery = url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
			http.Redirect(w, r, target.String(), http.StatusFound)
		case "/token":
			_ = r.ParseForm()
			mu.Lock()
			g, valid := codes[r.Form.Get("code")]
			delete(codes, r.Form.Get("code"))
			mu.Unlock()
			if !valid || g.redirect != r.Form.Get("redirect_uri") || oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")) != g.challenge {
				http.Error(w, "invalid grant", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","expires_in":3600}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(provider.Close)
	return provider
}

// OAuthStateCookie seals the whole flow into the state cookie and writes no
// flow; both strategies refuse a missing, altered or foreign state, and a
// replay stops at the store or at the provider's single-use code.
func TestOAuthStateStrategies(t *testing.T) {
	for _, strategy := range []auth.OAuthStateStrategy{auth.OAuthStateDatabase, auth.OAuthStateCookie} {
		t.Run(string(strategy), func(t *testing.T) {
			provider := singleUseProvider(t)
			inner, err := sqlite.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer inner.Close()
			store := &countingFlows{Store: inner}
			app := httptest.NewUnstartedServer(nil)
			base := "http://" + app.Listener.Addr().String()
			node, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: base, RateLimit: new(bool), OAuthStateStrategy: strategy,
				SocialProviders: map[string]auth.OAuthProvider{"local": {
					Config: oauth2.Config{ClientID: "client", ClientSecret: "secret", Endpoint: oauth2.Endpoint{AuthURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token"}},
					Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) {
						return auth.OAuthProfile{Subject: "subject", Email: "social@example.org", EmailVerified: true, Name: "Social"}, nil
					},
				}}})
			if err != nil {
				t.Fatal(err)
			}
			app.Config.Handler = node
			app.Start()
			defer app.Close()
			appURL, _ := url.Parse(base)
			stateName := "authn.oauth_state"
			newBrowser := func() *http.Client {
				jar, _ := cookiejar.New(nil)
				return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			}
			stateCookie := func(c *http.Client) *http.Cookie {
				for _, cookie := range c.Jar.Cookies(appURL) {
					if cookie.Name == stateName {
						return cookie
					}
				}
				return nil
			}
			post := func(c *http.Client, path, body string) *http.Response {
				t.Helper()
				r, _ := http.NewRequest("POST", base+"/api/auth"+path, bytes.NewReader([]byte(body)))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", base)
				res, err := c.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { res.Body.Close() })
				return res
			}
			// start signs in at the provider and returns the app callback URL.
			start := func(c *http.Client, callback string) string {
				t.Helper()
				res := post(c, "/sign-in/social", `{"provider":"local","callbackURL":"`+callback+`"}`)
				var started struct{ URL string }
				_ = json.NewDecoder(res.Body).Decode(&started)
				if res.StatusCode != 200 || started.URL == "" {
					t.Fatal("start answered", res.StatusCode)
				}
				authorized, err := c.Get(started.URL)
				if err != nil {
					t.Fatal(err)
				}
				authorized.Body.Close()
				return authorized.Header.Get("Location")
			}
			finish := func(c *http.Client, callback string) (int, string, string) {
				t.Helper()
				res, err := c.Get(callback)
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				var problem struct{ Code string }
				_ = json.NewDecoder(res.Body).Decode(&problem)
				return res.StatusCode, res.Header.Get("Location"), problem.Code
			}
			// A state the callback cannot use goes to the error page with
			// its code.
			refusedWith := func(c *http.Client, callback, why, code string) {
				t.Helper()
				if status, location, _ := finish(c, callback); status != http.StatusFound || location != base+"/api/auth/error?error="+code {
					t.Fatalf("%s answered %d %q, want %s", why, status, location, code)
				}
			}
			refused := func(c *http.Client, callback, why string) {
				t.Helper()
				refusedWith(c, callback, why, "state_mismatch")
			}
			withState := func(value string) *http.Client {
				c := newBrowser()
				c.Jar.SetCookies(appURL, []*http.Cookie{{Name: stateName, Value: value, Path: "/"}})
				return c
			}

			browser := newBrowser()
			callback := start(browser, "/home")
			captured := stateCookie(browser)
			if captured == nil {
				t.Fatal("no state cookie")
			}
			if sealed := strings.HasPrefix(captured.Value, "authn.v1."); sealed != (strategy == auth.OAuthStateCookie) {
				t.Fatalf("the state cookie was %q", captured.Value)
			}
			refused(newBrowser(), callback, "a callback without the state cookie")
			tampered := []byte(captured.Value)
			tampered[len(tampered)-3] ^= 1
			altered := "state_mismatch"
			if strategy == auth.OAuthStateCookie {
				altered = "state_invalid"
			}
			refusedWith(withState(string(tampered)), callback, "an altered state cookie", altered)
			withoutState, _ := url.Parse(callback)
			q := withoutState.Query()
			q.Del("state")
			withoutState.RawQuery = q.Encode()
			refusedWith(withState(captured.Value), withoutState.String(), "a callback without a state", "state_not_found")
			q.Set("state", strings.Repeat("s", 129))
			withoutState.RawQuery = q.Encode()
			refused(withState(captured.Value), withoutState.String(), "an oversized state")
			if status, _, code := finish(withState(captured.Value), callback+"&state=again"); status != 400 || code != "VALIDATION_ERROR" {
				t.Fatalf("a duplicate state answered %d %s", status, code)
			}
			other := newBrowser()
			otherCallback := start(other, "/home")
			refused(withState(captured.Value), otherCallback, "another flow's state cookie")
			if status, location, _ := finish(browser, callback); status != http.StatusFound || location != "/home" {
				t.Fatalf("the sign-in answered %d %q", status, location)
			}
			if c := stateCookie(browser); c != nil {
				t.Fatal("the state cookie survived its use")
			}
			// Replays: the same browser now has a session, so the binding
			// differs; a fresh client passes the cookie check in cookie mode
			// but the provider refuses the spent code.
			browser.Jar.SetCookies(appURL, []*http.Cookie{{Name: stateName, Value: captured.Value, Path: "/"}})
			refused(browser, callback, "a replay in the signed-in browser")
			if strategy == auth.OAuthStateDatabase {
				refused(withState(captured.Value), callback, "a replay of a consumed flow")
			} else if status, location, code := finish(withState(captured.Value), callback); status == http.StatusFound {
				t.Fatalf("a replay from a fresh client answered %d %q %s", status, location, code)
			}
			if saves := store.saves.Load(); (saves == 0) != (strategy == auth.OAuthStateCookie) {
				t.Fatalf("%d flows were stored", saves)
			}
			// A flow too large for a cookie is refused in cookie mode.
			long := "/" + strings.Repeat("a", 5000)
			res := post(newBrowser(), "/sign-in/social", `{"provider":"local","callbackURL":"`+long+`"}`)
			if (res.StatusCode == 400) != (strategy == auth.OAuthStateCookie) || (strategy == auth.OAuthStateCookie && res.Header.Get("Set-Cookie") != "") {
				t.Fatal("an oversized flow answered", res.StatusCode)
			}
			// Sign-out ends a sealed flow that is in progress.
			start(browser, "/again")
			res = post(browser, "/sign-out", `{}`)
			expired := false
			for _, line := range res.Header.Values("Set-Cookie") {
				expired = expired || strings.HasPrefix(line, stateName+"=;") && strings.Contains(line, "Max-Age=0")
			}
			if expired != (strategy == auth.OAuthStateCookie) {
				t.Fatalf("sign-out expired the state cookie: %v", res.Header.Values("Set-Cookie"))
			}
		})
	}
}

// New refuses an unknown strategy and a store that cannot keep the flows the
// strategy needs.
func TestOAuthStateStrategyConfiguration(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	providers := map[string]auth.OAuthProvider{"local": {Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{AuthURL: "https://issuer.example/a", TokenURL: "https://issuer.example/t"}},
		Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) {
			return auth.OAuthProfile{}, nil
		}}}
	noFlows := struct {
		auth.Store
		auth.OAuthIdentityStore
	}{store, store}
	noIdentity := struct{ auth.Store }{store}
	for name, tc := range map[string]struct {
		store    auth.Store
		strategy auth.OAuthStateStrategy
		ok       bool
	}{
		"unknown strategy":          {store, "session", false},
		"database without flows":    {noFlows, auth.OAuthStateDatabase, false},
		"default without flows":     {noFlows, "", false},
		"cookie without flows":      {noFlows, auth.OAuthStateCookie, true},
		"cookie without identities": {noIdentity, auth.OAuthStateCookie, false},
	} {
		_, err := auth.New(auth.Options{Store: tc.store, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example", OAuthStateStrategy: tc.strategy, SocialProviders: providers})
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A state failure keeps the query of a configured ErrorRedirectURL, and a
// provider's form post without a state is forwarded to the callback, which
// reports state_not_found.
func TestOAuthStateFailureDestination(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	node, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example", RateLimit: new(bool),
		ErrorRedirectURL: "/auth-problem?source=signin",
		SocialProviders: map[string]auth.OAuthProvider{"local": {
			Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{AuthURL: "https://issuer.example/authorize", TokenURL: "https://issuer.example/token"}},
			Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) {
				return auth.OAuthProfile{}, nil
			},
		}}})
	if err != nil {
		t.Fatal(err)
	}
	serve := func(r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		node.ServeHTTP(w, r)
		return w
	}
	w := serve(httptest.NewRequest("GET", "https://auth.example/api/auth/callback/local?code=x", nil))
	if w.Code != http.StatusFound || w.Header().Get("Location") != "https://auth.example/auth-problem?error=state_not_found&source=signin" {
		t.Fatal("a callback without a state answered", w.Code, w.Header().Get("Location"))
	}
	form := httptest.NewRequest("POST", "https://auth.example/api/auth/callback/local", strings.NewReader("code=x"))
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = serve(form)
	forwarded := w.Header().Get("Location")
	if w.Code != http.StatusFound || !strings.HasPrefix(forwarded, "https://auth.example/api/auth/callback/local?") {
		t.Fatal("a form post without a state answered", w.Code, forwarded)
	}
	if w = serve(httptest.NewRequest("GET", forwarded, nil)); w.Header().Get("Location") != "https://auth.example/auth-problem?error=state_not_found&source=signin" {
		t.Fatal("the forwarded callback answered", w.Code, w.Header().Get("Location"))
	}
}
