package goapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

// With both deployments mounted at the root, a sign-in through the OAuth
// proxy uses /callback/<id> URLs without a doubled slash. Production's
// provider callbacks get the preview's additionalData with float64
// numbers, and a provider error reaches the preview's ErrorRedirectURL with
// its code unchanged.
func TestOAuthProxyAtRootMount(t *testing.T) {
	const production, preview = "https://login.example.test", "https://preview.example.test"
	var mu sync.Mutex
	var exchangedAt string
	var seen map[string]any
	provider := authn.OAuthProvider{Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token"}},
		ExchangeCode: func(_ context.Context, c oauth2.Config, code, _ string, _ url.Values) (*oauth2.Token, error) {
			mu.Lock()
			exchangedAt = c.RedirectURL
			mu.Unlock()
			return &oauth2.Token{AccessToken: code}, nil
		},
		Resolve: func(ctx context.Context, _ *oauth2.Token, _ string) (authn.OAuthProfile, error) {
			mu.Lock()
			seen = authn.OAuthAdditionalData(ctx)
			mu.Unlock()
			return authn.OAuthProfile{Subject: "subject", Email: "person@example.org", EmailVerified: true}, nil
		}}
	secret := strings.Repeat("p", 32)
	instance := func(base string, opts authn.Options) *authn.Auth {
		t.Helper()
		store, err := sqlite.Open(":memory:")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		proxy, err := authn.NewOAuthProxy(authn.OAuthProxyOptions{ProductionURL: production, CurrentURL: base, Secret: secret})
		if err != nil {
			t.Fatal(err)
		}
		off := false
		opts.BaseURL, opts.BasePath, opts.Store, opts.Secret, opts.RateLimit = base, "/", store, strings.Repeat("s", 32), &off
		opts.Plugins = []authn.Plugin{proxy}
		opts.SocialProviders = map[string]authn.OAuthProvider{"local": provider}
		auth, err := authn.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		return auth
	}
	prod := instance(production, authn.Options{TrustedOrigins: []string{preview}})
	prev := instance(preview, authn.Options{ErrorRedirectURL: preview + "/oops"})
	serve := func(auth *authn.Auth, r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
		return w
	}
	// start begins a sign-in on the preview and returns the state the
	// provider sends back and the preview's cookies.
	start := func(body string) (string, []*http.Cookie) {
		t.Helper()
		r := httptest.NewRequest("POST", preview+"/sign-in/social", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", preview)
		w := serve(prev, r)
		var out struct{ URL string }
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.URL == "" {
			t.Fatal("the preview's start answered", w.Code, w.Body.String())
		}
		u, _ := url.Parse(out.URL)
		if got := u.Query().Get("redirect_uri"); got != production+"/callback/local" {
			t.Fatal("the authorization asked for redirect_uri", got)
		}
		return u.Query().Get("state"), w.Result().Cookies()
	}
	// relay has production handle the provider's callback, then the preview
	// complete it, and returns where the preview sends the browser.
	relay := func(state string, cookies []*http.Cookie, query url.Values) string {
		t.Helper()
		query.Set("state", state)
		w := serve(prod, httptest.NewRequest("GET", production+"/callback/local?"+query.Encode(), nil))
		next := w.Header().Get("Location")
		if w.Code != http.StatusFound || !strings.HasPrefix(next, preview+"/callback/local/oauth-proxy?") {
			t.Fatal("production answered", w.Code, next)
		}
		r := httptest.NewRequest("GET", next, nil)
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w = serve(prev, r)
		if w.Code != http.StatusFound {
			t.Fatal("the preview's completion answered", w.Code, w.Body.String())
		}
		return w.Header().Get("Location")
	}

	state, cookies := start(`{"provider":"local","callbackURL":"/done","disableRedirect":true,"additionalData":{"count":2}}`)
	if got := relay(state, cookies, url.Values{"code": {"good"}}); got != "/done" {
		t.Fatal("the proxied sign-in landed at", got)
	}
	mu.Lock()
	if exchangedAt != production+"/callback/local" || seen["count"] != float64(2) {
		t.Fatalf("production exchanged at %s and saw %#v", exchangedAt, seen)
	}
	mu.Unlock()

	state, cookies = start(`{"provider":"local","callbackURL":"/done","disableRedirect":true}`)
	if got := relay(state, cookies, url.Values{"error": {"invalid_request.scope"}}); got != preview+"/oops?error=invalid_request.scope" {
		t.Fatal("a proxied provider error landed at", got)
	}
}
