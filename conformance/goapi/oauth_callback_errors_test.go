package goapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

// Once the state is verified, every failure of a browser OAuth callback
// returns to the error callback, or to the error page when the sign-in gave
// none, with the reference's codes: the provider's own error and
// description, no_code, invalid_code, unable_to_get_user_info and
// email_not_found. None of them issues a session.
func TestOAuthCallbackErrors(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	provider := authn.OAuthProvider{Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token"}},
		ExchangeCode: func(_ context.Context, _ oauth2.Config, code, _ string, _ url.Values) (*oauth2.Token, error) {
			if code == "rejected" {
				return nil, errors.New("the provider refused the code")
			}
			return &oauth2.Token{AccessToken: code}, nil
		},
		Resolve: func(_ context.Context, tok *oauth2.Token, _ string) (authn.OAuthProfile, error) {
			switch tok.AccessToken {
			case "unreadable":
				return authn.OAuthProfile{}, errors.New("no profile")
			case "malformed":
				return authn.OAuthProfile{Subject: "subject", Email: "not-an-address"}, nil
			case "no-email":
				return authn.OAuthProfile{Subject: "subject"}, nil
			case "placeholder":
				return authn.OAuthProfile{Subject: "null", Email: "person@example.org"}, nil
			}
			return authn.OAuthProfile{Subject: "subject", Email: "person@example.org", EmailVerified: true}, nil
		}}
	off := false
	auth, err := authn.New(authn.Options{BaseURL: "https://auth.example.test", Store: store, Secret: strings.Repeat("s", 32), RateLimit: &off,
		SocialProviders: map[string]authn.OAuthProvider{"local": provider}})
	if err != nil {
		t.Fatal(err)
	}
	// start begins a sign-in and returns its state and cookies.
	start := func(errorCallbackURL string) (string, []*http.Cookie) {
		t.Helper()
		body := map[string]any{"provider": "local", "disableRedirect": true}
		if errorCallbackURL != "" {
			body["errorCallbackURL"] = errorCallbackURL
		}
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "https://auth.example.test/api/auth/sign-in/social", strings.NewReader(string(raw)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://auth.example.test")
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
		var out struct{ URL string }
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.URL == "" {
			t.Fatal("sign-in/social answered", w.Code, w.Body.String())
		}
		u, err := url.Parse(out.URL)
		if err != nil {
			t.Fatal(err)
		}
		return u.Query().Get("state"), w.Result().Cookies()
	}
	callback := func(state string, cookies []*http.Cookie, query url.Values) string {
		t.Helper()
		query.Set("state", state)
		r := httptest.NewRequest("GET", "https://auth.example.test/api/auth/callback/local?"+query.Encode(), nil)
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
		if w.Code != http.StatusFound {
			t.Fatal("the callback answered", w.Code, w.Body.String())
		}
		for _, c := range w.Result().Cookies() {
			if strings.HasSuffix(c.Name, "session_token") && c.Value != "" {
				t.Fatal("a failed callback issued a session")
			}
		}
		return w.Header().Get("Location")
	}
	const page = "https://auth.example.test/api/auth/error"
	for _, tc := range []struct {
		errorCallbackURL string
		query            url.Values
		want             string
	}{
		{"", url.Values{"error": {"access_denied"}, "error_description": {"Consent was declined"}}, page + "?error=access_denied&error_description=Consent+was+declined"},
		{"", url.Values{}, page + "?error=no_code"},
		{"", url.Values{"code": {"rejected"}}, page + "?error=invalid_code"},
		{"/retry", url.Values{"code": {"unreadable"}}, "/retry?error=unable_to_get_user_info"},
		{"/retry", url.Values{"code": {"malformed"}}, "/retry?error=unable_to_get_user_info"},
		{"/retry", url.Values{"code": {"no-email"}}, "/retry?error=email_not_found"},
		{"/retry", url.Values{"code": {"placeholder"}}, "/retry?error=unable_to_get_user_info"},
		{"/retry", url.Values{"error": {"access_denied"}}, "/retry?error=access_denied"},
	} {
		state, cookies := start(tc.errorCallbackURL)
		if got := callback(state, cookies, tc.query); got != tc.want {
			t.Fatalf("a callback with %v answered %s, want %s", tc.query, got, tc.want)
		}
	}
	// A state already spent by a failure is not used twice.
	state, cookies := start("")
	callback(state, cookies, url.Values{"error": {"access_denied"}})
	if got := callback(state, cookies, url.Values{"code": {"ok"}}); !strings.HasPrefix(got, page+"?error=state_") {
		t.Fatal("a spent state answered", got)
	}
}

// Mounted at the root, the OAuth proxy's own failures still go to /error on
// this host, not to the host-relative //error.
func TestOAuthProxyErrorAtRootMount(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	proxy, err := authn.NewOAuthProxy(authn.OAuthProxyOptions{ProductionURL: "https://login.example.test", Secret: strings.Repeat("p", 32)})
	if err != nil {
		t.Fatal(err)
	}
	off := false
	auth, err := authn.New(authn.Options{BaseURL: "https://preview.example.test", BasePath: "/", Store: store, Secret: strings.Repeat("s", 32), RateLimit: &off, Plugins: []authn.Plugin{proxy},
		SocialProviders: map[string]authn.OAuthProvider{"local": {Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token"}},
			Resolve: func(context.Context, *oauth2.Token, string) (authn.OAuthProfile, error) {
				return authn.OAuthProfile{}, errors.New("unused")
			}}}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	auth.ServeHTTP(w, httptest.NewRequest("GET", "https://preview.example.test/callback/local/oauth-proxy?callbackURL=/", nil))
	if got := w.Header().Get("Location"); w.Code != http.StatusFound || got != "/error?error=missing_profile" {
		t.Fatal("a proxy completion without a profile answered", w.Code, got)
	}
}
