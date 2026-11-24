package goapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

// A provider's own redirect URL replaces the callback route in the
// authorization request and the code exchange, and the application forwards
// it to the callback.
func TestOAuthCustomRedirectURL(t *testing.T) {
	var authorized, exchanged string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			q := r.URL.Query()
			authorized = q.Get("redirect_uri")
			target, _ := url.Parse(authorized)
			target.RawQuery = url.Values{"code": {"code"}, "state": {q.Get("state")}}.Encode()
			http.Redirect(w, r, target.String(), http.StatusFound)
		case "/token":
			_ = r.ParseForm()
			exchanged = r.Form.Get("redirect_uri")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","expires_in":3600}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer provider.Close()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	app := httptest.NewUnstartedServer(nil)
	base := "http://" + app.Listener.Addr().String()
	local := auth.OAuthProvider{
		Config: oauth2.Config{ClientID: "local-client", ClientSecret: "secret", RedirectURL: base + "/oauth/return",
			Endpoint: oauth2.Endpoint{AuthURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token"}},
		Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) {
			return auth.OAuthProfile{Subject: "subject", Email: "person@example.org", EmailVerified: true, Name: "Person"}, nil
		},
	}
	opts := auth.Options{Secret: strings.Repeat("s", 32), BaseURL: base, Store: store, SocialProviders: map[string]auth.OAuthProvider{"local": local}}
	handler, err := auth.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", handler)
	// The application's own route hands the provider's return to the callback.
	mux.HandleFunc("/oauth/return", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "/api/auth/callback/local"
		handler.ServeHTTP(w, r)
	})
	app.Config.Handler = mux
	app.Start()
	defer app.Close()

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar}
	req, _ := http.NewRequest("POST", base+"/api/auth/sign-in/social", bytes.NewReader([]byte(`{"provider":"local","callbackURL":"/signed-in"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", base)
	res, err := (&http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var start struct{ URL string }
	_ = json.NewDecoder(res.Body).Decode(&start)
	res.Body.Close()
	browser.CheckRedirect = func(r *http.Request, _ []*http.Request) error {
		if r.URL.Path == "/signed-in" {
			return http.ErrUseLastResponse
		}
		return nil
	}
	res, err = browser.Get(start.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if authorized != base+"/oauth/return" || exchanged != authorized {
		t.Fatalf("redirect_uri: authorized %q, exchanged %q", authorized, exchanged)
	}
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/signed-in" {
		t.Fatalf("callback: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	session, err := browser.Get(base + "/api/auth/get-session")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Body.Close()
	var got auth.SessionResult
	if err := json.NewDecoder(session.Body).Decode(&got); err != nil || got.User.Email != "person@example.org" {
		t.Fatalf("session: %#v, %v", got, err)
	}

	// A redirect URL that is not an absolute HTTP(S) URL is refused.
	for _, bad := range []string{"/oauth/return", "ftp://app.example/return", "https://app.example/return#frag"} {
		local.Config.RedirectURL = bad
		opts.SocialProviders = map[string]auth.OAuthProvider{"local": local}
		if _, err := auth.New(opts); err == nil {
			t.Errorf("accepted redirect URL %q", bad)
		}
	}
}
