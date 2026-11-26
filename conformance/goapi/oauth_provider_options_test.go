package goapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"golang.org/x/oauth2"
)

// expiringProvider serves /authorize and a /token whose responses carry
// expires_in only when expiresIn is set.
func expiringProvider(t *testing.T, expiresIn *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			target, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
			target.RawQuery = url.Values{"code": {"c"}, "state": {r.URL.Query().Get("state")}}.Encode()
			http.Redirect(w, r, target.String(), http.StatusFound)
		case "/token":
			body := `{"access_token":"access","refresh_token":"refresh","token_type":"Bearer"`
			if *expiresIn != "" {
				body += `,"expires_in":` + *expiresIn
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body + "}"))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// accessTokenExpiry returns the expiry get-access-token reports, or nil.
func (n *tokenAuthNode) accessTokenExpiry(t *testing.T) *time.Time {
	t.Helper()
	r, _ := http.NewRequest("GET", n.base+"/api/auth/list-accounts", nil)
	res, err := n.browser.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var accounts []struct{ ID string }
	if err := json.NewDecoder(res.Body).Decode(&accounts); err != nil || len(accounts) != 1 {
		t.Fatal("no linked account:", err)
	}
	var token struct{ AccessTokenExpiresAt *time.Time }
	if err := json.NewDecoder(n.post(t, "/get-access-token", `{"accountId":"`+accounts[0].ID+`"}`).Body).Decode(&token); err != nil {
		t.Fatal(err)
	}
	return token.AccessTokenExpiresAt
}

// AccessType is sent as access_type on sign-in and link authorization URLs,
// and the provider's AuthorizationParams override it.
func TestOAuthAccessType(t *testing.T) {
	srv, _ := tokenProvider(t)
	p := workProvider(srv, "secret", auth.TokenEndpointAuth{})
	p.AccessType = "offline"
	n, err := newTokenAuthNode(t, p)
	if err != nil {
		t.Fatal(err)
	}
	start := func(path string) url.Values {
		t.Helper()
		var started struct{ URL string }
		if err := json.NewDecoder(n.post(t, path, `{"provider":"work","callbackURL":"/done","disableRedirect":true}`).Body).Decode(&started); err != nil {
			t.Fatal(path, err)
		}
		u, err := url.Parse(started.URL)
		if err != nil {
			t.Fatal(err)
		}
		return u.Query()
	}
	if q := start("/sign-in/social"); q.Get("access_type") != "offline" {
		t.Fatal("the sign-in URL lacks access_type:", q)
	}
	if to := n.signIn(t); to != "/done" {
		t.Fatal("the sign-in landed at", to)
	}
	if q := start("/link-social"); q.Get("access_type") != "offline" {
		t.Fatal("the link URL lacks access_type:", q)
	}
	p.AuthorizationParams = url.Values{"access_type": {"online"}}
	n, err = newTokenAuthNode(t, p)
	if err != nil {
		t.Fatal(err)
	}
	if q := start("/sign-in/social"); q.Get("access_type") != "online" {
		t.Fatal("AuthorizationParams did not override access_type:", q)
	}
}

// DefaultAccessTokenLifetime gives a token response without expires_in an
// expiry, on the code exchange and the refresh, while a provider's expires_in
// wins and no default leaves the expiry unset; a negative default is refused.
func TestOAuthDefaultAccessTokenLifetime(t *testing.T) {
	expiresIn := ""
	srv := expiringProvider(t, &expiresIn)
	p := auth.OAuthProvider{
		Config:                     oauth2.Config{ClientID: "client", ClientSecret: "secret", Endpoint: oauth2.Endpoint{AuthURL: srv.URL + "/authorize", TokenURL: srv.URL + "/token"}},
		DefaultAccessTokenLifetime: time.Hour,
		Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) {
			return auth.OAuthProfile{Subject: "subject", Email: "person@example.org", EmailVerified: true}, nil
		},
	}
	within := func(got *time.Time, before, after time.Time, lifetime time.Duration) bool {
		return got != nil && !got.Before(before.Add(lifetime).Add(-time.Second)) && !got.After(after.Add(lifetime).Add(time.Second))
	}
	n, err := newTokenAuthNode(t, p)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	if to := n.signIn(t); to != "/done" {
		t.Fatal("the sign-in landed at", to)
	}
	if got := n.accessTokenExpiry(t); !within(got, before, time.Now(), time.Hour) {
		t.Fatal("the exchanged token's expiry is", got)
	}
	expiresIn = "120"
	n, err = newTokenAuthNode(t, p)
	if err != nil {
		t.Fatal(err)
	}
	before = time.Now()
	n.signIn(t)
	if got := n.accessTokenExpiry(t); !within(got, before, time.Now(), 2*time.Minute) {
		t.Fatal("the provider's expires_in did not win:", got)
	}
	// The refresh answers without expires_in, so its expiry is the default
	// and not the two minutes the sign-in stored.
	expiresIn = ""
	before = time.Now()
	if status := n.refresh(t); status != 200 {
		t.Fatal("the refresh answered", status)
	}
	if got := n.accessTokenExpiry(t); !within(got, before, time.Now(), time.Hour) {
		t.Fatal("the refreshed token's expiry is", got)
	}
	p.DefaultAccessTokenLifetime = 0
	n, err = newTokenAuthNode(t, p)
	if err != nil {
		t.Fatal(err)
	}
	n.signIn(t)
	if got := n.accessTokenExpiry(t); got != nil {
		t.Fatal("a token without expires_in got an expiry:", got)
	}
	p.DefaultAccessTokenLifetime = -time.Second
	if _, err := newTokenAuthNode(t, p); err == nil {
		t.Fatal("a negative default lifetime was accepted")
	}
}

// A provider's display name defaults to its SocialProviders key.
func TestOAuthProviderName(t *testing.T) {
	srv, _ := tokenProvider(t)
	named := workProvider(srv, "secret", auth.TokenEndpointAuth{})
	named.Name = "Work SSO"
	a := newHTTPAuth(t, auth.Options{BaseURL: "https://auth.example", SocialProviders: map[string]auth.OAuthProvider{"work": named, "plain": workProvider(srv, "secret", auth.TokenEndpointAuth{})}})
	if name, ok := a.OAuthProviderName("work"); !ok || name != "Work SSO" {
		t.Fatal("the explicit name is", name, ok)
	}
	if name, ok := a.OAuthProviderName("plain"); !ok || name != "plain" {
		t.Fatal("the default name is", name, ok)
	}
	if _, ok := a.OAuthProviderName("unknown"); ok {
		t.Fatal("an unknown provider has a name")
	}
}
