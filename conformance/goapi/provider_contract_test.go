package goapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"github.com/Plain-Org/plain-auth/providers"
)

// A preset's fields are plain data: replacing VerifyIDToken replaces its
// key check, replacing Config.Scopes drops its default scopes, and
// AuthorizationParams adds a prompt to every authorization URL. The custom
// verifier's refusal and a missing nonce answer INVALID_TOKEN without a
// session, and a verified token without an email answers
// USER_EMAIL_NOT_FOUND.
func TestProviderPresetOptions(t *testing.T) {
	var mu sync.Mutex
	var verified []string
	google := providers.Google("client", "secret")
	google.VerifyIDToken = func(_ context.Context, raw, nonce string) (authn.OAuthProfile, time.Time, error) {
		mu.Lock()
		verified = append(verified, raw+"|"+nonce)
		mu.Unlock()
		switch raw {
		case "refused":
			return authn.OAuthProfile{}, time.Time{}, errors.New("not ours")
		case "no-email":
			return authn.OAuthProfile{Subject: "no-email"}, time.Now().Add(time.Hour), nil
		}
		return authn.OAuthProfile{Subject: raw, Email: raw + "@example.test", EmailVerified: true, Name: "Person"}, time.Now().Add(time.Hour), nil
	}
	google.Config.Scopes = []string{"openid"}
	google.AuthorizationParams = url.Values{"prompt": {"select_account consent"}}
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	off := false
	auth, err := authn.New(authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), RateLimit: &off, EmailAndPassword: true,
		SocialProviders: map[string]authn.OAuthProvider{"google": google}})
	if err != nil {
		t.Fatal(err)
	}
	c := sessionClient{t, auth}
	start := func(path, cookie string) url.Values {
		t.Helper()
		var out struct{ URL string }
		if err := json.NewDecoder(c.post(path, `{"provider":"google","callbackURL":"/"}`, cookie, 200).Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(out.URL)
		if err != nil {
			t.Fatal(err)
		}
		return u.Query()
	}
	if q := start("/sign-in/social", ""); q.Get("scope") != "openid" || q.Get("prompt") != "select_account consent" {
		t.Fatal("the sign-in authorization asked for", q.Get("scope"), q.Get("prompt"))
	}
	for token, code := range map[string]string{"refused": "INVALID_TOKEN", "no-email": "USER_EMAIL_NOT_FOUND"} {
		r := c.post("/sign-in/social", `{"provider":"google","idToken":{"token":"`+token+`","nonce":"n"}}`, "", 401)
		if got, _, _ := errorBody(t, r); got != code || len(r.Header.Values("Set-Cookie")) != 0 {
			t.Fatal("ID token", token, "answered", got, r.Header.Values("Set-Cookie"))
		}
	}
	if code, _, _ := errorBody(t, c.post("/sign-in/social", `{"provider":"google","idToken":{"token":"ada","nonce":""}}`, "", 401)); code != "INVALID_TOKEN" {
		t.Fatal("an ID token without a nonce answered", code)
	}
	if _, err := store.FindAccountUser(t.Context(), "refused@example.test"); err == nil {
		t.Fatal("a refused ID token created an account")
	}
	r := c.post("/sign-in/social", `{"provider":"google","idToken":{"token":"ada","nonce":"n"}}`, "", 200)
	var cookie string
	for _, ck := range r.Cookies() {
		if strings.HasSuffix(ck.Name, "session_token") {
			cookie = ck.Name + "=" + ck.Value
		}
	}
	mu.Lock()
	seen := verified[len(verified)-1]
	mu.Unlock()
	if seen != "ada|n" || c.user(cookie) != "ada@example.test" {
		t.Fatal("the custom verifier saw", seen)
	}
	if q := start("/link-social", cookie); q.Get("prompt") != "select_account consent" || q.Get("scope") != "openid" {
		t.Fatal("the link authorization asked for", q.Get("scope"), q.Get("prompt"))
	}
}

// The provider credential routes need a session and an account of a
// configured provider that holds the token asked for.
func TestProviderCredentialErrors(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	google := providers.Google("client", "secret")
	google.VerifyIDToken = func(_ context.Context, raw, _ string) (authn.OAuthProfile, time.Time, error) {
		return authn.OAuthProfile{Subject: raw, Email: raw + "@example.test", EmailVerified: true, Name: "Person"}, time.Now().Add(time.Hour), nil
	}
	off := false
	auth, err := authn.New(authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), RateLimit: &off, EmailAndPassword: true,
		SocialProviders: map[string]authn.OAuthProvider{"google": google}})
	if err != nil {
		t.Fatal(err)
	}
	c := sessionClient{t, auth}
	c.post("/sign-up/email", `{"name":"Carl","email":"carl@example.test","password":"`+sessionEndpointPassword+`"}`, "", 200)
	cookie, _ := c.signIn("carl@example.test")
	// An ID-token link stores no access or refresh token.
	c.post("/link-social", `{"provider":"google","idToken":{"token":"carl","nonce":"n"}}`, cookie, 200)
	accounts := accountsOf(t, c, cookie)
	if accounts["credential"] == "" || accounts["google"] == "" {
		t.Fatal("unexpected accounts", accounts)
	}
	// The selector is validated first, as in the reference, then the session.
	if _, message, _ := errorBody(t, c.get("/account-info", cookie, 400)); message != "Select exactly one account" {
		t.Fatal("account-info without a selector answered", message)
	}
	if code, _, _ := errorBody(t, c.get("/account-info?accountId="+url.QueryEscape(accounts["google"]), "", 401)); code != "UNAUTHORIZED" {
		t.Fatal("an anonymous account-info answered", code)
	}
	for _, tc := range []struct {
		method, path, account, code string
	}{
		{"GET", "/account-info", "credential", "PROVIDER_NOT_CONFIGURED"},
		{"GET", "/account-info", "google", "ACCESS_TOKEN_NOT_FOUND"},
		{"POST", "/get-access-token", "credential", "PROVIDER_NOT_SUPPORTED"},
		{"POST", "/refresh-token", "credential", "PROVIDER_NOT_SUPPORTED"},
		{"POST", "/refresh-token", "google", "REFRESH_TOKEN_NOT_FOUND"},
	} {
		var r *http.Response
		if tc.method == "GET" {
			r = c.get(tc.path+"?accountId="+url.QueryEscape(accounts[tc.account]), cookie, 400)
		} else {
			r = c.post(tc.path, `{"accountId":"`+accounts[tc.account]+`"}`, cookie, 400)
		}
		if code, _, _ := errorBody(t, r); code != tc.code {
			t.Fatal(tc.method, tc.path, "for the", tc.account, "account answered", code, "want", tc.code)
		}
	}
	var api *authn.APIError
	if _, err := auth.GetAccessToken(t.Context(), nil, authn.AccountSelection{AccountID: accounts["google"]}); !errors.As(err, &api) || api.Code != "USER_ID_OR_SESSION_REQUIRED" {
		t.Fatal("a server call without a session or user answered", err)
	}
}
