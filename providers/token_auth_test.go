package providers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

// newProviderAuth builds an Auth with p and returns New's error.
func newProviderAuth(t *testing.T, name string, p auth.OAuthProvider) error {
	t.Helper()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_, err = auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: "https://app.example.org", SocialProviders: map[string]auth.OAuthProvider{name: p}})
	return err
}

// tokenForms records the token requests a provider receives through
// roundTripFunc and answers them with a refreshable token.
type tokenForms struct {
	forms   []url.Values
	headers []http.Header
}

// Cloudflare authenticates with HTTP Basic by default and with the form
// secret under TokenAuthClientSecretPost, on both the code exchange and the
// refresh; a public client sends no secret; a method that does not fit the
// secret is refused.
func TestCloudflareTokenEndpointAuth(t *testing.T) {
	for _, tc := range []struct {
		name   string
		secret string
		method auth.TokenAuthMethod
		check  func(url.Values, http.Header) bool
	}{
		{"default Basic", "secret", "", func(f url.Values, h http.Header) bool {
			u, p, ok := (&http.Request{Header: h}).BasicAuth()
			return ok && u == "client" && p == "secret" && !f.Has("client_secret")
		}},
		{"explicit Basic", "secret", auth.TokenAuthClientSecretBasic, func(f url.Values, h http.Header) bool {
			u, p, ok := (&http.Request{Header: h}).BasicAuth()
			return ok && u == "client" && p == "secret" && !f.Has("client_secret")
		}},
		{"post", "secret", auth.TokenAuthClientSecretPost, func(f url.Values, h http.Header) bool {
			return h.Get("Authorization") == "" && f.Get("client_id") == "client" && f.Get("client_secret") == "secret"
		}},
		{"public", "", "", func(f url.Values, h http.Header) bool {
			return h.Get("Authorization") == "" && f.Get("client_id") == "client" && !f.Has("client_secret")
		}},
		{"none", "", auth.TokenAuthNone, func(f url.Values, h http.Header) bool {
			return h.Get("Authorization") == "" && f.Get("client_id") == "client" && !f.Has("client_secret")
		}},
	} {
		p, err := New("cloudflare", "client", tc.secret)
		if err != nil {
			t.Fatal(err)
		}
		p.TokenEndpointAuth.Method = tc.method
		p.Config.Scopes = append(p.Config.Scopes, "offline_access")
		var got tokenForms
		var challenge string
		p.CustomizeAuthorization = func(u *url.URL) { challenge = u.Query().Get("code_challenge") }
		p.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch r.URL.String() {
			case "https://dash.cloudflare.com/oauth2/token":
				_ = r.ParseForm()
				got.forms, got.headers = append(got.forms, r.PostForm), append(got.headers, r.Header.Clone())
				return textResponse(200, "application/json", `{"access_token":"a","refresh_token":"r","token_type":"bearer","expires_in":3600}`), nil
			case "https://api.cloudflare.com/client/v4/user":
				return textResponse(200, "application/json", `{"success":true,"result":{"id":"cf-sub","email":"person@example.org","first_name":"A","last_name":"Person"}}`), nil
			}
			t.Fatalf("unexpected request %s", r.URL)
			return nil, nil
		})}
		f := runBrowserFlow(t, "cloudflare", p)
		if f.callback.Header().Get("Location") != "/done" || !strings.Contains(f.authorize.Query().Get("scope"), "offline_access") {
			t.Fatalf("%s: the sign-in failed: %s", tc.name, f.callback.Header().Get("Location"))
		}
		var accounts []struct{ ID string }
		f.call(t, "GET", "/list-accounts", "", &accounts)
		if len(accounts) != 1 || f.call(t, "POST", "/refresh-token", `{"accountId":"`+accounts[0].ID+`"}`, nil) != 200 {
			t.Fatalf("%s: the refresh failed", tc.name)
		}
		if len(got.forms) != 2 || got.forms[0].Get("grant_type") != "authorization_code" || oauth2.S256ChallengeFromVerifier(got.forms[0].Get("code_verifier")) != challenge || got.forms[1].Get("grant_type") != "refresh_token" {
			t.Fatalf("%s: token requests %v", tc.name, got.forms)
		}
		for i := range got.forms {
			if !tc.check(got.forms[i], got.headers[i]) {
				t.Fatalf("%s: request %d was authenticated wrongly: %v %v", tc.name, i, got.forms[i], got.headers[i])
			}
		}
	}
	for _, tc := range []struct {
		secret string
		method auth.TokenAuthMethod
	}{{"secret", auth.TokenAuthNone}, {"", auth.TokenAuthClientSecretBasic}} {
		p, _ := New("cloudflare", "client", tc.secret)
		p.TokenEndpointAuth.Method = tc.method
		if err := newProviderAuth(t, "cloudflare", p); err == nil {
			t.Fatalf("New accepted %s with secret %q", tc.method, tc.secret)
		}
	}
}

// Vercel's secretless client authenticates its code exchange through a
// custom hook, such as an OIDC workload token, or a client assertion; the
// hook keeps the code, redirect URI and PKCE verifier, and a secret method
// without a secret is refused.
func TestVercelClientAuthentication(t *testing.T) {
	serve := func(t *testing.T, check func(url.Values, http.Header)) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch r.URL.String() {
			case "https://api.vercel.com/login/oauth/token":
				_ = r.ParseForm()
				check(r.PostForm, r.Header)
				return textResponse(200, "application/json", `{"access_token":"a","token_type":"bearer","expires_in":3600}`), nil
			case "https://api.vercel.com/login/oauth/userinfo":
				return textResponse(200, "application/json", `{"sub":"vc-sub","email":"person@example.org","email_verified":true,"name":"Person"}`), nil
			}
			t.Fatalf("unexpected request %s", r.URL)
			return nil, nil
		})}
	}
	calls := 0
	p, err := New("vercel", "client", "")
	if err != nil {
		t.Fatal(err)
	}
	var challenge string
	p.CustomizeAuthorization = func(u *url.URL) { challenge = u.Query().Get("code_challenge") }
	p.TokenEndpointAuth = auth.TokenEndpointAuth{Method: auth.TokenAuthCustom, CustomizeRequest: func(_ context.Context, r auth.TokenRequest, form url.Values, _ http.Header) error {
		calls++
		form.Set("client_id", r.ClientID)
		form.Set("client_assertion_type", "urn:vercel:params:oauth:client-assertion-type:oidc-bearer")
		form.Set("client_assertion", "workload-oidc-token")
		return nil
	}}
	p.HTTPClient = serve(t, func(f url.Values, h http.Header) {
		if f.Get("client_assertion") != "workload-oidc-token" || f.Get("client_assertion_type") != "urn:vercel:params:oauth:client-assertion-type:oidc-bearer" || f.Get("client_id") != "client" || f.Has("client_secret") ||
			f.Get("code") != "provider-code" || f.Get("redirect_uri") != "https://app.example.org/identity/callback/vercel" || oauth2.S256ChallengeFromVerifier(f.Get("code_verifier")) != challenge || h.Get("Authorization") != "" {
			t.Fatal("the custom Vercel exchange is wrong:", f)
		}
	})
	if f := runBrowserFlowAt(t, "/identity", "vercel", p); f.callback.Header().Get("Location") != "/done" || calls != 1 || f.authorize.Query().Get("redirect_uri") != "https://app.example.org/identity/callback/vercel" {
		t.Fatalf("the custom Vercel sign-in failed: %s (%d hook calls)", f.callback.Header().Get("Location"), calls)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, err := PrivateKeyJWT(PrivateKeyJWTOptions{PrivateKeyPEM: pkcs8PEM(t, key), KeyID: "vercel-key", ValidFor: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	jwt, _ := New("vercel", "client", "")
	jwt.TokenEndpointAuth = auth.TokenEndpointAuth{Method: auth.TokenAuthPrivateKeyJWT, ClientAssertion: signer}
	jwt.HTTPClient = serve(t, func(f url.Values, _ http.Header) {
		parsed, err := jose.ParseSigned(f.Get("client_assertion"), []jose.SignatureAlgorithm{jose.RS256})
		if err != nil || f.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" || f.Has("client_secret") {
			t.Fatal("the Vercel client assertion is wrong:", f, err)
		}
		payload, err := parsed.Verify(&key.PublicKey)
		var claims struct {
			Iss, Sub, Aud string
			Iat, Exp      int64
		}
		if err != nil || json.Unmarshal(payload, &claims) != nil || claims.Iss != "client" || claims.Sub != "client" || claims.Aud != "https://api.vercel.com/login/oauth/token" || claims.Exp-claims.Iat != 60 || parsed.Signatures[0].Header.KeyID != "vercel-key" {
			t.Fatal("the Vercel client assertion claims are wrong:", claims, err)
		}
	})
	if f := runBrowserFlow(t, "vercel", jwt); f.callback.Header().Get("Location") != "/done" {
		t.Fatal("the Vercel client assertion sign-in failed:", f.callback.Header().Get("Location"))
	}
	withSecret, _ := New("vercel", "client", "secret")
	withSecret.TokenEndpointAuth = jwt.TokenEndpointAuth
	if err := newProviderAuth(t, "vercel", withSecret); err == nil {
		t.Fatal("New accepted a client assertion with a secret")
	}
	for _, method := range []auth.TokenAuthMethod{auth.TokenAuthClientSecretBasic, auth.TokenAuthClientSecretPost} {
		public, _ := New("vercel", "client", "")
		public.TokenEndpointAuth.Method = method
		if err := newProviderAuth(t, "vercel", public); err == nil {
			t.Fatal("New accepted", method, "without a secret")
		}
	}
}

// The helper presets that keep the standard token requests take a
// TokenEndpointAuth method; Notion, which has its own refresh, and VK, TikTok
// and WeChat, which have their own code exchange, refuse one.
func TestPresetsTakeTokenEndpointAuth(t *testing.T) {
	microsoft, err := Microsoft("client", "secret", MicrosoftOptions{})
	if err != nil {
		t.Fatal(err)
	}
	built := map[string]auth.OAuthProvider{"line": LINE("channel", "secret"), "microsoft": microsoft}
	for _, name := range []string{"gumroad", "hubspot", "patreon", "slack-oidc", "yandex"} {
		if built[name], err = New(name, "client", "secret"); err != nil {
			t.Fatal(name, err)
		}
	}
	for name, p := range built {
		for _, method := range []auth.TokenAuthMethod{auth.TokenAuthClientSecretBasic, auth.TokenAuthClientSecretPost} {
			p.TokenEndpointAuth = auth.TokenEndpointAuth{Method: method}
			if err := newProviderAuth(t, name, p); err != nil {
				t.Fatal(name, method, err)
			}
		}
	}
	for _, name := range []string{"notion", "vk", "tiktok", "wechat"} {
		p, err := New(name, "client", "secret")
		if err != nil {
			t.Fatal(name, err)
		}
		p.TokenEndpointAuth = auth.TokenEndpointAuth{Method: auth.TokenAuthClientSecretPost}
		if err := newProviderAuth(t, name, p); err == nil || !strings.Contains(err.Error(), "ExchangeCode or Refresh") {
			t.Fatal(name, "took a method:", err)
		}
	}
}
