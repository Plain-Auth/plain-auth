package providers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// startAuthorization starts a browser sign-in with provider registered under
// name and returns the provider authorization URL it redirects to.
func startAuthorization(t *testing.T, name string, provider auth.OAuthProvider, body map[string]any) *url.URL {
	t.Helper()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	const base = "https://app.example.org"
	h, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: base, SocialProviders: map[string]auth.OAuthProvider{name: provider}})
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"provider": name, "callbackURL": "/done"}
	for k, v := range body {
		payload[k] = v
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", base+"/api/auth/sign-in/social", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", base)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != 200 {
		t.Fatalf("the sign-in start answered %d: %s", res.Code, res.Body)
	}
	target, err := url.Parse(res.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return target
}

// Google sends include_granted_scopes=true unless DisableIncludeGrantedScopes
// is set, and access_type, display and hd when they are configured; a call's
// additionalParams win.
func TestGoogleAuthorizationOptions(t *testing.T) {
	q := startAuthorization(t, "google", Google("client", "secret"), nil).Query()
	if q.Get("include_granted_scopes") != "true" || q.Has("access_type") || q.Has("display") || q.Has("hd") {
		t.Fatal("the default authorization parameters are wrong:", q)
	}
	p := GoogleWithOptions(GoogleOptions{ClientID: "client", ClientSecret: "secret", AccessType: "offline", Display: "popup", HostedDomain: "example.org"})
	p.AuthorizationParams.Set("prompt", "select_account consent")
	q = startAuthorization(t, "google", p, nil).Query()
	for key, want := range map[string]string{"include_granted_scopes": "true", "access_type": "offline", "display": "popup", "hd": "example.org", "prompt": "select_account consent"} {
		if q.Get(key) != want {
			t.Fatalf("%s is %q, want %q", key, q.Get(key), want)
		}
	}
	q = startAuthorization(t, "google", GoogleWithOptions(GoogleOptions{ClientID: "client", DisableIncludeGrantedScopes: true}), nil).Query()
	if q.Has("include_granted_scopes") {
		t.Fatal("DisableIncludeGrantedScopes still sent include_granted_scopes")
	}
	q = startAuthorization(t, "google", Google("client", "secret"), map[string]any{"additionalParams": map[string]any{"include_granted_scopes": "false"}}).Query()
	if q.Get("include_granted_scopes") != "false" {
		t.Fatal("a call's additionalParams did not win:", q.Get("include_granted_scopes"))
	}
}

// A directly submitted ID token may name any of the app's client IDs as its
// audience, and its authorized party must be one of them; the code exchange
// accepts ClientID only.
func TestGoogleAdditionalClientIDs(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := google("web", "secret", &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, nil, "ios", "android", "")
	issuer := "https://accounts.google.com"
	sign := func(aud any, azp string) string {
		claims := jwt.MapClaims{"iss": issuer, "aud": aud, "nonce": "n", "sub": "subject", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "email": "person@example.org", "email_verified": true}
		if azp != "" {
			claims["azp"] = azp
		}
		raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, tc := range []struct {
		name  string
		aud   any
		azp   string
		valid bool
	}{
		{"web", "web", "", true},
		{"ios", "ios", "", true},
		{"android", "android", "", true},
		{"android party for web", "web", "android", true},
		{"other audience", "other", "", false},
		{"other party", "web", "other", false},
		{"several audiences with web party", []string{"web", "other"}, "web", true},
		{"several audiences without party", []string{"web", "other"}, "", false},
	} {
		profile, _, err := p.VerifyIDToken(context.Background(), sign(tc.aud, tc.azp), "n")
		if tc.valid != (err == nil) || tc.valid && profile.Subject != "subject" {
			t.Fatalf("%s: valid=%v, got %v", tc.name, tc.valid, err)
		}
	}
	issuer = "accounts.google.com"
	if _, _, err := p.VerifyIDToken(context.Background(), sign("web", "android"), "n"); err != nil {
		t.Fatal("a native token with the bare issuer was refused:", err)
	}
	issuer = "https://accounts.google.com"
	web := (&oauth2.Token{AccessToken: "access"}).WithExtra(map[string]any{"id_token": sign("web", "")})
	if profile, err := p.Resolve(context.Background(), web, "n"); err != nil || profile.Subject != "subject" {
		t.Fatal("the code exchange refused a token for ClientID:", err)
	}
	token := (&oauth2.Token{AccessToken: "access"}).WithExtra(map[string]any{"id_token": sign("ios", "")})
	if _, err := p.Resolve(context.Background(), token, "n"); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatal("the code exchange accepted a token issued to another client ID:", err)
	}
}
