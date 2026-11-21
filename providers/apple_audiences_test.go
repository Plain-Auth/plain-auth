package providers

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/sqlite"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

func TestAppleNativeAudiences(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, Algorithm: "RS256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://appleid.apple.com/auth/keys" || r.Method != "GET" {
			t.Fatalf("unexpected Apple signature key request: %s %s", r.Method, r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(jwks)))}, nil
	})}
	const web = "org.example.service"
	const mobile = "org.example.app"
	const watch = "org.example.watch"
	const issuer = "https://appleid.apple.com"
	opts := AppleOptions{ClientID: web, ClientSecret: "developer-secret", HTTPClient: httpClient, AppBundleIdentifier: mobile}
	p, err := AppleWithOptions(opts)
	if err != nil {
		t.Fatal(err)
	}
	native := signedClaims(t, key, issuer, "apple-user", "native-nonce", map[string]any{"aud": mobile, "email": "mobile@example.test", "email_verified": true})
	webToken := signedClaims(t, key, issuer, "apple-user", "web-nonce", map[string]any{"aud": web})
	if p.Config.ClientID != web {
		t.Fatal("native audience replaced browser client ID")
	}
	if _, _, err := p.VerifyIDToken(t.Context(), webToken, "web-nonce"); err == nil {
		t.Fatal("native verifier accepted unconfigured web audience")
	}
	access := &oauth2.Token{AccessToken: "web-access"}
	if _, err := p.Resolve(t.Context(), access.WithExtra(map[string]any{"id_token": native}), "native-nonce"); err == nil {
		t.Fatal("browser exchange accepted native audience")
	}
	if _, err := p.Resolve(t.Context(), access.WithExtra(map[string]any{"id_token": webToken}), "web-nonce"); err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const base = "https://app.example.org"
	h, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("x", 32), BaseURL: base, SocialProviders: map[string]auth.OAuthProvider{"apple": p}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{"provider": "apple", "idToken": map[string]any{"token": native, "nonce": "native-nonce"}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", base+"/api/auth/sign-in/social", strings.NewReader(string(data)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", base)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	var login auth.AuthResult
	if json.Unmarshal(resp.Body.Bytes(), &login) != nil || resp.Code != 200 || login.Token == "" || login.User.Email != "mobile@example.test" || len(resp.Result().Cookies()) == 0 {
		t.Fatal("native Apple login did not issue the expected application session", resp.Code)
	}
	opts.NativeAudiences = []string{web, watch}
	p, err = AppleWithOptions(opts)
	if err != nil {
		t.Fatal(err)
	}
	opts.NativeAudiences[0] = mobile
	for _, tc := range []struct {
		name  string
		aud   any
		party string
		valid bool
	}{
		{"explicit web", web, "", true}, {"explicit watch", watch, "", true},
		{"bundle overridden", mobile, "", false}, {"unknown app", "org.example.other", "", false},
		{"authorized multi", []string{watch, web}, watch, true},
		{"missing party", []string{watch, web}, "", false},
		{"foreign party", []string{watch, web}, mobile, false},
		{"unlisted party", []string{watch, "org.example.other"}, web, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := signedClaims(t, key, issuer, "apple-user", "nonce", map[string]any{"aud": tc.aud, "azp": tc.party})
			_, expiry, err := p.VerifyIDToken(t.Context(), raw, "nonce")
			if (err == nil) != tc.valid || err == nil && !expiry.After(time.Now()) {
				t.Fatal("unexpected native audience decision", err)
			}
		})
	}
	opts.NativeAudiences = []string{""}
	if _, err := AppleWithOptions(opts); err == nil {
		t.Fatal("empty explicit audience accepted")
	}
}
