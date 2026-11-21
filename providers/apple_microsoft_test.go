package providers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	auth "github.com/nabuhadba/go-better-auth"
	"github.com/nabuhadba/go-better-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

func signedClaims(t *testing.T, key *rsa.PrivateKey, issuer, subject, nonce string, extra map[string]any) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": issuer, "sub": subject, "aud": "client", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "nonce": nonce}
	for k, v := range extra {
		claims[k] = v
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAppleFormPostAndNativeToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}
	var nonce, challenge string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://appleid.apple.com/auth/token" || r.Method != "POST" {
			t.Fatalf("unexpected Apple token request: %s %s", r.Method, r.URL)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("client_secret") != "client-jwt" || r.Form.Get("code") != "apple-code" || oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")) != challenge {
			t.Fatal("incorrect authorization code exchange")
		}
		raw := signedClaims(t, key, "https://appleid.apple.com", "apple-subject", nonce, map[string]any{"email": "person@example.org", "email_verified": "true"})
		data, _ := json.Marshal(map[string]any{"access_token": "access", "token_type": "bearer", "id_token": raw})
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(data)))}, nil
	})}
	p := appleProvider("client", "client-jwt", keys, client)
	hash := sha256.Sum256([]byte("native-nonce"))
	raw := signedClaims(t, key, "https://appleid.apple.com", "apple-subject", hex.EncodeToString(hash[:]), map[string]any{"email": "person@example.org", "email_verified": true})
	profile, _, err := p.VerifyIDToken(context.Background(), raw, "native-nonce")
	if err != nil || profile.Subject != "apple-subject" {
		t.Fatalf("Apple native profile %#v, %v", profile, err)
	}
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const base = "https://app.example.org"
	h, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: base, SocialProviders: map[string]auth.OAuthProvider{"apple": p}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", base+"/api/auth/sign-in/social", strings.NewReader(`{"provider":"apple","callbackURL":"/done"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", base)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	u, err := url.Parse(res.Header().Get("Location"))
	if err != nil || res.Code != 200 {
		t.Fatalf("sign-in: %d %v", res.Code, err)
	}
	q := u.Query()
	nonce, challenge = q.Get("nonce"), q.Get("code_challenge")
	if u.Host != "appleid.apple.com" || q.Get("scope") != "email name" || q.Get("response_type") != "code id_token" || q.Get("response_mode") != "form_post" || challenge == "" {
		t.Fatalf("authorize URL %s", u)
	}
	var binding *http.Cookie
	for _, c := range res.Result().Cookies() {
		if strings.HasSuffix(c.Name, "oauth_state") {
			binding = c
		}
	}
	if binding == nil || binding.SameSite != http.SameSiteLaxMode || !binding.Secure {
		t.Fatal("expected secure state cookie")
	}
	values := url.Values{"code": {"apple-code"}, "state": {q.Get("state")}, "id_token": {"front-channel-unused"}, "user": {`{"name":{"firstName":"A","lastName":"Person"},"email":"ignored@example.org"}`}}
	// A cross-site form POST has no SameSite=Lax state cookie.
	req = httptest.NewRequest("POST", base+"/api/auth/callback/apple", strings.NewReader(values.Encode()))
	req.Header.Set("Origin", "https://appleid.apple.com")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res = httptest.NewRecorder()
	h.ServeHTTP(res, req)
	target := res.Header().Get("Location")
	if res.Code != 302 || !strings.HasPrefix(target, base+"/api/auth/callback/apple?") || strings.Contains(target, "front-channel-unused") {
		t.Fatalf("form callback: %d %q", res.Code, target)
	}
	req = httptest.NewRequest("GET", target, nil)
	req.AddCookie(binding)
	res = httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != 302 || res.Header().Get("Location") != "/done" {
		t.Fatalf("final callback: %d %s", res.Code, res.Body)
	}
	req = httptest.NewRequest("GET", base+"/api/auth/get-session", nil)
	for _, c := range res.Result().Cookies() {
		if strings.HasSuffix(c.Name, "session_token") {
			req.AddCookie(c)
		}
	}
	res = httptest.NewRecorder()
	h.ServeHTTP(res, req)
	var session auth.SessionResult
	if err := json.Unmarshal(res.Body.Bytes(), &session); err != nil || session.User.Name != "A Person" || session.User.Email != "person@example.org" {
		t.Fatalf("session %#v %v", session, err)
	}
}

func TestMicrosoftTenantAndMailboxClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}
	const org = "10000000-aaaa-0000-bbbb-000000000000"
	for _, tc := range []struct {
		mode, tid, issuer string
		allowed, verified bool
	}{
		{"organizations", org, org, true, true}, {"organizations", microsoftConsumers, microsoftConsumers, false, false},
		{"consumers", microsoftConsumers, microsoftConsumers, true, true}, {"consumers", org, org, false, false},
		{"common", org, microsoftConsumers, false, false}, {org, org, org, true, true},
	} {
		p := microsoftProvider("client", "secret", tc.mode, true, keys, nil)
		raw := signedClaims(t, key, microsoftAuthority+"/"+tc.issuer+"/v2.0", "pairwise-sub", "nonce", map[string]any{"oid": "object-id", "tid": tc.tid, "email": "person@example.org", "verified_primary_email": []string{"person@example.org"}})
		actual, _, err := p.VerifyIDToken(context.Background(), raw, "nonce")
		if !tc.allowed {
			if err == nil {
				t.Fatalf("accepted %s token for %s", tc.tid, tc.mode)
			}
			continue
		}
		if err != nil || actual.Subject != "object-id" || actual.EmailVerified != tc.verified {
			t.Fatalf("%s: %#v %v", tc.mode, actual, err)
		}
	}
	p := microsoftProvider("client", "secret", "common", true, keys, nil)
	raw := signedClaims(t, key, microsoftAuthority+"/"+org+"/v2.0", "sub", "nonce", map[string]any{"oid": "oid", "tid": org, "email": "person@example.org"})
	claims, _, err := p.VerifyIDToken(context.Background(), raw, "nonce")
	if err != nil || claims.EmailVerified {
		t.Fatalf("missing Microsoft verification claim: %#v %v", claims, err)
	}
}
