package providers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"github.com/golang-jwt/jwt/v5"
)

func TestDiscoveredOIDCDirectGrantAndExplicitLink(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "authorization_endpoint": issuer.URL + "/authorize", "token_endpoint": issuer.URL + "/token", "jwks_uri": issuer.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer issuer.Close()
	p, err := OpenIDConnect(context.Background(), issuer.URL, "client", "secret")
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler, err := auth.New(auth.Options{Store: store, BaseURL: "http://app.example.org", Secret: strings.Repeat("s", 32), EmailAndPassword: true, SocialProviders: map[string]auth.OAuthProvider{"work": p}})
	if err != nil {
		t.Fatal(err)
	}
	request := func(path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "http://app.example.org/api/auth/"+path, bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://app.example.org")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}
	email := "person@example.org"
	reg := request("sign-up/email", map[string]string{"name": "Person", "email": email, "password": "good-password-123"}, nil)
	if reg.Code != 200 {
		t.Fatalf("registration: %s", reg.Body.String())
	}
	var owner auth.AuthResult
	if err := json.Unmarshal(reg.Body.Bytes(), &owner); err != nil || owner.User.ID == "" {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	for _, c := range reg.Result().Cookies() {
		if c.Name == "authn.session_token" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("missing session cookie")
	}
	grant := func(email, subject, nonce string) map[string]any {
		claims := jwt.MapClaims{"iss": issuer.URL, "aud": "client", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "sub": subject, "nonce": nonce, "email": email, "name": "OIDC User", "email_verified": true}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "test"
		raw, err := token.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"provider": "work", "idToken": map[string]string{"token": raw, "nonce": nonce}}
	}
	link := grant(email, "subject", "link-original")
	if res := request("link-social", link, nil); res.Code != 401 {
		t.Fatalf("anonymous link: %d", res.Code)
	}
	if res := request("link-social", grant("other@example.org", "other-subject", "link-other"), cookie); res.Code != 401 {
		t.Fatalf("foreign email link: %d %s", res.Code, res.Body)
	}
	if res := request("link-social", link, cookie); res.Code != 200 || len(res.Result().Cookies()) != 0 {
		t.Fatalf("explicit link: %d %s", res.Code, res.Body)
	}
	login := grant(email, "subject", "login")
	res := request("sign-in/social", login, nil)
	if res.Code != 200 {
		t.Fatalf("direct sign-in: %d %s", res.Code, res.Body)
	}
	var actual auth.AuthResult
	if err := json.Unmarshal(res.Body.Bytes(), &actual); err != nil || actual.User.ID != owner.User.ID || actual.Token == "" {
		t.Fatalf("unexpected identity %#v, %v", actual, err)
	}
	if res := request("sign-in/social", login, nil); res.Code != 401 {
		t.Fatalf("reused token: %d %s", res.Code, res.Body)
	}
	invalid := grant(email, "subject", "real")
	invalid["idToken"].(map[string]string)["nonce"] = "wrong"
	if res := request("sign-in/social", invalid, nil); res.Code != 401 {
		t.Fatalf("nonce mismatch: %d", res.Code)
	}
}

// OpenIDConnect refuses discovery that does not let it verify ID tokens: no
// signing keys or insecure ones, no or another issuer, or no token endpoint.
// No signing keys are fetched for a refused issuer.
func TestOpenIDConnectRefusesUnverifiableDiscovery(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(base string, doc map[string]any)
	}{
		{"no jwks_uri", func(_ string, d map[string]any) { delete(d, "jwks_uri") }},
		{"insecure jwks_uri", func(_ string, d map[string]any) { d["jwks_uri"] = "http://keys.example/jwks" }},
		{"no issuer", func(_ string, d map[string]any) { delete(d, "issuer") }},
		{"another issuer", func(_ string, d map[string]any) { d["issuer"] = "https://other.example" }},
		{"no token endpoint", func(_ string, d map[string]any) { delete(d, "token_endpoint") }},
	} {
		keys := 0
		var issuer *httptest.Server
		issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration":
				doc := map[string]any{"issuer": issuer.URL, "authorization_endpoint": issuer.URL + "/authorize", "token_endpoint": issuer.URL + "/token", "jwks_uri": issuer.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}}
				tc.edit(issuer.URL, doc)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(doc)
			case "/keys":
				keys++
			}
		}))
		if _, err := OpenIDConnect(context.Background(), issuer.URL, "client", "secret"); err == nil || keys != 0 {
			t.Fatalf("%s: OpenIDConnect returned %v after %d key requests", tc.name, err, keys)
		}
		issuer.Close()
	}
}

// DiscoveryHeaders reach the discovery request and signing keys on the
// issuer's origin, never the token endpoint or keys elsewhere, while the
// provider's TokenHeaders reach its token request; discovery
// follows no redirects, and an invalid header fails before any request. With
// DisableNonceBinding a browser sign-in sends no nonce and accepts an ID
// token without one, while a directly submitted token still needs its nonce.
func TestOpenIDConnectWithOptions(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := map[string]any{"keys": []any{map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}}
	var mu sync.Mutex
	seen := map[string][]string{}
	record := func(name string, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		seen[name] = append(seen[name], r.Header.Get("Epic-Client-ID"))
	}
	headersAt := func(name string) []string {
		mu.Lock()
		defer mu.Unlock()
		out := seen[name]
		delete(seen, name)
		return out
	}
	otherKeys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record("other keys", r)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer otherKeys.Close()
	var issuer *httptest.Server
	keysURI, tokenHeader := "", ""
	tokenHeaderLeaked := false
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r.URL.Path, r)
		if r.URL.Path != "/token" && r.Header.Get("X-Token") != "" {
			mu.Lock()
			tokenHeaderLeaked = true
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			jwksURI := issuer.URL + "/keys"
			if keysURI != "" {
				jwksURI = keysURI
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "authorization_endpoint": issuer.URL + "/authorize", "token_endpoint": issuer.URL + "/token", "jwks_uri": jwksURI, "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/moved/.well-known/openid-configuration":
			http.Redirect(w, r, issuer.URL+"/final/.well-known/openid-configuration", http.StatusFound)
		case "/final/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL + "/moved", "authorization_endpoint": issuer.URL + "/authorize", "token_endpoint": issuer.URL + "/token", "jwks_uri": issuer.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			_ = json.NewEncoder(w).Encode(jwks)
		case "/token":
			mu.Lock()
			tokenHeader = r.Header.Get("X-Token")
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "id_token": signedClaims(t, key, issuer.URL, "subject", "", map[string]any{"email": "person@example.org", "email_verified": true})})
		}
	}))
	defer issuer.Close()
	headers := http.Header{"epic-client-id": {"epic"}}
	p, err := OpenIDConnectWithOptions(context.Background(), OpenIDConnectOptions{Issuer: issuer.URL, ClientID: "client", ClientSecret: "secret", DiscoveryHeaders: headers, DisableNonceBinding: true})
	if err != nil {
		t.Fatal(err)
	}
	p.TokenHeaders = http.Header{"X-Token": {"token-header"}}
	f := runBrowserFlow(t, "work", p)
	if to := f.callback.Header().Get("Location"); to != "/done" || f.authorize.Query().Has("nonce") {
		t.Fatal("the sign-in without nonce binding landed at", to, "after authorizing with", f.authorize.Query())
	}
	if got := headersAt("/.well-known/openid-configuration"); len(got) != 1 || got[0] != "epic" {
		t.Fatal("discovery sent", got)
	}
	if got := headersAt("/keys"); len(got) == 0 || got[0] != "epic" {
		t.Fatal("the same-origin keys request sent", got)
	}
	mu.Lock()
	leaked := tokenHeaderLeaked
	mu.Unlock()
	if leaked {
		t.Fatal("TokenHeaders reached discovery or the keys")
	}
	mu.Lock()
	gotToken := tokenHeader
	mu.Unlock()
	if got := headersAt("/token"); len(got) != 1 || got[0] != "" || gotToken != "token-header" {
		t.Fatal("the token request sent", got, gotToken)
	}
	direct := func(p auth.OAuthProvider, tokenNonce, nonce string) error {
		_, _, err := p.VerifyIDToken(context.Background(), signedClaims(t, key, issuer.URL, "subject", tokenNonce, map[string]any{"email": "person@example.org", "email_verified": true}), nonce)
		return err
	}
	if direct(p, "", "") == nil || direct(p, "n", "n") != nil {
		t.Fatal("a directly submitted token does not need its nonce")
	}

	bound, err := OpenIDConnect(context.Background(), issuer.URL, "client", "secret")
	if err != nil {
		t.Fatal(err)
	}
	f = runBrowserFlow(t, "work", bound)
	if to := f.callback.Header().Get("Location"); !strings.HasPrefix(to, "/oops?error=unable_to_get_user_info") || f.authorize.Query().Get("nonce") == "" {
		t.Fatal("a token without the nonce was accepted:", to)
	}
	if got := headersAt("/.well-known/openid-configuration"); len(got) != 1 || got[0] != "" {
		t.Fatal("discovery without headers sent", got)
	}

	keysURI = otherKeys.URL + "/keys"
	elsewhere, err := OpenIDConnectWithOptions(context.Background(), OpenIDConnectOptions{Issuer: issuer.URL, ClientID: "client", DiscoveryHeaders: headers})
	if err != nil {
		t.Fatal(err)
	}
	if direct(elsewhere, "n", "n") != nil {
		t.Fatal("keys on another origin could not verify a token")
	}
	if got := headersAt("other keys"); len(got) == 0 || got[0] != "" {
		t.Fatal("keys on another origin got", got)
	}
	keysURI = ""

	if _, err := OpenIDConnectWithOptions(context.Background(), OpenIDConnectOptions{Issuer: issuer.URL + "/moved", ClientID: "client", DiscoveryHeaders: headers}); err == nil {
		t.Fatal("discovery followed a redirect")
	}
	mu.Lock()
	seen = map[string][]string{}
	mu.Unlock()
	if _, err := OpenIDConnectWithOptions(context.Background(), OpenIDConnectOptions{Issuer: issuer.URL, ClientID: "client", DiscoveryHeaders: http.Header{"Bad Name": {"x"}}}); err == nil {
		t.Fatal("an invalid discovery header was accepted")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 0 {
		t.Fatal("a refused configuration still made requests:", seen)
	}
}
