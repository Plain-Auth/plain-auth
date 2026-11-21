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
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	auth "github.com/nabuhadba/go-better-auth"
	"github.com/nabuhadba/go-better-auth/adapters/sqlite"
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
