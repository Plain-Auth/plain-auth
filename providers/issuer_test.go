package providers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	auth "github.com/FineStack/frost-auth"
	"github.com/FineStack/frost-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

func TestNamedIssuerFlows(t *testing.T) {
	data, err := os.ReadFile("testdata/issuers.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures map[string]struct {
		Authorization, Token, Scope, Claims string
		PKCE                                bool
		Input                               map[string]any
		Expected                            auth.OAuthProfile
	}
	if err = json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, f := range fixtures {
		t.Run(name, func(t *testing.T) {
			p, err := New(name, "client", "secret")
			issuer := map[string]string{"twitch": twitchIssuer, "paybin": "https://idp.paybin.io", "cognito": "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_abcdef"}[name]
			if name == "cognito" {
				p, err = Cognito("client", "secret", CognitoOptions{Domain: "auth.fixture.example.org", Region: "us-east-2", UserPoolID: "us-east-2_abcdef"})
			}
			if err != nil {
				t.Fatal(err)
			}
			var nonce, challenge string
			tokenCalls, keyCalls := 0, 0
			p.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				var body any
				switch r.URL.String() {
				case f.Token:
					tokenCalls++
					if err := r.ParseForm(); err != nil || r.Form.Get("code") != "issuer-code" || r.Form.Get("client_id") != "client" || r.Form.Get("client_secret") != "secret" {
						t.Fatal("issuer token exchange")
					}
					if f.PKCE && oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")) != challenge {
						t.Fatal("issuer PKCE")
					}
					raw := signedClaims(t, key, issuer, f.Expected.Subject, nonce, f.Input)
					body = map[string]any{"access_token": "access", "token_type": "bearer", "id_token": raw}
				case "https://idp.paybin.io/.well-known/openid-configuration":
					body = map[string]any{"issuer": issuer, "authorization_endpoint": f.Authorization, "token_endpoint": f.Token, "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}}
				case issuer + "/keys", issuer + "/.well-known/jwks.json":
					keyCalls++
					body = map[string]any{"keys": []any{map[string]string{"kty": "RSA", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}}
				case "https://auth.fixture.example.org/oauth2/userinfo":
					if r.Header.Get("Authorization") != "Bearer cognito-only" {
						t.Fatal("missing Cognito bearer")
					}
					body = map[string]any{"sub": "fixture-sub", "email": "person@example.org", "username": "user", "email_verified": "true"}
				default:
					t.Fatalf("unexpected issuer endpoint %s", r.URL)
				}
				data, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(data))}, nil
			})}
			store, err := sqlite.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			const base = "https://app.example.org"
			h, err := auth.New(auth.Options{BaseURL: base, Secret: strings.Repeat("s", 32), Store: store, SocialProviders: map[string]auth.OAuthProvider{name: p}})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", base+"/api/auth/sign-in/social", strings.NewReader(`{"provider":"`+name+`"}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", base)
			res := httptest.NewRecorder()
			h.ServeHTTP(res, r)
			loc, err := url.Parse(res.Header().Get("Location"))
			if err != nil || res.Code != 200 {
				t.Fatalf("sign-in %d %v", res.Code, err)
			}
			q := loc.Query()
			if name == "cognito" && strings.Contains(loc.RawQuery, "+") {
				t.Fatal("Cognito scope encoding")
			}
			loc.RawQuery = ""
			nonce, challenge = q.Get("nonce"), q.Get("code_challenge")
			if loc.String() != f.Authorization || q.Get("scope") != f.Scope || q.Get("claims") != f.Claims || nonce == "" || (challenge != "") != f.PKCE {
				t.Fatalf("authorization %v", q)
			}
			r = httptest.NewRequest("GET", base+"/api/auth/callback/"+name+"?code=issuer-code&state="+q.Get("state"), nil)
			for _, cookie := range res.Result().Cookies() {
				r.AddCookie(cookie)
			}
			res = httptest.NewRecorder()
			h.ServeHTTP(res, r)
			if res.Code != 302 || tokenCalls != 1 || keyCalls != 1 {
				t.Fatalf("callback %d %s (requests %d,%d)", res.Code, res.Body, tokenCalls, keyCalls)
			}
			r = httptest.NewRequest("GET", base+"/api/auth/get-session", nil)
			for _, cookie := range res.Result().Cookies() {
				r.AddCookie(cookie)
			}
			res = httptest.NewRecorder()
			h.ServeHTTP(res, r)
			var actual auth.SessionResult
			if err := json.Unmarshal(res.Body.Bytes(), &actual); err != nil {
				t.Fatal(err)
			}
			want := f.Expected
			if actual.User.Name != want.Name || actual.User.Email != want.Email || actual.User.EmailVerified != want.EmailVerified || !reflect.DeepEqual(actual.User.Image, want.Image) {
				t.Errorf("user: %#v, want %#v", actual.User, want)
			}
			if name == "cognito" {
				ctx := context.WithValue(context.Background(), oauth2.HTTPClient, p.HTTPClient)
				got, err := p.Resolve(ctx, &oauth2.Token{AccessToken: "cognito-only"}, "")
				if err != nil || !got.EmailVerified || got.Name != "user" || got.Subject != "fixture-sub" {
					t.Fatalf("Cognito userinfo: %#v %v", got, err)
				}
			}
		})
	}
}
