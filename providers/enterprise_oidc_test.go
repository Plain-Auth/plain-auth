package providers

import (
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
	"strings"
	"testing"

	"github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/sqlite"
	"golang.org/x/oauth2"
)

func TestEnterpriseOIDCPresets(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/enterprise_oidc.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct{ Name, Preset, Input, Issuer string }
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	presets := map[string]func(context.Context, string, string, string) (stonewrit.OAuthProvider, error){"auth0": Auth0, "keycloak": Keycloak, "okta": Okta}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			base := strings.TrimRight(tc.Issuer, "/")
			var nonce, challenge string
			transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				var response any
				switch r.URL.String() {
				case base + "/.well-known/openid-configuration":
					response = map[string]any{"issuer": tc.Issuer, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token", "jwks_uri": base + "/keys", "end_session_endpoint": base + "/end", "id_token_signing_alg_values_supported": []string{"RS256"}}
				case base + "/token":
					user, pass, _ := r.BasicAuth()
					if err := r.ParseForm(); err != nil || r.PostForm.Get("code") != "fixture" || user != "client" || pass != "secret" ||
						r.PostForm.Get("redirect_uri") != "https://app.example/identity/callback/"+tc.Name ||
						oauth2.S256ChallengeFromVerifier(r.PostForm.Get("code_verifier")) != challenge {
						t.Fatal("invalid authorization code exchange parameters")
					}
					response = map[string]any{"access_token": "fixture", "token_type": "Bearer", "id_token": signedClaims(t, key, tc.Issuer, "subject", nonce, map[string]any{"email": "owner@example.test", "email_verified": true, "name": "Owner"})}
				case base + "/keys":
					response = map[string]any{"keys": []any{map[string]string{"kty": "RSA", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}}
				default:
					t.Fatalf("unexpected provider request %s", r.URL)
				}
				data, err := json.Marshal(response)
				if err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(data)))}, nil
			})
			ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: transport})
			provider, err := presets[tc.Preset](ctx, tc.Input, "client", "secret")
			if err != nil {
				t.Fatal(err)
			}
			if provider.EndSessionEndpoint != base+"/end" {
				t.Fatal("missing discovered provider logout URL")
			}
			db, err := sqlite.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			instance, err := stonewrit.New(stonewrit.Options{Store: db, BaseURL: "https://app.example", BasePath: "/identity", Secret: strings.Repeat("x", 32), SocialProviders: map[string]stonewrit.OAuthProvider{tc.Name: provider}})
			if err != nil {
				t.Fatal(err)
			}
			start := httptest.NewRequest("POST", "https://app.example/identity/sign-in/social", strings.NewReader(`{"provider":"`+tc.Name+`"}`))
			start.Header.Set("Content-Type", "application/json")
			start.Header.Set("Origin", "https://app.example")
			w := httptest.NewRecorder()
			instance.ServeHTTP(w, start)
			location, err := url.Parse(w.Header().Get("Location"))
			if err != nil || w.Code != 200 {
				t.Fatal("start sign-in", w.Code, w.Body.String(), err)
			}
			q := location.Query()
			location.RawQuery = ""
			nonce, challenge = q.Get("nonce"), q.Get("code_challenge")
			if location.String() != base+"/authorize" || q.Get("scope") != "openid profile email" || nonce == "" || challenge == "" || q.Get("code_challenge_method") != "S256" {
				t.Fatal("discovered sign-in lost the registered issuer, scopes, nonce or PKCE")
			}
			back := httptest.NewRequest("GET", "https://app.example/identity/callback/"+tc.Name+"?code=fixture&state="+url.QueryEscape(q.Get("state")), nil)
			for _, cookie := range w.Result().Cookies() {
				back.AddCookie(cookie)
			}
			w = httptest.NewRecorder()
			instance.ServeHTTP(w, back)
			if w.Code != http.StatusFound {
				t.Fatal("callback", w.Code, w.Body.String())
			}
			read := httptest.NewRequest("GET", "https://app.example/identity/get-session", nil)
			for _, cookie := range w.Result().Cookies() {
				read.AddCookie(cookie)
			}
			session, err := instance.GetSession(t.Context(), read.Header)
			if err != nil || session == nil || session.User.Email != "owner@example.test" || !session.User.EmailVerified {
				t.Fatal("verified enterprise identity did not produce a session", err)
			}
			wrongIssuer := signedClaims(t, key, "https://other.example", "subject", nonce, map[string]any{"email": "owner@example.test"})
			if _, _, err = provider.VerifyIDToken(t.Context(), wrongIssuer, nonce); err == nil {
				t.Fatal("accepted an ID token issued by a different tenant")
			}
		})
	}
}

func TestEnterpriseIssuerConfiguration(t *testing.T) {
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid issuer triggered discovery")
		return nil, nil
	})})
	for _, domain := range []string{"", "http://tenant.example", "https://name@tenant.example", "https://tenant.example/path", "https://tenant.example/?x=1"} {
		if _, err := Auth0(ctx, domain, "client", "secret"); err == nil {
			t.Errorf("accepted Auth0 domain %q", domain)
		}
	}
	for _, issuer := range []string{"id.example", "http://id.example/realm", "https://id.example/realm#section", "https://id.example/oauth2/default?x=1"} {
		if _, err := Keycloak(ctx, issuer, "client", "secret"); err == nil {
			t.Errorf("accepted Keycloak issuer %q", issuer)
		}
		if _, err := Okta(ctx, issuer, "client", "secret"); err == nil {
			t.Errorf("accepted Okta issuer %q", issuer)
		}
	}
}
