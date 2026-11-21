package providers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

func TestGoogleVerifiesIDToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := google("client", "secret", &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, nil)
	for _, tc := range []struct {
		name, issuer, audience, nonce string
		valid                         bool
	}{
		{"valid", "https://accounts.google.com", "client", "state-nonce", true},
		{"wrong issuer", "https://other.example", "client", "state-nonce", false},
		{"wrong audience", "https://accounts.google.com", "other", "state-nonce", false},
		{"wrong nonce", "https://accounts.google.com", "client", "unrelated", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{"iss": tc.issuer, "aud": tc.audience, "nonce": tc.nonce, "sub": "subject", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "email": "person@example.org", "email_verified": true, "name": "Person"}
			raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			token := (&oauth2.Token{AccessToken: "access"}).WithExtra(map[string]any{"id_token": raw})
			result, err := p.Resolve(context.Background(), token, "state-nonce")
			if tc.valid {
				if err != nil || result.Subject != "subject" || !result.EmailVerified || result.Email != "person@example.org" {
					t.Fatalf("%#v, %v", result, err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid identity token")
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGitHubVerifiedEmail(t *testing.T) {
	for _, verified := range []bool{true, false} {
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Host != "api.github.com" || r.Header.Get("Authorization") != "Bearer access" {
				t.Fatalf("unexpected API request %s", r.URL)
			}
			var body string
			switch r.URL.Path {
			case "/user":
				body = `{"id":42,"login":"person","email":null}`
			case "/user/emails":
				if verified {
					body = `[{"email":"person@example.org","primary":true,"verified":true}]`
				} else {
					body = `[{"email":"person@example.org","primary":true,"verified":false}]`
				}
			default:
				t.Fatalf("path %s", r.URL.Path)
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})}
		ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
		p, err := GitHub("client", "secret").Resolve(ctx, &oauth2.Token{AccessToken: "access"}, "nonce")
		if err != nil || p.Subject != "42" || p.Email != "person@example.org" || p.EmailVerified != verified || p.Name != "person" {
			t.Fatalf("%#v %v", p, err)
		}
	}
}
