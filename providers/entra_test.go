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
	"os"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestSingleTenantEntraProfile(t *testing.T) {
	const tenant = "363368ff-7777-452f-886c-a111d48741bb"
	const issuer = microsoftAuthority + "/" + tenant + "/v2.0"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var graph any
	var graphCalls int
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var payload any
		switch r.URL.String() {
		case issuer + "/.well-known/openid-configuration":
			payload = map[string]any{"issuer": issuer, "authorization_endpoint": microsoftAuthority + "/" + tenant + "/oauth2/v2.0/authorize", "token_endpoint": microsoftAuthority + "/" + tenant + "/oauth2/v2.0/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}}
		case issuer + "/keys":
			payload = map[string]any{"keys": []any{map[string]string{"kty": "RSA", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}}
		case "https://graph.microsoft.com/oidc/userinfo":
			if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer access" {
				t.Fatal("invalid Graph UserInfo request")
			}
			graphCalls++
			payload = graph
		default:
			t.Fatalf("unexpected request %s", r.URL)
		}
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
	})}
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, client)
	for _, bad := range []string{"", "common", "consumers", "organizations", "invalid"} {
		if _, err := MicrosoftEntraID(ctx, bad, "client", "secret"); err == nil {
			t.Fatalf("accepted tenant %q", bad)
		}
	}
	p, err := MicrosoftEntraID(ctx, strings.ToUpper(tenant), "client", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.Config.Scopes, " ") != "openid profile email" || p.Config.Endpoint.AuthURL != microsoftAuthority+"/"+tenant+"/oauth2/v2.0/authorize" {
		t.Fatal("wrong Entra authorization settings")
	}

	var cases []struct {
		Name, WantEmail, WantName string
		WantVerified              bool
		Token, Graph              map[string]any
	}
	data, err := os.ReadFile("testdata/entra_profiles.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			graph = c.Graph
			raw := signedClaims(t, key, issuer, "pairwise-id", "proof", c.Token)
			token := (&oauth2.Token{AccessToken: "access"}).WithExtra(map[string]any{"id_token": raw})
			before := graphCalls
			got, err := p.Resolve(ctx, token, "proof")
			if err != nil || got.Subject != "object-id" || got.Email != c.WantEmail || got.Name != c.WantName || got.EmailVerified != c.WantVerified || graphCalls != before+1 {
				t.Fatal("Entra profile", got, err)
			}
			base, _, err := p.VerifyIDToken(ctx, raw, "proof")
			if err != nil || base.Subject != "object-id" || graphCalls != before+1 {
				t.Fatal("native verification", base, err)
			}
		})
	}
	for _, claims := range []map[string]any{{"tid": tenant}, {"oid": "object-id", "tid": "different"}, {"oid": "object-id", "tid": tenant, "aud": "another"}} {
		raw := signedClaims(t, key, issuer, "pairwise-id", "proof", claims)
		before := graphCalls
		if _, err := p.Resolve(ctx, (&oauth2.Token{AccessToken: "access"}).WithExtra(map[string]any{"id_token": raw}), "proof"); err == nil || graphCalls != before {
			t.Fatal("accepted invalid directory identity")
		}
	}
}

func TestEntraVerificationFollowsTheSelectedEmail(t *testing.T) {
	result := entraProfile(profileData{"oid": "object-id", "email": "one@example.org"}, profileData{"email": "two@example.org", "email_verified": true})
	if result.Email != "one@example.org" || result.EmailVerified {
		t.Fatal("Graph verification does not establish ownership of a different email address")
	}
}

// The code exchange posts the configured client secret to the tenant's
// token endpoint.
func TestEntraCodeExchangeSendsTheSecret(t *testing.T) {
	const tenant = "363368ff-7777-452f-886c-a111d48741bb"
	const issuer = microsoftAuthority + "/" + tenant + "/v2.0"
	tokenURL := microsoftAuthority + "/" + tenant + "/oauth2/v2.0/token"
	var exchanged bool
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var payload any
		switch r.URL.String() {
		case issuer + "/.well-known/openid-configuration":
			payload = map[string]any{"issuer": issuer, "authorization_endpoint": microsoftAuthority + "/" + tenant + "/oauth2/v2.0/authorize", "token_endpoint": tokenURL, "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}}
		case tokenURL:
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			user, pass, basic := r.BasicAuth()
			sent := basic && user == "client" && pass == "tenant-secret" || r.PostForm.Get("client_id") == "client" && r.PostForm.Get("client_secret") == "tenant-secret"
			if r.Method != http.MethodPost || r.PostForm.Get("code") != "code" || !sent {
				t.Fatal("the code exchange did not send the configured secret", r.Header, r.PostForm)
			}
			exchanged = true
			payload = map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600}
		default:
			t.Fatalf("unexpected request %s", r.URL)
		}
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
	})}
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, client)
	p, err := MicrosoftEntraID(ctx, tenant, "client", "tenant-secret")
	if err != nil {
		t.Fatal(err)
	}
	token, err := p.Config.Exchange(ctx, "code")
	if err != nil || token.AccessToken != "access" || !exchanged {
		t.Fatal("the tenant token endpoint was not used for the code exchange", err)
	}
}
