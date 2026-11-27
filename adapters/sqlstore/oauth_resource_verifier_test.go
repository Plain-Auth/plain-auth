package sqlstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
	jose "github.com/go-jose/go-jose/v4"
)

// Two access token verifiers that share the SQL store as their replay store
// spend a DPoP proof once between them, on SQLite, PostgreSQL and MySQL.
func TestResourceVerifierSharedReplay(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			s, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), []string{"oauth-provider"}, schema.Options{})
			must(err)
			t.Cleanup(func() { s.Close() })
			signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			must(err)
			keys := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &signing.PublicKey, KeyID: "ec", Algorithm: "ES256", Use: "sig"}}})
			}))
			t.Cleanup(keys.Close)
			const iss, aud = "https://issuer.example.test/api/auth", "https://api.example.test"
			verifier := func() *op.AccessTokenVerifier {
				v, err := op.NewAccessTokenVerifier(op.AccessTokenVerifierOptions{Issuer: iss, Audience: []string{aud}, JWKSURL: keys.URL, Transport: keys.Client().Transport,
					DPoP: op.DPoPOptions{ReplayStore: s}})
				must(err)
				return v
			}
			first, second := verifier(), verifier()
			key := newDPoPKey(t)
			claims, _ := json.Marshal(map[string]any{"iss": iss, "aud": aud, "sub": "user", "exp": time.Now().Unix() + 60, "cnf": map[string]any{"jkt": key.thumb}})
			tokenSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: signing}, new(jose.SignerOptions).WithHeader("kid", "ec").WithType("at+jwt"))
			must(err)
			object, err := tokenSigner.Sign(claims)
			must(err)
			token, err := object.CompactSerialize()
			must(err)
			sum := sha256.Sum256([]byte(token))
			proofClaims, _ := json.Marshal(map[string]any{"htm": "GET", "htu": aud + "/posts", "iat": time.Now().Unix(), "jti": rand.Text(), "ath": base64.RawURLEncoding.EncodeToString(sum[:])})
			signedProof, err := key.signer.Sign(proofClaims)
			must(err)
			proof, err := signedProof.CompactSerialize()
			must(err)
			req := op.ResourceRequest{Authorization: "DPoP " + token, DPoP: proof, Method: "GET", URL: aud + "/posts"}
			if _, err := first.VerifyRequest(ctx, req); err != nil {
				t.Fatal("the first verifier refused the proof", err)
			}
			_, err = second.VerifyRequest(ctx, req)
			var failure *op.ResourceFailure
			if !errors.As(err, &failure) || failure.Code != "invalid_dpop_proof" {
				t.Fatal("the second verifier accepted a spent proof", err)
			}
		})
	}
}

// A resource server's verifier introspects an opaque resource token
// through the issuer's real /oauth2/introspect as its linked client, and
// sees it inactive once revoked, on SQLite, PostgreSQL and MySQL.
func TestResourceVerifierIntrospection(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			s, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), []string{"oauth-provider"}, schema.Options{})
			must(err)
			t.Cleanup(func() { s.Close() })
			write := func(q string, args ...any) {
				t.Helper()
				_, err := s.db.ExecContext(ctx, s.bind(q), args...)
				must(err)
			}
			secret := "resource-verifier-secret"
			digest := sha256.Sum256([]byte(secret))
			for id, grants := range map[string]string{"app": `["client_credentials"]`, "api": `[]`} {
				write(`INSERT INTO "oauthClient" ("id","clientId","clientSecret","tokenEndpointAuthMethod","redirectUris","grantTypes","clientCredentialsScopes") VALUES (?,?,?,'client_secret_post','[]',?,?)`,
					id, id, base64.RawURLEncoding.EncodeToString(digest[:]), grants, `["reports"]`)
			}
			write(`INSERT INTO "oauthResource" ("id","identifier","name") VALUES ('api','urn:api','API')`)
			for _, id := range []string{"app", "api"} {
				write(`INSERT INTO "oauthClientResource" ("id","resourceId","clientId") VALUES (?,'urn:api',?)`, "link-"+id, id)
			}
			p, err := op.New(op.Options{Scopes: []string{"reports"}})
			must(err)
			const origin = "https://verifier.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("i", 40), Store: s, Plugins: []auth.Plugin{p}, RateLimit: &off})
			must(err)
			post := func(path string, form url.Values) map[string]any {
				t.Helper()
				req := httptest.NewRequest("POST", origin+"/api/auth"+path, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				var body map[string]any
				_ = json.Unmarshal(out.Body.Bytes(), &body)
				if out.Code != 200 {
					t.Fatal("the issuer refused", path, out.Code, body)
				}
				return body
			}
			token := post("/oauth2/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {"app"}, "client_secret": {secret}, "scope": {"reports"}, "resource": {"urn:api"}})["access_token"].(string)
			v, err := op.NewAccessTokenVerifier(op.AccessTokenVerifierOptions{Issuer: h.OAuthIssuer(), Audience: []string{"urn:api"}, Transport: guestTransport{h},
				Remote: &op.RemoteVerification{IntrospectionURL: origin + "/api/auth/oauth2/introspect", ClientID: "api", ClientSecret: secret}})
			must(err)
			claims, err := v.VerifyBearer(ctx, token, "reports")
			if err != nil || claims["client_id"] != "app" || claims["aud"] != "urn:api" {
				t.Fatal("the introspected token was refused", claims, err)
			}
			post("/oauth2/revoke", url.Values{"client_id": {"app"}, "client_secret": {secret}, "token": {token}})
			_, err = v.VerifyBearer(ctx, token)
			var failure *op.ResourceFailure
			if !errors.As(err, &failure) || failure.Description != "token inactive" {
				t.Fatal("a revoked token was not inactive", err)
			}
		})
	}
}
