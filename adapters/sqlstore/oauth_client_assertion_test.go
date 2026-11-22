package sqlstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/schema"
	jose "github.com/go-jose/go-jose/v4"
)

type clientPublicKeyTransport func(*http.Request) (*http.Response, error)

func (t clientPublicKeyTransport) RoundTrip(r *http.Request) (*http.Response, error) { return t(r) }

func TestOAuthClientAssertionAcrossPools(t *testing.T) {
	const origin = "https://issuer.example.test"
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			var hosts []*auth.Auth
			var stores []*Store
			var duringIssue func()
			const keyOrigin = "https://keys.example.test"
			var publicKeys string
			transport := clientPublicKeyTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != keyOrigin+"/public" {
					return nil, errors.New("unknown key URL")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(publicKeys)), Header: http.Header{"Content-Type": {"application/jwk-set+json"}}}, nil
			})
			for range 2 {
				s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
				must(err)
				t.Cleanup(func() { s.Close() })
				stores = append(stores, s)
				p, err := op.New(op.Options{Assertions: op.AssertionOptions{ClockTolerance: 3 * time.Second, JWKSTransport: transport}, Tokens: op.TokenOptions{
					GenerateOpaqueToken: func(context.Context) (string, error) {
						if duringIssue != nil {
							duringIssue()
						}
						return rand.Text(), nil
					},
				}})
				must(err)
				off := false
				h, err := auth.New(auth.Options{Store: s, Plugins: []auth.Plugin{p}, Secret: strings.Repeat("s", 40), BaseURL: origin, TrustedOrigins: []string{keyOrigin}, RateLimit: &off})
				must(err)
				hosts = append(hosts, h)
			}
			store := stores[0]
			write := func(query string, args ...any) {
				t.Helper()
				_, err := store.db.ExecContext(ctx, store.bind(query), args...)
				must(err)
			}
			keys := func() (string, jose.Signer) {
				t.Helper()
				pub, priv, err := ed25519.GenerateKey(rand.Reader)
				must(err)
				encoded, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, Algorithm: "EdDSA", Use: "sig", KeyID: "test"}}})
				must(err)
				signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
				must(err)
				return string(encoded), signer
			}
			jwks, signer := keys()
			for _, id := range []string{"first", "second"} {
				write(`INSERT INTO "oauthClient" ("id","clientId","tokenEndpointAuthMethod","redirectUris","jwks","grantTypes","clientCredentialsScopes") VALUES (?,?,?,?,?,?,?)`, id, id, "private_key_jwt", "[]", jwks, `["client_credentials"]`, `["read"]`)
			}
			publicKeys = jwks
			write(`UPDATE "oauthClient" SET "jwks"=NULL, "jwksUri"=? WHERE "clientId"=?`, keyOrigin+"/public", "second")
			exp := time.Now().Unix() + 90
			sign := func(id, jti string) string {
				t.Helper()
				claims, err := json.Marshal(map[string]any{"iss": id, "sub": id, "aud": origin + "/api/auth", "exp": exp, "jti": jti})
				must(err)
				signed, err := signer.Sign(claims)
				must(err)
				raw, err := signed.CompactSerialize()
				must(err)
				return raw
			}
			send := func(h *auth.Auth, a string) *httptest.ResponseRecorder {
				form := url.Values{"grant_type": {"client_credentials"}, "client_assertion": {a}, "client_assertion_type": {op.ClientAssertionType}}
				req := httptest.NewRequest(http.MethodPost, origin+"/api/auth/oauth2/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, req)
				return w
			}
			shared := sign("first", "once")
			start := make(chan struct{})
			results := make(chan *httptest.ResponseRecorder, 2)
			for _, h := range hosts {
				go func() { <-start; results <- send(h, shared) }()
			}
			close(start)
			var statuses []int
			for range 2 {
				w := <-results
				if w.Code != 200 && !strings.Contains(w.Body.String(), "jti has already been used") {
					t.Fatalf("unexpected response %d %s", w.Code, w.Body.String())
				}
				statuses = append(statuses, w.Code)
			}
			slices.Sort(statuses)
			if !slices.Equal(statuses, []int{200, 400}) {
				t.Fatalf("concurrent responses %v", statuses)
			}
			sum := sha256.Sum256([]byte("private_key_jwt:first:once"))
			var expires time.Time
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "expiresAt" FROM "oauthClientAssertion" WHERE "id"=?`), base64.RawURLEncoding.EncodeToString(sum[:24])).Scan(&expires))
			if expires.Unix() != exp+3 {
				t.Fatalf("wrong replay expiry %v", expires)
			}
			if w := send(hosts[1], sign("second", "once")); w.Code != 200 {
				t.Fatalf("per-client jti namespace: %d %s", w.Code, w.Body.String())
			}

			replacement, _ := keys()
			duringIssue = func() { write(`UPDATE "oauthClient" SET "jwks"=? WHERE "clientId"=?`, replacement, "first") }
			if w := send(hosts[1], sign("first", "rotating")); w.Code != 400 || !strings.Contains(w.Body.String(), "keys have changed") {
				t.Fatalf("rotation during issuance: %d %s", w.Code, w.Body.String())
			}
			duringIssue = nil
			if w := send(hosts[0], sign("first", "old-key")); w.Code != 401 {
				t.Fatalf("retired key: %d %s", w.Code, w.Body.String())
			}
			var issued int
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "oauthAccessToken" WHERE "clientId"=?`), "first").Scan(&issued))
			if issued != 1 {
				t.Fatalf("expected one issued token, got %d", issued)
			}
		})
	}
}
