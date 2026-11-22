package sqlstore

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"

	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/schema"
	jose "github.com/go-jose/go-jose/v4"
)

type unboundMachineStore struct {
	auth.Store
	op.MachineTokenStore
	op.ConsentStore
}

type failedDPoPReplay struct{}

func (failedDPoPReplay) ReserveDPoPProof(context.Context, string, time.Time, time.Time) (bool, error) {
	return false, errors.New("private storage failure")
}

func TestDPoPMachineTokenIssuance(t *testing.T) {
	const base = "https://public.example.test"
	const mount = "/identity"
	const path = mount + "/oauth2/token"
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			_, key, err := ed25519.GenerateKey(rand.Reader)
			must(err)
			public := (&jose.JSONWebKey{Key: key}).Public()
			fingerprint, err := public.Thumbprint(crypto.SHA256)
			must(err)
			thumb := base64.RawURLEncoding.EncodeToString(fingerprint)
			opts := new(jose.SignerOptions).WithType("dpop+jwt").WithHeader("jwk", public)
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, opts)
			must(err)
			sign := func(target string) string {
				t.Helper()
				body, err := json.Marshal(map[string]any{"iat": time.Now().Unix(), "jti": rand.Text(), "htm": "POST", "htu": target})
				must(err)
				jwt, err := signer.Sign(body)
				must(err)
				compact, err := jwt.CompactSerialize()
				must(err)
				return compact
			}
			dsn := organizationTestDSN(t, dialect)
			s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
			must(err)
			t.Cleanup(func() { s.Close() })
			peer, err := Open(ctx, dialect, dsn)
			must(err)
			t.Cleanup(func() { peer.Close() })
			_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO "oauthClient" ("id","clientId","clientSecret","tokenEndpointAuthMethod","grantTypes","clientCredentialsScopes","redirectUris") VALUES ('reg','app','secret','client_secret_post',?,?,?)`), `["client_credentials"]`, `["reports"]`, `[]`)
			must(err)
			newHost := func(store auth.Store, options op.Options) http.Handler {
				t.Helper()
				options.Registration.VerifySecret = func(_ context.Context, raw, stored string) (bool, error) { return raw == stored, nil }
				plug, err := op.New(options)
				must(err)
				off := false
				host, err := auth.New(auth.Options{BaseURL: base, BasePath: mount, Secret: strings.Repeat("s", 40), Store: store, Plugins: []auth.Plugin{plug}, RateLimit: &off})
				must(err)
				return host
			}
			hosts := []http.Handler{newHost(s, op.Options{}), newHost(peer, op.Options{})}
			call := func(host http.Handler, route string, form url.Values, proofs ...string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, "http://private.internal"+route, strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				for _, v := range proofs {
					r.Header.Add("DPoP", v)
				}
				w := httptest.NewRecorder()
				host.ServeHTTP(w, r)
				return w
			}
			expect := func(w *httptest.ResponseRecorder, status int, code string) map[string]any {
				t.Helper()
				var object map[string]any
				if w.Code != status || json.Unmarshal(w.Body.Bytes(), &object) != nil || code != "" && object["error"] != code || strings.Contains(w.Body.String(), "private storage failure") {
					t.Fatalf("unexpected %d: %s", w.Code, w.Body.String())
				}
				return object
			}
			credentials := url.Values{"grant_type": {"client_credentials"}, "client_id": {"app"}, "client_secret": {"secret"}}
			// A bad caller does not consume the rightful sender's proof.
			proof := sign(base + path + "?x=1")
			invalid := url.Values{"grant_type": {"client_credentials"}, "client_id": {"app"}, "client_secret": {"invalid"}}
			expect(call(hosts[0], path, invalid, proof), 400, "invalid_client")
			issued := expect(call(hosts[0], path, credentials, proof), 200, "")
			if issued["token_type"] != "DPoP" {
				t.Fatal(issued)
			}
			introspect := url.Values{"client_id": {"app"}, "client_secret": {"secret"}, "token": {issued["access_token"].(string)}}
			claims := expect(call(hosts[1], mount+"/oauth2/introspect", introspect), 200, "")
			confirmation, _ := claims["cnf"].(map[string]any)
			if claims["active"] != true || claims["token_type"] != "DPoP" || confirmation["jkt"] != thumb {
				t.Fatal("bound token read as", claims)
			}
			expect(call(hosts[1], path, credentials, proof), 400, "invalid_dpop_proof")
			expect(call(hosts[1], path, credentials, sign("http://private.internal"+path)), 400, "invalid_dpop_proof")
			fresh := sign(base + path)
			expect(call(hosts[0], path, credentials, fresh, fresh), 400, "invalid_dpop_proof")
			expect(call(hosts[0], path, credentials, fresh), 200, "")
			if got := expect(call(hosts[0], path, credentials), 200, ""); got["token_type"] != "Bearer" {
				t.Fatal(got)
			}
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "oauthClient" SET "dpopBoundAccessTokens"=? WHERE "clientId"='app'`), true)
			must(err)
			expect(call(hosts[0], path, credentials), 400, "invalid_dpop_proof")
			expect(call(hosts[1], path, credentials, sign(base+path)), 200, "")
			// Two issuer instances racing to use one proof may mint one token.
			single := sign(base + path)
			var wins atomic.Int32
			var wg sync.WaitGroup
			for i := range 8 {
				wg.Go(func() {
					w := call(hosts[i%2], path, credentials, single)
					if w.Code == 200 {
						wins.Add(1)
					} else if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_dpop_proof") {
						t.Errorf("unexpected concurrent result %d %s", w.Code, w.Body.String())
					}
				})
			}
			wg.Wait()
			if wins.Load() != 1 {
				t.Fatalf("minted %d tokens with one proof", wins.Load())
			}
			custom := newHost(s, op.Options{DPoP: op.DPoPOptions{SigningAlgorithms: []string{"ES256"}}})
			expect(call(custom, path, credentials, sign(base+path)), 400, "invalid_dpop_proof")
			down := newHost(s, op.Options{DPoP: op.DPoPOptions{ReplayStore: failedDPoPReplay{}}})
			expect(call(down, path, credentials, sign(base+path)), 500, "")
			limited := newHost(unboundMachineStore{s, s, s}, op.Options{})
			expect(call(limited, path, credentials, sign(base+path)), 501, "")
			var total int
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "oauthAccessToken"`)).Scan(&total))
			if total != 5 {
				t.Fatalf("persisted %d tokens", total)
			}
		})
	}
}
