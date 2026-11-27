package sqlstore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/mcp"
	"github.com/Plain-Org/plain-auth/schema"
)

// Two auth instances on one database guard the same MCP resource with
// RequireAuth, whose replay store defaults to that database: a DPoP proof
// the first accepts, the second refuses, on SQLite, PostgreSQL and MySQL.
func TestRequireAuthSharedReplay(t *testing.T) {
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
			const origin = "https://mcp.example.test"
			instance := func() (*auth.Auth, *Store) {
				s, err := OpenWithOptions(ctx, dialect, dsn, []string{"jwt", "oauth-provider"}, schema.Options{})
				must(err)
				t.Cleanup(func() { s.Close() })
				keys, err := auth.NewJWT(auth.JWTOptions{})
				must(err)
				off := false
				a, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("c", 40), Store: s, Plugins: []auth.Plugin{keys}, RateLimit: &off})
				must(err)
				return a, s
			}
			first, firstStore := instance()
			second, secondStore := instance()
			resource := first.PublicURL()
			key := newDPoPKey(t)
			now := time.Now()
			token, err := first.SignJWT(ctx, "user", auth.JWTSignOptions{Type: "at+jwt", Issuer: first.OAuthIssuer(), Audience: []string{resource}, IssuedAt: now, ExpiresAt: now.Add(time.Minute),
				Claims: map[string]any{"azp": "client", "cnf": map[string]any{"jkt": key.thumb}}})
			must(err)
			sum := sha256.Sum256([]byte(token))
			claims, _ := json.Marshal(map[string]any{"htm": "POST", "htu": resource, "iat": now.Unix(), "jti": rand.Text(), "ath": base64.RawURLEncoding.EncodeToString(sum[:])})
			signed, err := key.signer.Sign(claims)
			must(err)
			proof, err := signed.CompactSerialize()
			must(err)
			ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
			call := func(a *auth.Auth, s *Store) int {
				t.Helper()
				h, err := mcp.RequireAuth(a, s, ok, mcp.AuthOptions{})
				must(err)
				r := httptest.NewRequest("POST", resource, nil)
				r.Header.Set("Authorization", "DPoP "+token)
				r.Header.Set("DPoP", proof)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w.Code
			}
			if code := call(first, firstStore); code != 204 {
				t.Fatal("the first instance refused the proof", code)
			}
			if code := call(second, secondStore); code != 401 {
				t.Fatal("the second instance accepted a spent proof", code)
			}
		})
	}
}
