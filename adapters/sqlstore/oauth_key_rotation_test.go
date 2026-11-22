package sqlstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/schema"
	jose "github.com/go-jose/go-jose/v4"
)

// Both HTTP requests finish verifying against the original registration before either write begins.
type gatedClientKeyStore struct {
	*Store
	ready   chan<- struct{}
	proceed <-chan struct{}
}

func (s gatedClientKeyStore) RotateOAuthClientKeys(ctx context.Context, id, digest string, expires time.Time, keys json.RawMessage, check func(op.MachineClient) error) error {
	select {
	case s.ready <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-s.proceed:
	case <-ctx.Done():
		return ctx.Err()
	}
	return s.Store.RotateOAuthClientKeys(ctx, id, digest, expires, keys, check)
}

func TestOAuthClientKeyRotation(t *testing.T) {
	const origin = "https://rotation.example.test"
	const aud = origin + "/api/auth/oauth2/client/rotate-keys"
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
			open := func() *Store {
				t.Helper()
				s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
				must(err)
				t.Cleanup(func() { s.Close() })
				return s
			}
			store, peer := open(), open()
			call := func(s auth.Store) *client.Client {
				t.Helper()
				plugin, err := op.New(op.Options{ImmutableClientIDs: []string{"immutable"}, Assertions: op.AssertionOptions{AllowKeyRotation: true}})
				must(err)
				off := false
				h, err := auth.New(auth.Options{BaseURL: origin + "/", Secret: strings.Repeat("s", 40), Plugins: []auth.Plugin{plugin}, Store: s, RateLimit: &off})
				must(err)
				c, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
				must(err)
				return c
			}
			gen := func(kid string) (json.RawMessage, jose.Signer) {
				t.Helper()
				pub, priv, err := ed25519.GenerateKey(rand.Reader)
				must(err)
				b, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, Use: "sig", KeyID: kid, Algorithm: "EdDSA"}}})
				must(err)
				signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, (&jose.SignerOptions{}).WithHeader("kid", kid))
				must(err)
				return b, signer
			}
			old, signer := gen("old")
			nextA, _ := gen("a")
			nextB, _ := gen("b")
			sign := func(id string) string {
				t.Helper()
				data, err := json.Marshal(map[string]any{"iss": id, "sub": id, "aud": aud, "jti": rand.Text(), "exp": time.Now().Unix() + 90})
				must(err)
				signed, err := signer.Sign(data)
				must(err)
				v, err := signed.CompactSerialize()
				must(err)
				return v
			}
			exec := func(q string, args ...any) {
				t.Helper()
				_, err := store.db.ExecContext(ctx, store.bind(q), args...)
				must(err)
			}
			seed := func(id, method string, keys, uri any, disabled bool) {
				exec(`INSERT INTO "oauthClient" ("id","clientId","redirectUris","tokenEndpointAuthMethod","jwks","jwksUri","disabled") VALUES (?,?,?,?,?,?,?)`,
					id, id, "[]", method, keys, uri, disabled)
			}
			seed("racing", "private_key_jwt", string(old), nil, false)
			seed("retry", "private_key_jwt", string(old), nil, false)
			seed("immutable", "private_key_jwt", string(old), nil, false)
			seed("disabled", "private_key_jwt", string(old), nil, true)
			seed("remote", "private_key_jwt", nil, "https://keys.example.test/keys", false)
			seed("secret", "client_secret_basic", nil, nil, false)
			existing := func(id string) string {
				t.Helper()
				current, err := peer.LookupMachineClient(ctx, id)
				must(err)
				var set jose.JSONWebKeySet
				must(json.Unmarshal([]byte(current.JWKS), &set))
				if len(set.Keys) != 1 {
					t.Fatalf("unexpected stored key count %d", len(set.Keys))
				}
				return set.Keys[0].KeyID
			}
			count := func(want int) {
				t.Helper()
				var n int
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "oauthClientAssertion"`)).Scan(&n))
				if n != want {
					t.Fatalf("replay rows %d, want %d", n, want)
				}
			}
			c := call(store)
			problem := func(err error, status int, code string) {
				t.Helper()
				var p *auth.APIError
				if !errors.As(err, &p) || p.Status != status || p.Code != code {
					t.Fatalf("wanted %d %s, got %v", status, code, err)
				}
			}
			for _, id := range []string{"immutable", "disabled", "remote", "secret", "absent"} {
				_, err := c.RotateOAuthClientKeys(ctx, sign(id), nextA)
				problem(err, 400, "invalid_client")
			}
			count(0)
			ready, proceed := make(chan struct{}, 2), make(chan struct{})
			one, two := call(gatedClientKeyStore{store, ready, proceed}), call(gatedClientKeyStore{peer, ready, proceed})
			type result struct {
				kid string
				err error
			}
			out := make(chan result, 2)
			race := func(c *client.Client, kid, assertion string, keys json.RawMessage) {
				_, err := c.RotateOAuthClientKeys(ctx, assertion, keys)
				out <- result{kid, err}
			}
			go race(one, "a", sign("racing"), nextA)
			go race(two, "b", sign("racing"), nextB)
			for range 2 {
				select {
				case <-ready:
				case <-time.After(10 * time.Second):
					close(proceed)
					t.Fatal("clients did not reach the conditional update")
				}
			}
			close(proceed)
			var successes []string
			for range 2 {
				r := <-out
				if r.err != nil {
					problem(r.err, 409, "invalid_request")
				} else {
					successes = append(successes, r.kid)
				}
			}
			if !slices.Equal(successes, []string{existing("racing")}) {
				t.Fatalf("registered keys disagree with winner %v", successes)
			}
			count(1)

			// Force the key update itself to fail after the replay row was inserted.
			exec(`ALTER TABLE "oauthClient" RENAME COLUMN "updatedAt" TO "temporarilyUnavailable"`)
			retry := sign("retry")
			_, err := c.RotateOAuthClientKeys(ctx, retry, nextB)
			problem(err, 500, "INTERNAL_SERVER_ERROR")
			count(1)
			if existing("retry") != "old" {
				t.Fatal("failed rotation changed the key")
			}
			exec(`ALTER TABLE "oauthClient" RENAME COLUMN "temporarilyUnavailable" TO "updatedAt"`)
			resultKeys, err := c.RotateOAuthClientKeys(ctx, retry, nextB)
			must(err)
			if resultKeys.ClientID != "retry" || existing("retry") != "b" {
				t.Fatal("retry failed to install replacement keys")
			}
			count(2)
		})
	}
}
