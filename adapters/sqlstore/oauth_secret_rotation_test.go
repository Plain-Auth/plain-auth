package sqlstore

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestOAuthClientSecretRotation(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			failed := func(err error, status int, code string) {
				t.Helper()
				var p *auth.APIError
				if !errors.As(err, &p) || p.Status != status || p.Code != code {
					t.Fatalf("expected %d %s, got %v", status, code, err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			open := func() *Store {
				t.Helper()
				s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider", "admin"}, schema.Options{})
				must(err)
				t.Cleanup(func() { s.Close() })
				return s
			}
			s, peer := open(), open()
			type barrier struct{ entered, release chan struct{} }
			var gate atomic.Pointer[barrier]
			var counter atomic.Int64
			var generateFixed atomic.Bool
			var failHash atomic.Bool
			const prefix = "rot_"
			hash := func(secret string) string {
				m := hmac.New(sha256.New, []byte("test local storage key"))
				m.Write([]byte(secret))
				return hex.EncodeToString(m.Sum(nil))
			}
			options := op.Options{ImmutableClientIDs: []string{"operator"}, Registration: op.RegistrationOptions{Enabled: true, SecretPrefix: prefix,
				GenerateClientSecret: func() (string, error) {
					if generateFixed.Load() {
						return "first", nil
					}
					return fmt.Sprintf("credential-%d", counter.Add(1)), nil
				},
				StoreSecret: func(ctx context.Context, raw string) (string, error) {
					if b := gate.Swap(nil); b != nil {
						close(b.entered)
						select {
						case <-b.release:
						case <-ctx.Done():
							return "", ctx.Err()
						}
					}
					if failHash.Load() {
						return "", errors.New("fixture storage hook failed")
					}
					return hash(raw), nil
				},
			}}
			host := func(s *Store) *client.Client {
				t.Helper()
				p, err := op.New(options)
				must(err)
				off := false
				const origin = "https://rotation.example.test"
				h, err := auth.New(auth.Options{BaseURL: origin, Store: s, Plugins: []auth.Plugin{p}, Secret: strings.Repeat("s", 40), EmailAndPassword: true, RateLimit: &off})
				must(err)
				c, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
				must(err)
				return c
			}
			owner, other := host(s), host(peer)
			account := func(c *client.Client, name string) string {
				t.Helper()
				signed, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: name, Email: name + "@rotate.test", Password: "local rotation password"})
				must(err)
				return signed.User.ID
			}
			ownerID := account(owner, "owner")
			otherID := account(other, "other")
			generateFixed.Store(true)
			app, err := owner.RegisterOAuthClient(ctx, op.RegistrationMetadata{RedirectURIs: []string{"https://app.example.test/cb"}})
			must(err)
			stored := func() string {
				t.Helper()
				var v string
				must(peer.db.QueryRowContext(ctx, peer.bind(`SELECT "clientSecret" FROM "oauthClient" WHERE "clientId"=?`), app.ClientID).Scan(&v))
				return v
			}
			if stored() != hash("first") {
				t.Fatal("wrong initial digest")
			}
			_, err = owner.RotateOAuthClientSecret(ctx, app.ClientID)
			failed(err, 500, "INTERNAL_SERVER_ERROR")
			generateFixed.Store(false)
			failHash.Store(true)
			_, err = owner.RotateOAuthClientSecret(ctx, app.ClientID)
			failed(err, 500, "INTERNAL_SERVER_ERROR")
			failHash.Store(false)
			if stored() != hash("first") {
				t.Fatal("failed generation changed an active credential")
			}
			exec := func(q string, args ...any) {
				t.Helper()
				_, err := peer.db.ExecContext(ctx, peer.bind(q), args...)
				must(err)
			}
			const extensionData = `{"label":"custom","client_secret":"hidden","clientSecret":"masked"}`
			exec(`UPDATE "oauthClient" SET "metadata"=? WHERE "clientId"=?`, extensionData, app.ClientID)
			updated, err := owner.RotateOAuthClientSecret(ctx, app.ClientID)
			must(err)
			verify := func(r op.RotatedClient) string {
				t.Helper()
				raw, ok := strings.CutPrefix(r.ClientSecret, prefix)
				if !ok || r.ClientID != app.ClientID || r.UserID == nil || *r.UserID != ownerID || r.SecretExpiresAt == nil || *r.SecretExpiresAt != 0 || len(r.Extensions) != 1 || string(r.Extensions["label"]) != `"custom"` {
					t.Fatal("incorrect rotation response or credential metadata exposed")
				}
				return hash(raw)
			}
			active := verify(updated)
			if stored() != active || active == hash("first") {
				t.Fatal("replacement credential was not committed")
			}
			blockedRotation := func(change func()) error {
				t.Helper()
				b := &barrier{entered: make(chan struct{}), release: make(chan struct{})}
				gate.Store(b)
				result := make(chan error, 1)
				go func() { _, err := owner.RotateOAuthClientSecret(ctx, app.ClientID); result <- err }()
				select {
				case <-b.entered:
				case err := <-result:
					t.Fatalf("rotation ended before storage hook: %v", err)
				case <-time.After(5 * time.Second):
					t.Fatal("rotation did not reach the storage hook")
				}
				func() { defer close(b.release); change() }()
				return <-result
			}
			exec(`INSERT INTO "oauthClient" ("id","clientId","redirectUris","clientSecret","userId") VALUES (?,?,?,?,?)`, "protected-row", "operator", "[]", active, ownerID)
			_, err = owner.RotateOAuthClientSecret(ctx, "operator")
			failed(err, 400, "invalid_client")
			err = blockedRotation(func() {
				exec(`UPDATE "oauthClient" SET "metadata"=? WHERE "clientId"=?`, `"invalid metadata envelope"`, app.ClientID)
			})
			failed(err, 500, "INTERNAL_SERVER_ERROR")
			if stored() != active {
				t.Fatal("failed response projection committed the replacement")
			}
			exec(`UPDATE "oauthClient" SET "metadata"=? WHERE "clientId"=?`, extensionData, app.ClientID)
			err = blockedRotation(func() { exec(`UPDATE "oauthClient" SET "userId"=? WHERE "clientId"=?`, otherID, app.ClientID) })
			failed(err, 401, "")
			if stored() != active {
				t.Fatal("previous owner rotated after ownership transferred")
			}
			exec(`UPDATE "oauthClient" SET "userId"=? WHERE "clientId"=?`, ownerID, app.ClientID)
			err = blockedRotation(func() {
				exec(`UPDATE "oauthClient" SET "tokenEndpointAuthMethod"='private_key_jwt' WHERE "clientId"=?`, app.ClientID)
			})
			failed(err, 400, "invalid_client")
			if stored() != active {
				t.Fatal("authentication method change did not cancel rotation")
			}
			exec(`UPDATE "oauthClient" SET "tokenEndpointAuthMethod"='client_secret_post' WHERE "clientId"=?`, app.ClientID)
			exec(`UPDATE "session" SET "impersonatedBy"=? WHERE "userId"=?`, "admin-fixture", ownerID)
			_, err = owner.RotateOAuthClientSecret(ctx, app.ClientID)
			failed(err, 403, "OWNER_SESSION_REQUIRED")
			exec(`UPDATE "session" SET "impersonatedBy"=NULL WHERE "userId"=?`, ownerID)
			options.Registration.Enabled = false
			second := host(peer)
			_, err = second.SignInEmail(ctx, client.SignInRequest{Email: "owner@rotate.test", Password: "local rotation password"})
			must(err)
			type result struct {
				client op.RotatedClient
				err    error
			}
			results := make(chan result, 6)
			for i := range 6 {
				caller := []*client.Client{owner, second}[i%2]
				go func() { c, e := caller.RotateOAuthClientSecret(ctx, app.ClientID); results <- result{c, e} }()
			}
			issued := map[string]bool{}
			for range 6 {
				r := <-results
				must(r.err)
				digest := verify(r.client)
				if issued[digest] {
					t.Fatal("duplicate rotation credential")
				}
				issued[digest] = true
			}
			if final := stored(); !issued[final] || final == active {
				t.Fatal("concurrent rotation left an unissued or superseded credential")
			}
			err = blockedRotation(func() { exec(`DELETE FROM "oauthClient" WHERE "clientId"=?`, app.ClientID) })
			failed(err, 404, "not_found")
		})
	}
}
