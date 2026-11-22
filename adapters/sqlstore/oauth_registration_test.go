package sqlstore

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestDynamicOAuthRegistration(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			expect := func(err error, status int, code string) {
				t.Helper()
				var api *auth.APIError
				if !errors.As(err, &api) || api.Status != status || api.Code != code {
					t.Fatalf("want %d %s, got %v", status, code, err)
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
			s, peer := open(), open()
			const origin = "https://issuer.example.test"
			noLimit := false
			newHost := func(store *Store, opts op.Options) (*auth.Auth, *client.Client) {
				t.Helper()
				p, err := op.New(opts)
				must(err)
				h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("k", 40), Store: store, EmailAndPassword: true, Plugins: []auth.Plugin{p}, RateLimit: &noLimit, TrustedOrigins: []string{"https://keys.example.test"}})
				must(err)
				c, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
				must(err)
				return h, c
			}
			allowed := []string{"openid", "reports", "other"}
			configured := op.Options{Scopes: allowed, Registration: op.RegistrationOptions{
				Enabled: true, DefaultScopes: []string{"openid"}, AllowedScopes: []string{"reports"},
				DefaultResources: []string{"urn:reports"}, AllowedResources: []string{"urn:billing", "urn:missing", "urn:disabled"},
				SecretPrefix: "app_", GenerateClientSecret: func() (string, error) { return "a-secret-from-generator", nil },
				ClientReference: func(_ context.Context, a op.RegistrationAccess) (string, error) { return "tenant-" + a.User.ID, nil },
				ValidateInitialToken: func(_ context.Context, token string, h http.Header, m op.RegistrationMetadata) (*op.InitialAuthorization, error) {
					if token == "allow" && h.Get("Authorization") == "Bearer allow" && m.Scope == "reports" {
						m.RedirectURIs[0] = "https://callback-snapshot.example.test/changed"
						return &op.InitialAuthorization{ReferenceID: "integration"}, nil
					}
					return nil, nil
				},
			}}
			host, owner := newHost(s, configured)
			registry, err := op.NewResourceManager(host, s, op.ResourceManagerOptions{Resources: []op.ResourceDefinition{{Identifier: "urn:reports"}, {Identifier: "urn:billing"}, {Identifier: "urn:disabled", Policy: op.ResourcePatch{Disabled: op.Set(true)}}}})
			must(err)
			must(registry.Seed(ctx))
			m := op.RegistrationMetadata{Scope: "reports", Resources: []string{"urn:billing", "urn:reports", "urn:billing"}, RedirectURIs: []string{"https://app.example.test/callback"}}
			_, err = owner.RegisterOAuthClient(ctx, m)
			expect(err, 401, "")
			signed, err := owner.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "operator@registration.test", Password: "safe local test password"})
			must(err)
			app, err := owner.RegisterOAuthClient(ctx, m)
			must(err)
			if app.SecretExpiresAt == nil || *app.SecretExpiresAt != 0 || app.ReferenceID != "tenant-"+signed.User.ID || app.UserID != "" || app.ClientSecret != "app_a-secret-from-generator" || app.Scope != "openid reports" || !slices.Equal(app.Resources, []string{"urn:reports", "urn:billing"}) {
				t.Fatalf("incorrect registration response, id %s", app.ClientID)
			}
			var hash string
			var ownerID *string
			var ref string
			var issued time.Time
			must(peer.db.QueryRowContext(ctx, peer.bind(`SELECT "clientSecret","userId","referenceId","createdAt" FROM "oauthClient" WHERE "clientId"=?`), app.ClientID).Scan(&hash, &ownerID, &ref, &issued))
			digest := sha256.Sum256([]byte("a-secret-from-generator"))
			if hash != base64.RawURLEncoding.EncodeToString(digest[:]) || ownerID != nil || ref != app.ReferenceID || issued.Unix() != app.IssuedAt {
				t.Fatal("incorrect registration at rest")
			}
			count := func(q string, args ...any) int {
				t.Helper()
				var n int
				must(peer.db.QueryRowContext(ctx, peer.bind(q), args...).Scan(&n))
				return n
			}
			if count(`SELECT COUNT(*) FROM "oauthClientResource" WHERE "clientId"=?`, app.ClientID) != 2 {
				t.Fatal("incorrect number of resource links")
			}
			token, err := owner.WithBearerToken("allow")
			must(err)
			keyed := m
			keyed.TokenEndpointAuthMethod = "private_key_jwt"
			uri := "https://keys.example.test/jwks"
			keyed.JWKSURI = &uri
			machine, err := token.RegisterOAuthClient(ctx, keyed)
			must(err)
			if machine.ReferenceID != "integration" || machine.ClientSecret != "" || machine.SecretExpiresAt != nil || !slices.Equal(machine.RedirectURIs, keyed.RedirectURIs) {
				t.Fatal("initial token or asymmetric registration lost")
			}
			notAllowed := keyed
			badURI := "https://foreign.example.test/key"
			notAllowed.JWKSURI = &badURI
			_, err = token.RegisterOAuthClient(ctx, notAllowed)
			expect(err, 400, "invalid_client_metadata")
			for _, id := range []string{"urn:outside", "urn:disabled", "urn:missing"} {
				bad := m
				bad.Resources = []string{"urn:billing", id}
				_, err = owner.RegisterOAuthClient(ctx, bad)
				expect(err, 400, "invalid_target")
			}
			if count(`SELECT COUNT(*) FROM "oauthClient"`) != 2 || count(`SELECT COUNT(*) FROM "oauthClientResource"`) != 4 {
				t.Fatal("rejected registrations changed the database")
			}

			// A failure after the client and its first grant were inserted must roll back both.
			record := op.ClientRegistrationRecord{ID: "rollback", ClientID: "rollback", CreatedAt: time.Now().UTC(), Metadata: op.RegistrationMetadata{RedirectURIs: []string{}, Resources: []string{"urn:billing", "urn:billing"}}}
			if err := s.CreateRegisteredClient(ctx, record); err == nil {
				t.Fatal("duplicate link should fail")
			}
			if count(`SELECT COUNT(*) FROM "oauthClient" WHERE "clientId"='rollback'`) != 0 || count(`SELECT COUNT(*) FROM "oauthClientResource" WHERE "clientId"='rollback'`) != 0 {
				t.Fatal("failed grant left partial registration")
			}

			configured.Registration.GenerateClientID = func() (string, error) { return "same-id", nil }
			configured.Registration.AllowUnauthenticated = true
			_, first := newHost(s, configured)
			_, second := newHost(peer, configured)
			start := make(chan struct{})
			done := make(chan error, 8)
			for i := range 8 {
				public := m
				public.TokenEndpointAuthMethod = "none"
				caller := []*client.Client{first, second}[i%2]
				go func() { <-start; _, err := caller.RegisterOAuthClient(ctx, public); done <- err }()
			}
			close(start)
			successes := 0
			for range 8 {
				if err := <-done; err == nil {
					successes++
				} else {
					expect(err, 500, "INTERNAL_SERVER_ERROR")
				}
			}
			if successes != 1 || count(`SELECT COUNT(*) FROM "oauthClientResource" WHERE "clientId"='same-id'`) != 2 {
				t.Fatal("colliding registrations did not leave one complete client")
			}
		})
	}
}

func TestRegistrationLimitsAndCustomSecretStore(t *testing.T) {
	ctx := t.Context()
	s, err := OpenWithOptions(ctx, "sqlite", organizationTestDSN(t, "sqlite"), []string{"oauth-provider"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	for _, limit := range []int{5, 2} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			registration := op.RegistrationOptions{
				Enabled: true, AllowUnauthenticated: true, SecretPrefix: "example_",
				StoreSecret: func(_ context.Context, raw string) (string, error) {
					mac := hmac.New(sha256.New, []byte("host-managed-test-key"))
					mac.Write([]byte(raw))
					return hex.EncodeToString(mac.Sum(nil)), nil
				},
			}
			if limit != 5 {
				registration.RateLimit = &auth.RateLimitRule{Max: limit, Window: time.Minute}
			}
			p, err := op.New(op.Options{Registration: registration})
			if err != nil {
				t.Fatal(err)
			}
			const origin = "https://issuer.example.test"
			host, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("k", 40), Store: s, Plugins: []auth.Plugin{p}})
			if err != nil {
				t.Fatal(err)
			}
			c, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
			if err != nil {
				t.Fatal(err)
			}
			m := op.RegistrationMetadata{RedirectURIs: []string{"https://client.example.test/cb"}}
			for range limit {
				app, err := c.RegisterOAuthClient(ctx, m)
				if err != nil {
					t.Fatal(err)
				}
				var stored string
				if err := s.db.QueryRowContext(ctx, `SELECT "clientSecret" FROM "oauthClient" WHERE "clientId"=?`, app.ClientID).Scan(&stored); err != nil {
					t.Fatal(err)
				}
				raw, ok := strings.CutPrefix(app.ClientSecret, registration.SecretPrefix)
				want, err := registration.StoreSecret(ctx, raw)
				if !ok || err != nil || want != stored {
					t.Fatal("custom secret storage differs from the issued credential")
				}
			}
			_, err = c.RegisterOAuthClient(ctx, m)
			var problem *auth.APIError
			if !errors.As(err, &problem) || problem.Status != http.StatusTooManyRequests {
				t.Fatalf("after %d registrations: %v", limit, err)
			}
		})
	}
}
