package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

// ResolveProvidersLimit chooses each signed-in user's registration quota
// before the store enforces it.
func TestEnterpriseProviderLimitResolver(t *testing.T) {
	one := 1
	if _, err := sso.New(sso.Options{ProvidersLimit: &one, ResolveProvidersLimit: func(context.Context, auth.User) (int, error) { return 1, nil }}); err == nil {
		t.Fatal("conflicting provider limits were accepted")
	}
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"sso"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			var mu sync.Mutex
			var seen []string
			fail := false
			p, err := sso.New(sso.Options{ResolveProvidersLimit: func(_ context.Context, u auth.User) (int, error) {
				mu.Lock()
				defer mu.Unlock()
				seen = append(seen, u.Email)
				if fail {
					return 0, errors.New("directory unavailable")
				}
				switch u.Email {
				case "admin@example.test":
					return 2, nil
				case "full@example.test":
					return -1, nil
				}
				return 0, nil
			}})
			must(err)
			host, err := auth.New(auth.Options{BaseURL: "https://enterprise.test", BasePath: "/identity", Store: store, Plugins: []auth.Plugin{p}, RateLimit: new(bool), EmailAndPassword: true, Secret: strings.Repeat("s", 32)})
			must(err)
			person := func(name string) *client.Client {
				c, err := client.New("https://enterprise.test/identity", &http.Client{Transport: guestTransport{host}})
				must(err)
				_, err = c.SignUpEmail(ctx, client.SignUpRequest{Name: name, Email: name + "@example.test", Password: "valid-long-password"})
				must(err)
				return c
			}
			admin, member, full := person("admin"), person("member"), person("full")
			register := func(c *client.Client, id string) error {
				_, err := c.RegisterOIDCProvider(ctx, client.RegisterOIDCProviderRequest{ProviderID: id, Domain: id + ".example", Issuer: "https://idp.example.test", OIDC: client.OIDCRegistration{SkipDiscovery: true, Config: sso.Config{ClientID: "application", ClientSecret: "private",
					AuthorizationEndpoint: "https://idp.example.test/authorize", TokenEndpoint: "https://idp.example.test/token", JWKSEndpoint: "https://idp.example.test/keys"}}})
				return err
			}
			refused := func(err error, status int, message string) bool {
				var ae *auth.APIError
				return errors.As(err, &ae) && ae.Status == status && ae.Message == message
			}
			providers := func() int {
				var n int
				must(store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM "ssoProvider"`).Scan(&n))
				return n
			}
			if err := register(member, "member-one"); !refused(err, 403, "SSO provider registration is disabled") {
				t.Fatal("the resolver's zero limit did not disable registration", err)
			}
			if err := register(full, "full-one"); !refused(err, 403, "You have reached the maximum number of SSO providers") {
				t.Fatal("a negative resolved limit did not count as reached", err)
			}
			if register(admin, "admin-one") != nil || register(admin, "admin-two") != nil {
				t.Fatal("a registration under the resolved limit was refused")
			}
			if err := register(admin, "admin-three"); !refused(err, 403, "You have reached the maximum number of SSO providers") {
				t.Fatal("the resolved limit was not enforced", err)
			}
			mu.Lock()
			got := slices.Contains(seen, "admin@example.test")
			fail = true
			mu.Unlock()
			if !got {
				t.Fatal("ResolveProvidersLimit did not receive the signed-in user", seen)
			}
			before := providers()
			var ae *auth.APIError
			if err := register(member, "member-two"); !errors.As(err, &ae) || ae.Status != 500 || providers() != before {
				t.Fatal("a failing limit resolver allowed a registration", err)
			}
		})
	}
}
