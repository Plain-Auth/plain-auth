package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// seedOutage fails resource lookups while down is set.
type seedOutage struct {
	*Store
	down bool
}

func (s *seedOutage) OAuthResource(ctx context.Context, id string) (op.Resource, error) {
	if s.down {
		return op.Resource{}, errors.New("resource table unavailable")
	}
	return s.Store.OAuthResource(ctx, id)
}

// The provider seeds its declared resources on the first request; a seed
// that failed there is retried by the next registration that links one.
// Registration resources must be declared.
func TestProviderResourceSeeding(t *testing.T) {
	for _, list := range []op.RegistrationOptions{{Enabled: true, DefaultResources: []string{"urn:undeclared"}}, {Enabled: true, AllowedResources: []string{"urn:undeclared"}}} {
		if _, err := op.New(op.Options{Registration: list}); err == nil || !strings.Contains(err.Error(), `"urn:undeclared" is not declared in Resources`) {
			t.Fatal("an undeclared registration resource was accepted", err)
		}
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
			s, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), []string{"oauth-provider"}, schema.Options{})
			must(err)
			t.Cleanup(func() { s.Close() })
			store := &seedOutage{Store: s, down: true}
			p, err := op.New(op.Options{Scopes: []string{"reports"}, Resources: []op.ResourceDefinition{{Identifier: "urn:reports"}},
				Registration: op.RegistrationOptions{Enabled: true, AllowedResources: []string{"urn:reports"}}})
			must(err)
			const origin = "https://seeds.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("r", 40), Store: store, EmailAndPassword: true, Plugins: []auth.Plugin{p}, RateLimit: &off})
			must(err)
			owner, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
			must(err)
			rows := func() int {
				t.Helper()
				var n int
				must(s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+s.bind(`"oauthResource"`)).Scan(&n))
				return n
			}
			// The first request still succeeds while the seed fails.
			_, err = owner.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "owner@seeds.test", Password: "local seed test password"})
			must(err)
			if rows() != 0 {
				t.Fatal("a failed seed wrote a resource")
			}
			store.down = false
			app, err := owner.RegisterOAuthClient(ctx, op.RegistrationMetadata{RedirectURIs: []string{"https://app.example.test/cb"}, Resources: []string{"urn:reports"}})
			if err != nil || !slices.Equal(app.Resources, []string{"urn:reports"}) || rows() != 1 {
				t.Fatal("registration did not retry the failed seed", app.Resources, err, rows())
			}
		})
	}
}
