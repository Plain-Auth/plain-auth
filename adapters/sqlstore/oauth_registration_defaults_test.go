package sqlstore

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// Without scope options a registration takes the issuer's scopes, and
// without generators its client ID and secret are 32 ASCII letters. An
// initial access token whose authorization names nobody registers a client
// without an owner, and a configured secret generator also serves rotation.
func TestDefaultOAuthRegistration(t *testing.T) {
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
			defer s.Close()
			const origin = "https://defaults.example.test"
			off := false
			host := func(r op.RegistrationOptions) *auth.Auth {
				p, err := op.New(op.Options{Scopes: []string{"openid", "reports"}, Registration: r})
				must(err)
				h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("k", 40), Store: s, EmailAndPassword: true, Plugins: []auth.Plugin{p}, RateLimit: &off})
				must(err)
				return h
			}
			sdk := func(h *auth.Auth) *client.Client {
				c, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
				must(err)
				return c
			}
			anonymous := func(context.Context, string, http.Header, op.RegistrationMetadata) (*op.InitialAuthorization, error) {
				return &op.InitialAuthorization{}, nil
			}
			plain := host(op.RegistrationOptions{Enabled: true, ValidateInitialToken: anonymous})
			owner := sdk(plain)
			_, err = owner.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "owner@defaults.test", Password: "safe local test password"})
			must(err)
			m := op.RegistrationMetadata{RedirectURIs: []string{"https://app.example.test/callback"}}
			app, err := owner.RegisterOAuthClient(ctx, m)
			must(err)
			letters := regexp.MustCompile(`^[A-Za-z]{32}$`)
			var stored []byte
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "scopes" FROM "oauthClient" WHERE "clientId"=?`), app.ClientID).Scan(&stored))
			var scopes []string
			must(json.Unmarshal(stored, &scopes))
			if !letters.MatchString(app.ClientID) || !letters.MatchString(app.ClientSecret) || app.Scope != "openid reports" || !slices.Equal(scopes, []string{"openid", "reports"}) {
				t.Fatal("a default registration did not take the issuer's scopes and 32-letter credentials", app.ClientID, app.Scope, scopes)
			}
			bearer, err := sdk(plain).WithBearerToken("anyone")
			must(err)
			ownerless, err := bearer.RegisterOAuthClient(ctx, m)
			must(err)
			if ownerless.UserID != "" || ownerless.ReferenceID != "" {
				t.Fatal("an initial access token naming nobody registered an owned client", ownerless.UserID, ownerless.ReferenceID)
			}
			generated := host(op.RegistrationOptions{Enabled: true, GenerateClientSecret: func() (string, error) { return "rotated-by-generator", nil }})
			rotator := sdk(generated)
			_, err = rotator.SignInEmail(ctx, client.SignInRequest{Email: "owner@defaults.test", Password: "safe local test password"})
			must(err)
			rotated, err := rotator.RotateOAuthClientSecret(ctx, app.ClientID)
			if err != nil || rotated.ClientSecret != "rotated-by-generator" {
				t.Fatal("rotation did not use the configured secret generator", rotated.ClientSecret, err)
			}
		})
	}
}
