package sqlstore

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// An operator-managed client refuses deletion, secret rotation and a scope
// update by its owner with 400 invalid_client, as another runtime refuses a
// trusted client, and stays as it was.
func TestOAuthImmutableClients(t *testing.T) {
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
			opts := op.Options{ImmutableClientIDs: []string{"operator"}, Registration: op.RegistrationOptions{Enabled: true}}
			p, err := op.New(opts)
			must(err)
			const origin = "https://immutable.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("k", 40), Store: s, EmailAndPassword: true, Plugins: []auth.Plugin{p}, RateLimit: &off})
			must(err)
			owner, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
			must(err)
			account, err := owner.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "owner@immutable.test", Password: "safe local test password"})
			must(err)
			_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO "oauthClient" ("id","clientId","redirectUris","clientSecret","userId","tokenEndpointAuthMethod","clientCredentialsScopes") VALUES (?,?,?,?,?,?,?)`),
				"operator-row", "operator", "[]", "stored-digest", account.User.ID, "client_secret_post", `["reports"]`)
			must(err)
			refused := func(what string, err error) {
				t.Helper()
				var api *auth.APIError
				var oauth *auth.OAuthError
				if !(errors.As(err, &api) && api.Status == 400 && api.Code == "invalid_client" || errors.As(err, &oauth) && oauth.Status == 400 && oauth.Code == "invalid_client") {
					t.Fatal("an operator-managed client was not refused with invalid_client", what, err)
				}
			}
			refused("deletion", owner.DeleteOAuthClient(ctx, "operator"))
			_, err = owner.RotateOAuthClientSecret(ctx, "operator")
			refused("secret rotation", err)
			manager, err := op.NewClientManager(h, s, opts)
			must(err)
			headers := http.Header{}
			headers.Add("Cookie", h.SessionCookie(*account.Token, true).String())
			// Clearing the grant needs no approval, so only the immutability
			// check can refuse it.
			_, err = manager.SetClientCredentialsScopes(ctx, headers, "operator", []string{})
			refused("scope update", err)
			var secret, machineScopes string
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT "clientSecret","clientCredentialsScopes" FROM "oauthClient" WHERE "clientId"=?`), "operator").Scan(&secret, &machineScopes))
			if secret != "stored-digest" || machineScopes != `["reports"]` {
				t.Fatal("a refused change altered the operator-managed client", secret, machineScopes)
			}
		})
	}
}
