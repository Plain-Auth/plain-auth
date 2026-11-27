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
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// Every client management action reaches ClientPrivileges with its client
// ID, a denial answers 401, an approval never bypasses ownership, and an
// ownerless client is never listed or reachable by an owner call.
func TestOAuthClientPrivileges(t *testing.T) {
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
			var mu sync.Mutex
			var seen []string
			var deny string
			opts := op.Options{Scopes: []string{"openid", "reports"}, ClientPrivileges: func(_ context.Context, a op.ClientAccess) (bool, error) {
				mu.Lock()
				defer mu.Unlock()
				seen = append(seen, a.Action+" "+a.ClientID)
				return a.Action != deny, nil
			}}
			p, err := op.New(opts)
			must(err)
			const origin = "https://privileges.example.test"
			off := false
			h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("v", 40), Store: s, EmailAndPassword: true, Plugins: []auth.Plugin{p}, RateLimit: &off})
			must(err)
			account := func(email string) (*client.Client, http.Header) {
				t.Helper()
				c, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
				must(err)
				signed, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: email, Password: "local privilege test password"})
				must(err)
				return c, http.Header{"Cookie": {h.SessionCookie(*signed.Token, true).String()}}
			}
			owner, headers := account("owner@privileges.test")
			other, _ := account("other@privileges.test")
			manager, err := op.NewClientManager(h, s, opts)
			must(err)
			refused := func(err error) bool {
				var api *auth.APIError
				return errors.As(err, &api) && api.Status == 401
			}
			m := op.RegistrationMetadata{RedirectURIs: []string{"https://app.example.test/cb"}}
			app, err := owner.CreateOAuthClient(ctx, m)
			must(err)
			_, err = owner.OAuthClient(ctx, app.ClientID)
			must(err)
			_, err = owner.OAuthClients(ctx)
			must(err)
			_, err = owner.RotateOAuthClientSecret(ctx, app.ClientID)
			must(err)
			_, err = manager.UpdateClient(ctx, headers, app.ClientID, op.ClientAdminUpdate{Fields: map[string]any{"client_name": "Named"}})
			must(err)
			machine, err := manager.CreateClient(ctx, headers, op.ClientCreation{RegistrationMetadata: op.RegistrationMetadata{GrantTypes: []string{"client_credentials"}}, ClientCredentialsScopes: []string{"reports"}})
			must(err)
			must(owner.DeleteOAuthClient(ctx, machine.ClientID))
			want := []string{"create ", "read " + app.ClientID, "list ", "rotate " + app.ClientID, "update " + app.ClientID, "create ", "configure-client-credentials-scopes ", "delete " + machine.ClientID}
			mu.Lock()
			got := slices.Clone(seen)
			mu.Unlock()
			if !slices.Equal(got, want) {
				t.Fatal("the privilege callback did not see every action and client", got)
			}
			// A denied action answers 401.
			for _, action := range []string{"create", "read", "rotate", "delete"} {
				deny = action
				var err error
				switch action {
				case "create":
					_, err = owner.CreateOAuthClient(ctx, m)
				case "read":
					_, err = owner.OAuthClient(ctx, app.ClientID)
				case "rotate":
					_, err = owner.RotateOAuthClientSecret(ctx, app.ClientID)
				case "delete":
					err = owner.DeleteOAuthClient(ctx, app.ClientID)
				}
				if !refused(err) {
					t.Fatal("a denied action was not refused", action, err)
				}
			}
			deny = ""
			// Approval does not make another user an owner.
			if _, err := other.OAuthClient(ctx, app.ClientID); !refused(err) {
				t.Fatal("an approved stranger read the client", err)
			}
			if err := other.DeleteOAuthClient(ctx, app.ClientID); !refused(err) {
				t.Fatal("an approved stranger deleted the client", err)
			}
			// An ownerless client is never listed or reachable by owners.
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "oauthClient" SET "userId"=NULL WHERE "clientId"=?`), app.ClientID)
			must(err)
			list, err := owner.OAuthClients(ctx)
			must(err)
			if len(list) != 0 {
				t.Fatal("an ownerless client was listed", list)
			}
			if _, err := owner.OAuthClient(ctx, app.ClientID); !refused(err) {
				t.Fatal("an ownerless client was read", err)
			}
			if _, err := manager.UpdateClient(ctx, headers, app.ClientID, op.ClientAdminUpdate{Fields: map[string]any{"client_name": "X"}}); !refused(err) {
				t.Fatal("an ownerless client was updated", err)
			}
		})
	}
}
