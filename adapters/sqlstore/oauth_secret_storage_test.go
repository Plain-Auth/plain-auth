package sqlstore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// Encrypted secret storage seals each secret for its client: the row holds
// an envelope rather than a digest, the secret authenticates, a wrong one
// or an envelope copied to another client does not, and rotation seals the
// new secret. A host's own encrypt and decrypt pair works the same way.
func TestEncryptedClientSecrets(t *testing.T) {
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
			const origin = "https://secrets.example.test"
			off := false
			host := func(r op.RegistrationOptions) (*auth.Auth, *client.Client) {
				t.Helper()
				r.Enabled = true
				p, err := op.New(op.Options{Scopes: []string{"reports"}, DisableJWTPlugin: true, Registration: r})
				must(err)
				h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("e", 40), Store: s, EmailAndPassword: true, Plugins: []auth.Plugin{p}, RateLimit: &off})
				must(err)
				c, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
				must(err)
				return h, c
			}
			stored := func(id string) string {
				t.Helper()
				var v string
				must(s.db.QueryRowContext(ctx, s.bind(`SELECT "clientSecret" FROM "oauthClient" WHERE "clientId"=?`), id).Scan(&v))
				return v
			}
			// Revocation authenticates the client first and answers 200 for
			// an unknown token.
			authenticates := func(h *auth.Auth, id, secret string) bool {
				t.Helper()
				form := url.Values{"client_id": {id}, "client_secret": {secret}, "token": {"unknown-token"}}
				req := httptest.NewRequest("POST", origin+"/api/auth/oauth2/revoke", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				out := httptest.NewRecorder()
				h.ServeHTTP(out, req)
				return out.Code == 200
			}
			m := op.RegistrationMetadata{RedirectURIs: []string{"https://app.example.test/cb"}, TokenEndpointAuthMethod: "client_secret_post"}
			h, owner := host(op.RegistrationOptions{SecretStorage: "encrypted"})
			_, err = owner.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "owner@secrets.test", Password: "local secret test password"})
			must(err)
			first, err := owner.RegisterOAuthClient(ctx, m)
			must(err)
			second, err := owner.RegisterOAuthClient(ctx, m)
			must(err)
			envelope := stored(first.ClientID)
			if !strings.HasPrefix(envelope, "authn.v1.") || strings.Contains(envelope, first.ClientSecret) {
				t.Fatal("the stored secret is not an envelope", envelope)
			}
			if !authenticates(h, first.ClientID, first.ClientSecret) || authenticates(h, first.ClientID, first.ClientSecret+"x") {
				t.Fatal("the encrypted secret did not authenticate exactly")
			}
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "oauthClient" SET "clientSecret"=? WHERE "clientId"=?`), envelope, second.ClientID)
			must(err)
			if authenticates(h, second.ClientID, first.ClientSecret) {
				t.Fatal("an envelope copied to another client authenticated")
			}
			rotated, err := owner.RotateOAuthClientSecret(ctx, first.ClientID)
			must(err)
			if after := stored(first.ClientID); after == envelope || !strings.HasPrefix(after, "authn.v1.") || !authenticates(h, first.ClientID, rotated.ClientSecret) || authenticates(h, first.ClientID, first.ClientSecret) {
				t.Fatal("rotation did not seal the new secret", after)
			}
			// A host encrypt and decrypt pair is used the same way.
			custom, customOwner := host(op.RegistrationOptions{
				StoreSecret: func(_ context.Context, raw string) (string, error) { return "sealed:" + reverse(raw), nil },
				DecryptSecret: func(_ context.Context, v string) (string, error) {
					return reverse(strings.TrimPrefix(v, "sealed:")), nil
				},
			})
			_, err = customOwner.SignInEmail(ctx, client.SignInRequest{Email: "owner@secrets.test", Password: "local secret test password"})
			must(err)
			app, err := customOwner.RegisterOAuthClient(ctx, m)
			must(err)
			if stored(app.ClientID) != "sealed:"+reverse(app.ClientSecret) || !authenticates(custom, app.ClientID, app.ClientSecret) || authenticates(custom, app.ClientID, "wrong") {
				t.Fatal("the host's encrypt and decrypt pair was not used")
			}
		})
	}
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
