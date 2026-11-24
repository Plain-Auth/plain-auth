package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/siwe"
	"github.com/Plain-Org/plain-auth/schema"
)

// A new wallet user goes through ValidateUserInfo with method siwe; a
// refusal answers 403 with the app's code and stores nothing.
func TestSIWEUserValidation(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			ddl, err := schema.Generate(dialect, []string{"siwe"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			p, err := siwe.New(siwe.Options{Domain: "wallet.example.test", Chains: []int64{1}, RequireEmail: true})
			if err != nil {
				t.Fatal(err)
			}
			var checks []auth.UserInfoValidation
			refuse := true
			off := false
			server, err := auth.New(auth.Options{Store: store, BaseURL: returnOrigin + returnMount, Secret: strings.Repeat("s", 32), RateLimit: &off, Plugins: []auth.Plugin{p},
				ValidateUserInfo: func(_ context.Context, v auth.UserInfoValidation) error {
					checks = append(checks, v)
					if refuse || !strings.HasSuffix(v.User.Email, "@company.example") {
						return &auth.APIError{Code: "wallet_blocked", Message: "Not allowed"}
					}
					return nil
				}})
			if err != nil {
				t.Fatal(err)
			}
			c, err := client.New(returnOrigin+returnMount, &http.Client{Transport: localBillingTransport(func(r *http.Request) (*http.Response, error) {
				out := httptest.NewRecorder()
				server.ServeHTTP(out, r)
				return out.Result(), nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			signIn := func(w walletSigner, email string) error {
				n, err := c.SIWENonce(ctx)
				if err != nil {
					t.Fatal(err)
				}
				s := walletMessage(w.address, "wallet.example.test", n, 1)
				_, err = c.VerifySIWEWithEmail(ctx, s, w.sign(s), email)
				return err
			}
			var api *auth.APIError
			if err := signIn(freshWallet(t), "ada@company.example"); !errors.As(err, &api) || api.Status != 403 || api.Code != "wallet_blocked" {
				t.Fatal("a refused wallet signed in", err)
			}
			check := checks[len(checks)-1]
			if check.Action != auth.UserInfoCreateUser || check.Method != "siwe" || check.User.Name == "" || check.User.Email != "ada@company.example" {
				t.Fatalf("the wallet check was %+v", check)
			}
			if _, err := store.FindAccountUser(ctx, "ada@company.example"); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("a refused wallet stored a user", err)
			}
			// Under an allowlist the contact signs up, although the wallet
			// address email would not pass.
			refuse = false
			if err := signIn(freshWallet(t), "ada@company.example"); err != nil {
				t.Fatal("an allowed contact was refused", err)
			}
			if _, err := store.FindAccountUser(ctx, "ada@company.example"); err != nil {
				t.Fatal("the contact email was not used", err)
			}
			// A taken contact falls back to the wallet email, which is checked.
			if err := signIn(freshWallet(t), "ada@company.example"); !errors.As(err, &api) || api.Code != "wallet_blocked" {
				t.Fatal("a taken contact fell back to an unchecked wallet email", err)
			}
			if check := checks[len(checks)-1]; check.User.Email == "ada@company.example" {
				t.Fatal("the fallback was not checked with the wallet email")
			}
		})
	}
}
