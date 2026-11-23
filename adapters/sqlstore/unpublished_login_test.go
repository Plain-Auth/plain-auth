package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/siwe"
	"github.com/Plain-Org/plain-auth/schema"
)

type unpublishedUserStore struct {
	*Store
	failRead atomic.Bool
}

func (s *unpublishedUserStore) ReadUserFields(ctx context.Context, id string, fields map[string]auth.UserField) (map[string]any, error) {
	if s.failRead.Load() {
		return nil, errors.New("fixture: committed profile read unavailable")
	}
	return s.Store.ReadUserFields(ctx, id, fields)
}

func TestDiscardUnpublishedLogin(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			fields := map[string]auth.UserField{"locale": {Type: auth.FieldString}}
			base, err := OpenWithAdditionalFields(ctx, dialect, organizationTestDSN(t, dialect), []string{"siwe"}, schema.AdditionalFields{User: fields})
			if err != nil {
				t.Fatal(err)
			}
			defer base.Close()
			store := &unpublishedUserStore{Store: base}
			const domain = "wallet.example.test"
			plugin, err := siwe.New(siwe.Options{Domain: domain})
			if err != nil {
				t.Fatal(err)
			}
			for _, mode := range []string{"profile", "cookie"} {
				t.Run(mode, func(t *testing.T) {
					var fail atomic.Bool
					srv := httptest.NewUnstartedServer(nil)
					limit := false
					opts := auth.Options{Store: store, BaseURL: "http://" + srv.Listener.Addr().String(), Secret: strings.Repeat("s", 40), RateLimit: &limit, Plugins: []auth.Plugin{plugin, emailOTPFieldPlugin(t, false)}}
					if mode == "profile" {
						opts.UserAdditionalFields = fields
					} else {
						opts.SessionCookieCache = &auth.SessionCookieCacheOptions{VersionFor: func(context.Context, auth.Session, auth.User) (string, error) {
							if fail.Load() {
								return "", errors.New("fixture: cache publication unavailable")
							}
							return "test", nil
						}}
					}
					host, err := auth.New(opts)
					if err != nil {
						t.Fatal(err)
					}
					srv.Config.Handler = host
					srv.Start()
					defer srv.Close()
					browser := func() *client.Client {
						t.Helper()
						transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
							response, err := http.DefaultTransport.RoundTrip(r)
							if err == nil && (strings.HasSuffix(r.URL.Path, "/siwe/verify") || strings.HasSuffix(r.URL.Path, "/sign-in/email-otp")) {
								var primary, snapshot bool
								for _, cookie := range response.Cookies() {
									if cookie.Value != "" && cookie.MaxAge >= 0 {
										primary = primary || strings.HasSuffix(cookie.Name, ".session_token")
										snapshot = snapshot || strings.HasSuffix(cookie.Name, ".session_data")
									}
								}
								success := response.StatusCode == http.StatusOK
								if primary != success || snapshot != (success && mode == "cookie") {
									t.Errorf("HTTP %d, published session %t and snapshot %t", response.StatusCode, primary, snapshot)
								}
							}
							return response, err
						})
						c, err := client.New(opts.BaseURL, &http.Client{Transport: transport})
						if err != nil {
							t.Fatal(err)
						}
						return c
					}
					setFailure := func(on bool) { fail.Store(on); store.failRead.Store(on && mode == "profile") }
					t.Cleanup(func() { setFailure(false) })
					for _, method := range []string{"wallet", "otp"} {
						t.Run(method, func(t *testing.T) {
							defer setFailure(false)
							before, after := browser(), browser()
							email := mode + "@publication.test"
							wallet := freshWallet(t)
							if method == "wallet" {
								email = wallet.address + "@siwe.placeholder.invalid"
							}
							issue := func(c *client.Client) func() (string, error) {
								t.Helper()
								if method == "wallet" {
									n, err := c.SIWENonce(ctx)
									if err != nil {
										t.Fatal(err)
									}
									m := walletMessage(wallet.address, domain, n, 1)
									signature := wallet.sign(m)
									return func() (string, error) {
										v, err := c.VerifySIWE(ctx, m, signature)
										if err != nil {
											return "", err
										}
										return v.Token, nil
									}
								}
								code, err := host.CreateEmailOTP(ctx, email, auth.OTPSignIn)
								if err != nil {
									t.Fatal(err)
								}
								input := auth.EmailOTPSignInInput{Email: email, OTP: code}
								if mode == "profile" {
									input.AdditionalFields = map[string]any{"locale": "fr"}
								}
								return func() (string, error) {
									v, err := c.SignInEmailOTP(ctx, input)
									if err != nil {
										return "", err
									}
									return v.Token, nil
								}
							}
							// No prior token from this account exists. A failure after commit
							// must preserve the account and spent proof but retire the new token.
							proof := issue(after)
							setFailure(true)
							if token, err := proof(); err == nil || token != "" {
								t.Fatalf("expected publication error: %v", err)
							}
							setFailure(false)
							owner, err := store.FindAccountUser(ctx, email)
							if err != nil {
								t.Fatal("account creation did not commit", err)
							}
							count := func(want int) {
								t.Helper()
								var live int
								err := store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "session" WHERE "userId"=?`), owner.ID).Scan(&live)
								if err != nil || live != want {
									t.Fatalf("unpublished session persisted, have %d want %d (err %v)", live, want, err)
								}
							}
							count(0)
							if token, err := proof(); err == nil || token != "" {
								t.Fatal("spent proof was accepted after publication failure")
							}
							if v, err := after.GetSession(ctx); err != nil || v != nil {
								t.Fatal("failed response authenticated the browser", v, err)
							}
							if mode == "profile" && method == "otp" {
								raw, err := store.ReadUserFields(ctx, owner.ID, fields)
								if err != nil || raw["locale"] != "fr" {
									t.Fatal("committed signup profile changed", raw, err)
								}
							}

							first, err := issue(before)()
							if err != nil || first == "" {
								t.Fatal("new login failed", err)
							}
							proof = issue(after)
							setFailure(true)
							if token, err := proof(); err == nil || token != "" {
								t.Fatal("returning login failure published a cookie or token")
							}
							setFailure(false)
							count(1)
							if valid, err := before.GetSession(ctx); err != nil || valid == nil || valid.Session.Token != first {
								t.Fatal("failed login revoked an earlier published session", valid, err)
							}
							last, err := issue(after)()
							if err != nil || last == "" || last == first {
								t.Fatal("fresh login failed after publication recovered", err)
							}
							count(2)
						})
					}
				})
			}
		})
	}
}
