package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authn "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/client"
	"github.com/Stonewrit/stonewrit-auth/plugins/anonymous"
	"github.com/Stonewrit/stonewrit-auth/plugins/twofactor"
	"github.com/Stonewrit/stonewrit-auth/schema"
	"github.com/pquerna/otp/totp"
)

type guestTransport struct{ server *authn.Auth }

func (g guestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	g.server.ServeHTTP(w, r)
	return w.Result(), nil
}

func TestAnonymousGuestLifecycle(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"anonymous", "two-factor"})
			if err != nil {
				t.Fatal(err)
			}
			const origin = "https://guest.example"
			stores := []*Store{}
			var otp, linkToken string
			server := func(o anonymous.Options) *authn.Auth {
				t.Helper()
				s, err := OpenWithSchema(ctx, dialect, dsn, ddl)
				if err != nil {
					t.Fatal(err)
				}
				stores = append(stores, s)
				t.Cleanup(func() { s.Close() })
				p, err := anonymous.New(o)
				if err != nil {
					t.Fatal(err)
				}
				mail, err := authn.NewEmailOTP(authn.EmailOTPOptions{Send: func(_ context.Context, m authn.EmailOTPMessage) error { otp = m.OTP; return nil }})
				if err != nil {
					t.Fatal(err)
				}
				link, err := authn.NewMagicLink(authn.MagicLinkOptions{Send: func(_ context.Context, m authn.MagicLinkMessage) error { linkToken = m.Token; return nil }})
				if err != nil {
					t.Fatal(err)
				}
				off := false
				a, err := authn.New(authn.Options{Store: s, EmailAndPassword: true, Secret: strings.Repeat("s", 32), RateLimit: &off, BaseURL: origin, Plugins: []authn.Plugin{p, twofactor.New(twofactor.Options{}), mail, link}})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			browser := func(a *authn.Auth) *client.Client {
				c, err := client.New(origin, &http.Client{Transport: guestTransport{a}})
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			var calls atomic.Int32
			var fail atomic.Bool
			opts := anonymous.Options{GenerateName: func(_ context.Context, r *http.Request) (string, error) {
				if r.URL.Path != "/api/auth/sign-in/anonymous" {
					return "", fmt.Errorf("wrong creation route")
				}
				return "Visitor", nil
			}, EmailDomainName: "guests.example", OnLinkAccount: func(ctx context.Context, e anonymous.Link) error {
				if e.Request == nil || e.AnonymousUser.User.IsAnonymous == nil || !*e.AnonymousUser.User.IsAnonymous || e.NewUser.User.IsAnonymous == nil || *e.NewUser.User.IsAnonymous {
					return errors.New("invalid guest transition context")
				}
				db := stores[0]
				_, err := e.Tx.ExecContext(ctx, db.bind(`INSERT INTO "guestTransfer" ("source","target") VALUES (?,?)`), e.AnonymousUser.User.ID, e.NewUser.User.ID)
				if err != nil {
					return err
				}
				if fail.Load() {
					return errors.New("transfer operation failed")
				}
				calls.Add(1)
				return nil
			}}
			first, second := server(opts), server(opts)
			db := stores[0]
			_, err = db.db.ExecContext(ctx, db.bind(`CREATE TABLE "guestTransfer" ("source" varchar(64) primary key,"target" varchar(64) not null)`))
			if err != nil {
				t.Fatal(err)
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			expectErr := func(err error, status int, code string) {
				t.Helper()
				var e *authn.APIError
				if !errors.As(err, &e) || e.Status != status || e.Code != code {
					t.Fatalf("expected %d %s, got %v", status, code, err)
				}
			}
			guest := func(c *client.Client) *authn.AuthResult {
				t.Helper()
				g, err := c.SignInAnonymous(ctx)
				must(err)
				if g.User.IsAnonymous == nil || !*g.User.IsAnonymous || g.User.Name != "Visitor" || !strings.HasSuffix(g.User.Email, "@guests.example") {
					t.Fatalf("invalid guest identity %v", g.User)
				}
				return g
			}
			signup := func(c *client.Client, id string) (*client.EmailResult, error) {
				return c.SignUpEmail(ctx, client.SignUpRequest{Name: id, Email: id + "@test.example", Password: "a local test password"})
			}
			count := func(query string, v string) int {
				t.Helper()
				var n int
				must(db.db.QueryRowContext(ctx, db.bind(query), v).Scan(&n))
				return n
			}
			c := browser(first)
			g := guest(c)
			_, err = c.SignInAnonymous(ctx)
			expectErr(err, 400, "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY")
			if count(`SELECT COUNT(*) FROM "account" WHERE "userId"=?`, g.User.ID) != 0 {
				t.Fatal("guest unexpectedly acquired a password account")
			}
			session, err := c.GetSession(ctx)
			must(err)
			if session.User.IsAnonymous == nil || !*session.User.IsAnonymous {
				t.Fatal("guest flag missing from session")
			}
			fail.Store(true)
			_, err = signup(c, "permanent")
			expectErr(err, 500, "INTERNAL_SERVER_ERROR")
			if count(`SELECT COUNT(*) FROM "guestTransfer" WHERE "source"=?`, g.User.ID) != 0 || count(`SELECT COUNT(*) FROM "user" WHERE "id"=?`, g.User.ID) != 1 || count(`SELECT COUNT(*) FROM "session" s JOIN "user" u ON u."id"=s."userId" WHERE u."email"=?`, "permanent@test.example") != 0 {
				t.Fatal("failed callback partially transferred guest records or left a target session")
			}
			fail.Store(false)
			signed, err := c.SignInEmail(ctx, client.SignInRequest{Email: "permanent@test.example", Password: "a local test password"})
			must(err)
			if signed.User.IsAnonymous == nil || *signed.User.IsAnonymous || signed.User.ID == g.User.ID {
				t.Fatal("normal account did not replace guest")
			}
			if count(`SELECT COUNT(*) FROM "guestTransfer" WHERE "source"=?`, g.User.ID) != 1 || count(`SELECT COUNT(*) FROM "user" WHERE "id"=?`, g.User.ID) != 0 {
				t.Fatal("guest was not atomically transferred and removed")
			}
			expectErr(c.DeleteAnonymousUser(ctx), 403, "USER_IS_NOT_ANONYMOUS")
			c = browser(second)
			g = guest(c)
			must(c.DeleteAnonymousUser(ctx))
			session, err = c.GetSession(ctx)
			must(err)
			if session != nil || count(`SELECT COUNT(*) FROM "user" WHERE "id"=?`, g.User.ID) != 0 {
				t.Fatal("explicit guest deletion left active state")
			}
			c = browser(second)
			g = guest(c)
			must(c.SignOut(ctx))
			if count(`SELECT COUNT(*) FROM "user" WHERE "id"=?`, g.User.ID) != 1 {
				t.Fatal("sign-out deleted guest data")
			}
			c = browser(first)
			g = guest(c)
			must(c.SendEmailOTP(ctx, "mail@test.example", authn.OTPSignIn))
			_, err = c.SignInEmailOTP(ctx, authn.EmailOTPSignInInput{Email: "mail@test.example", Name: "Mail", OTP: otp})
			must(err)
			if count(`SELECT COUNT(*) FROM "guestTransfer" WHERE "source"=?`, g.User.ID) != 1 {
				t.Fatal("email OTP did not transfer guest")
			}
			c = browser(second)
			g = guest(c)
			must(c.SignInMagicLink(ctx, client.MagicLinkRequest{Email: "link@example.test", Name: "Link"}))
			_, err = c.VerifyMagicLink(ctx, linkToken)
			must(err)
			if count(`SELECT COUNT(*) FROM "guestTransfer" WHERE "source"=?`, g.User.ID) != 1 {
				t.Fatal("verified magic link did not transfer the guest")
			}
			permanent := browser(first)
			_, err = signup(permanent, "mfa")
			must(err)
			enroll, err := permanent.EnableTOTP(ctx, "a local test password", "Test")
			must(err)
			uri, err := url.Parse(enroll.URI)
			must(err)
			code, err := totp.GenerateCode(uri.Query().Get("secret"), time.Now())
			must(err)
			_, err = permanent.VerifyTOTP(ctx, code)
			must(err)
			c = browser(first)
			g = guest(c)
			pending, err := c.SignInEmail(ctx, client.SignInRequest{Email: "mfa@test.example", Password: "a local test password"})
			must(err)
			if !pending.TwoFactorRedirect || count(`SELECT COUNT(*) FROM "guestTransfer" WHERE "source"=?`, g.User.ID) != 0 {
				t.Fatal("guest transferred before second-factor completion")
			}
			_, err = c.VerifyBackupCode(ctx, enroll.BackupCodes[0], false)
			must(err)
			if count(`SELECT COUNT(*) FROM "guestTransfer" WHERE "source"=?`, g.User.ID) != 1 {
				t.Fatal("second-factor completion lost the guest")
			}
			c = browser(first)
			g = guest(c)
			pending, err = c.SignInEmail(ctx, client.SignInRequest{Email: "mfa@test.example", Password: "a local test password"})
			must(err)
			if !pending.TwoFactorRedirect {
				t.Fatal("expected pending guest challenge")
			}
			must(c.SignOut(ctx))
			if _, _, err = stores[0].Session(ctx, g.Token); !errors.Is(err, authn.ErrNotFound) {
				t.Fatal("sign-out during MFA retained a live guest proof")
			}
			_, err = c.VerifyBackupCode(ctx, enroll.BackupCodes[1], false)
			// A sign-out may also cancel the second-factor challenge itself.
			if err != nil {
				var api *authn.APIError
				if !errors.As(err, &api) || api.Status >= 500 {
					t.Fatal(err)
				}
			}
			if count(`SELECT COUNT(*) FROM "guestTransfer" WHERE "source"=?`, g.User.ID) != 0 {
				t.Fatal("canceled guest flow transferred after sign-out")
			}
			retain := opts
			retain.DisableDeleteAnonymousUser = true
			keep := server(retain)
			c = browser(keep)
			g = guest(c)
			expectErr(c.DeleteAnonymousUser(ctx), 400, "DELETE_ANONYMOUS_USER_DISABLED")
			n := calls.Load()
			targets := make([]string, 2)
			for i := range targets {
				hit, err := keep.SignInEmail(ctx, authn.SignInInput{Email: "permanent@test.example", Password: "a local test password"}, authn.RequestMeta{})
				must(err)
				targets[i] = hit.Token
			}
			ch := make(chan error, 2)
			for i, store := range stores[:2] {
				go func() {
					ch <- store.LinkAnonymous(ctx, g.Token, targets[i], time.Now(), true, func(_ context.Context, _ authn.AnonymousLink) error { calls.Add(1); return nil })
				}()
			}
			must(<-ch)
			must(<-ch)
			if calls.Load() != n+1 || count(`SELECT COUNT(*) FROM "user" WHERE "id"=?`, g.User.ID) != 1 {
				t.Fatal("retained guest transferred more than once or disappeared")
			}
		})
	}
}
