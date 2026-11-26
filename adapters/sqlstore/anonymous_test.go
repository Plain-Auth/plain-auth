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

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/anonymous"
	"github.com/Plain-Org/plain-auth/plugins/phonenumber"
	"github.com/Plain-Org/plain-auth/plugins/twofactor"
	"github.com/Plain-Org/plain-auth/schema"
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
			// A password sign-in from a guest browser hands the guest off and,
			// with deletion disabled, keeps its user row and session.
			c = browser(keep)
			g = guest(c)
			signed, err = c.SignInEmail(ctx, client.SignInRequest{Email: "permanent@test.example", Password: "a local test password"})
			must(err)
			if signed.User.ID == g.User.ID || count(`SELECT COUNT(*) FROM "guestTransfer" WHERE "source"=?`, g.User.ID) != 1 ||
				count(`SELECT COUNT(*) FROM "user" WHERE "id"=?`, g.User.ID) != 1 || count(`SELECT COUNT(*) FROM "session" WHERE "userId"=?`, g.User.ID) != 1 {
				t.Fatal("a retained guest was deleted or not handed off on sign-in")
			}
		})
	}
}

// A guest who signs in with a phone code is handed off to that number's
// account like any other sign-in, while a sessionless verification and a
// number update keep the guest.
func TestAnonymousPhoneHandoff(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			var store authn.Store
			if dialect == "memory" {
				store = memory.New()
			} else {
				ddl, err := schema.Generate(dialect, []string{"phone-number", "anonymous"})
				if err != nil {
					t.Fatal(err)
				}
				db, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { db.Close() })
				store = db
			}
			var code string
			phone, err := phonenumber.New(phonenumber.Options{SendOTP: func(_ context.Context, m authn.PhoneOTPMessage) error { code = m.Code; return nil },
				SignUpOnVerification: &authn.PhoneSignUpOptions{GetTempEmail: func(n string) string { return n[1:] + "@phone.test" }}})
			if err != nil {
				t.Fatal(err)
			}
			var links []anonymous.Link
			guests, err := anonymous.New(anonymous.Options{OnLinkAccount: func(_ context.Context, e anonymous.Link) error { links = append(links, e); return nil }})
			if err != nil {
				t.Fatal(err)
			}
			const origin = "https://phone-guest.example"
			off := false
			a, err := authn.New(authn.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("p", 32), RateLimit: &off, EmailAndPassword: true, Plugins: []authn.Plugin{guests, phone}})
			if err != nil {
				t.Fatal(err)
			}
			browser := func() *client.Client {
				c, err := client.New(origin, &http.Client{Transport: guestTransport{a}})
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			verify := func(c *client.Client, number string, sessionless, update bool) *client.PhoneVerificationResult {
				t.Helper()
				if err := c.SendPhoneNumberOTP(ctx, number); err != nil {
					t.Fatal(err)
				}
				result, err := c.VerifyPhoneNumber(ctx, authn.PhoneVerificationInput{PhoneNumber: number, Code: code, DisableSession: sessionless, UpdatePhoneNumber: update})
				if err != nil {
					t.Fatal(err)
				}
				return result
			}
			guestStore := store.(authn.AnonymousStore)
			c := browser()
			g, err := c.SignInAnonymous(ctx)
			if err != nil {
				t.Fatal(err)
			}
			signed := verify(c, "+12025550142", false, false)
			if len(links) != 1 || links[0].AnonymousUser.User.ID != g.User.ID || links[0].NewUser.User.ID != signed.User.ID || links[0].Request.URL.Path != "/api/auth/phone-number/verify" {
				t.Fatal("phone verification did not hand off the guest", links)
			}
			if _, err := guestStore.IsAnonymous(ctx, g.User.ID); !errors.Is(err, authn.ErrNotFound) {
				t.Fatal("the guest survived a phone sign-in", err)
			}
			if _, _, err := store.Session(ctx, g.Token); !errors.Is(err, authn.ErrNotFound) {
				t.Fatal("the guest session survived a phone sign-in", err)
			}
			if s, err := c.GetSession(ctx); err != nil || s == nil || s.User.ID != signed.User.ID || s.User.IsAnonymous == nil || *s.User.IsAnonymous {
				t.Fatal("the browser is not signed in as the phone account", err)
			}
			c2 := browser()
			g2, err := c2.SignInAnonymous(ctx)
			if err != nil {
				t.Fatal(err)
			}
			verify(c2, "+12025550142", true, false)
			if anon, err := guestStore.IsAnonymous(ctx, g2.User.ID); len(links) != 1 || err != nil || !anon {
				t.Fatal("a sessionless phone verification handed off the guest", err)
			}
			if s, err := c2.GetSession(ctx); err != nil || s == nil || s.User.ID != g2.User.ID {
				t.Fatal("a sessionless phone verification signed the guest out", err)
			}
			verify(c2, "+12025550143", false, true)
			if anon, err := guestStore.IsAnonymous(ctx, g2.User.ID); len(links) != 1 || err != nil || !anon {
				t.Fatal("a phone number update handed off the guest", err)
			}
			if s, err := c2.GetSession(ctx); err != nil || s == nil || s.User.ID != g2.User.ID {
				t.Fatal("a phone number update signed the guest out", err)
			}
			owner := browser()
			const pw = "phone-guest-password"
			if _, err := owner.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "owner@phone-guest.example", Password: pw}); err != nil {
				t.Fatal(err)
			}
			verify(owner, "+12025550144", false, true)
			c3 := browser()
			g3, err := c3.SignInAnonymous(ctx)
			if err != nil {
				t.Fatal(err)
			}
			byPassword, err := c3.SignInPhoneNumber(ctx, client.PhoneSignInRequest{PhoneNumber: "+12025550144", Password: pw})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := guestStore.IsAnonymous(ctx, g3.User.ID); len(links) != 2 || links[1].AnonymousUser.User.ID != g3.User.ID || links[1].NewUser.User.ID != byPassword.User.ID || links[1].Request.URL.Path != "/api/auth/sign-in/phone-number" || !errors.Is(err, authn.ErrNotFound) {
				t.Fatal("a phone password sign-in did not hand off and remove the guest", links, err)
			}
		})
	}
}
