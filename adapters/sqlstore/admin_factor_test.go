package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	stonewrit "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/client"
	"github.com/Stonewrit/stonewrit-auth/plugins/admin"
	"github.com/Stonewrit/stonewrit-auth/plugins/anonymous"
	"github.com/Stonewrit/stonewrit-auth/plugins/organization"
	"github.com/Stonewrit/stonewrit-auth/plugins/passkey"
	"github.com/Stonewrit/stonewrit-auth/plugins/stripe"
	"github.com/Stonewrit/stonewrit-auth/plugins/twofactor"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

func TestAdminGuestAndFactorSessionBoundaries(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			expect := func(err error, code string) {
				t.Helper()
				var api *stonewrit.APIError
				if !errors.As(err, &api) || api.Code != code {
					t.Fatalf("expected %s, got %v", code, err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"admin", "anonymous", "device-authorization", "jwt", "organization", "passkey", "two-factor"})
			must(err)
			s, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer s.Close()
			operator := testUser("operator")
			seed := testSession(operator, "operator-session")
			seed.ExpiresAt = time.Now().Add(time.Hour)
			must(s.CreateUser(ctx, operator, "unused", &seed))
			administration, err := admin.New(admin.Options{AdminUserIDs: []string{operator.ID}})
			must(err)
			guests, err := anonymous.New(anonymous.Options{})
			must(err)
			deliveries := 0
			factors := twofactor.New(twofactor.Options{OTP: twofactor.OTPOptions{Send: func(context.Context, twofactor.OTPMessage) error {
				deliveries++
				return nil
			}}})
			const origin = "https://accounts.example"
			keys, err := passkey.New(passkey.Options{RPID: "accounts.example", RPName: "Accounts", Origins: []string{origin}})
			must(err)
			devices, err := stonewrit.NewDeviceAuthorization(stonewrit.DeviceAuthorizationOptions{})
			must(err)
			orgs, err := organization.New(organization.Options{Store: s})
			must(err)
			transfers, err := stonewrit.NewOneTimeToken(stonewrit.OneTimeTokenOptions{})
			must(err)
			jwt, err := stonewrit.NewJWT(stonewrit.JWTOptions{})
			must(err)
			billing := stripe.New(stripe.Options{Portal: &stripe.PortalOptions{Customers: s}})
			off := false
			service, err := stonewrit.New(stonewrit.Options{Store: s, BaseURL: origin, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []stonewrit.Plugin{factors, guests, administration, keys, devices, orgs, transfers, jwt, billing}})
			must(err)
			browser := func(credentials ...*http.Cookie) *client.Client {
				t.Helper()
				jar, err := cookiejar.New(nil)
				must(err)
				base, err := url.Parse(origin)
				must(err)
				jar.SetCookies(base, credentials)
				b, err := client.New(origin, &http.Client{Jar: jar, Transport: guestTransport{service}})
				must(err)
				return b
			}
			member := browser()
			guest, err := member.SignInAnonymous(ctx)
			must(err)
			if guest.User.AdminUserFields == nil || guest.User.Role != "user" || guest.User.IsAnonymous == nil || !*guest.User.IsAnonymous || guest.User.TwoFactorEnabled == nil || *guest.User.TwoFactorEnabled {
				t.Fatal("guest registration omitted its active profile fields")
			}
			const password = "owner example password"
			login := client.SignInRequest{Email: "member@example.test", Password: password}
			account, err := member.SignUpEmail(ctx, client.SignUpRequest{Email: login.Email, Password: password, Name: "Member"})
			must(err)
			again, err := member.SignInEmail(ctx, login)
			must(err)
			if again.User.AdminUserFields == nil || again.User.Role != "user" || again.User.IsAnonymous == nil || *again.User.IsAnonymous {
				t.Fatal("credential login omitted the administrative or guest fields")
			}
			staff := browser(service.SessionCookie(seed.Token, true))
			delegated, err := staff.AdminImpersonate(ctx, account.User.ID)
			must(err)
			tx, err := s.db.BeginTx(ctx, nil)
			must(err)
			ownerErr := s.lockActiveAccount(ctx, tx, account.User.ID, delegated.Session.Token, time.Now())
			must(tx.Rollback())
			if !errors.Is(ownerErr, stonewrit.ErrNotFound) {
				t.Fatalf("delegated source authorized a credential write: %v", ownerErr)
			}
			expect(staff.EnableDeliveredFactor(ctx, password), "UNAUTHORIZED")
			for _, path := range []string{"/list-sessions", "/one-time-token/generate", "/passkey/generate-register-options", "/token"} {
				expect(staff.Do(ctx, http.MethodGet, path, nil, nil), "OWNER_SESSION_REQUIRED")
			}
			for path, body := range map[string]map[string]string{
				"/revoke-sessions":             {},
				"/get-access-token":            {"accountId": "local-selected-account"},
				"/organization/invite-member":  {"email": "member@example.test", "role": "member"},
				"/device/approve":              {"userCode": "EXAMPLE"},
				"/subscription/billing-portal": {},
			} {
				expect(staff.Do(ctx, http.MethodPost, path, body, nil), "OWNER_SESSION_REQUIRED")
			}
			sessionHeaders := func(token string) http.Header {
				t.Helper()
				req := httptest.NewRequest(http.MethodGet, origin+"/api/auth/get-session", nil)
				req.AddCookie(service.SessionCookie(token, true))
				rec := httptest.NewRecorder()
				service.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("get-session returned %d", rec.Code)
				}
				return rec.Header()
			}
			if sessionHeaders(delegated.Session.Token).Get("Set-Auth-Jwt") != "" || sessionHeaders(*again.Token).Get("Set-Auth-Jwt") == "" {
				t.Fatal("JWT session header did not distinguish delegation from direct authentication")
			}
			active, err := staff.GetSession(ctx)
			must(err)
			if active == nil || active.Session.ID != delegated.Session.ID || active.Session.ImpersonatedBy == nil || *active.Session.ImpersonatedBy != operator.ID {
				t.Fatal("denied enrollment changed the delegated login")
			}
			_, err = staff.AdminStopImpersonating(ctx)
			must(err)
			must(member.EnableDeliveredFactor(ctx, password))
			challenged := browser()
			visitor, err := challenged.SignInAnonymous(ctx)
			must(err)
			pending, err := challenged.SignInEmail(ctx, login)
			must(err)
			if !pending.TwoFactorRedirect || pending.Token != nil {
				t.Fatal("credential sign-in did not leave a pending second factor")
			}
			_, err = staff.AdminBanUser(ctx, account.User.ID, "", time.Hour)
			must(err)
			expect(challenged.SendFactorOTP(ctx), "INVALID_TWO_FACTOR_COOKIE")
			err = s.WithTwoFactor(ctx, stonewrit.FactorSubject{UserID: account.User.ID, Now: time.Now()}, func(stonewrit.FactorState) (stonewrit.FactorChange, error) {
				return stonewrit.FactorChange{}, errors.New("suspended owner reached a factor operation")
			})
			expect(err, "BANNED_USER")
			if deliveries != 0 {
				t.Fatal("suspended account received an OTP")
			}
			retained, err := s.IsAnonymous(ctx, visitor.User.ID)
			must(err)
			if !retained {
				t.Fatal("a denied second factor transferred the guest")
			}
			signed, err := challenged.GetSession(ctx)
			must(err)
			if signed != nil {
				t.Fatal("denied challenge issued a session")
			}
			_, err = staff.AdminUnbanUser(ctx, account.User.ID)
			must(err)
			expect(challenged.SendFactorOTP(ctx), "INVALID_TWO_FACTOR_COOKIE")
			_, err = challenged.SignInEmail(ctx, login)
			must(err)
			must(staff.AdminSetPassword(ctx, account.User.ID, "replacement example password"))
			expect(challenged.SendFactorOTP(ctx), "INVALID_TWO_FACTOR_COOKIE")
		})
	}
}
