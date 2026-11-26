package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/phonenumber"
)

// The phone routes honour rememberMe with a browser-session cookie and a
// one-day session, capped at a shorter SessionTTL; sent codes expire after
// ExpiresIn, five minutes by default; a server without SendOTP answers 501
// before the validator runs; and the validator guards every phone route.
func TestPhoneRouteOptions(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			store, _ := phoneStores(t, dialect)
			var mu sync.Mutex
			var codes []string
			send := func(_ context.Context, m phonenumber.Message) error {
				mu.Lock()
				defer mu.Unlock()
				codes = append(codes, m.Code)
				return nil
			}
			texted := func() (int, string) {
				mu.Lock()
				defer mu.Unlock()
				if len(codes) == 0 {
					return 0, ""
				}
				return len(codes), codes[len(codes)-1]
			}
			valid := func(_ context.Context, n string) (bool, error) { return strings.HasPrefix(n, "+"), nil }
			off := false
			serve := func(o phonenumber.Options, ttl time.Duration) string {
				t.Helper()
				p, err := phonenumber.New(o)
				if err != nil {
					t.Fatal(err)
				}
				srv := httptest.NewUnstartedServer(nil)
				t.Cleanup(srv.Close)
				a, err := auth.New(auth.Options{Store: store, BaseURL: "http://" + srv.Listener.Addr().String(), Secret: strings.Repeat("s", 48), RateLimit: &off,
					EmailAndPassword: true, SessionTTL: ttl, Plugins: []auth.Plugin{p}})
				if err != nil {
					t.Fatal(err)
				}
				srv.Config.Handler = a
				srv.Start()
				return srv.URL
			}
			browser := func(url string) *client.Client {
				t.Helper()
				c, err := client.New(url, nil)
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			issued := func(h http.Header, name string) (set *http.Cookie, expired bool) {
				for _, c := range (&http.Response{Header: h}).Cookies() {
					if strings.HasSuffix(c.Name, "."+name) {
						if c.MaxAge < 0 {
							expired = true
						} else {
							set = c
						}
					}
				}
				return set, expired
			}
			const number, pw = "+12025550160", "phone-options-password"
			defaults := serve(phonenumber.Options{SendOTP: send, Validate: valid}, 0)
			owner := browser(defaults)
			if _, err := owner.SignUpEmail(ctx, client.SignUpRequest{Name: "Remember", Email: "remember@example.test", Password: pw}); err != nil {
				t.Fatal(err)
			}
			if err := owner.SendPhoneNumberOTP(ctx, number); err != nil {
				t.Fatal(err)
			}
			_, code := texted()
			if _, err := owner.VerifyPhoneNumber(ctx, auth.PhoneVerificationInput{PhoneNumber: number, Code: code, UpdatePhoneNumber: true}); err != nil {
				t.Fatal(err)
			}
			signIn := func(c *client.Client, remember *bool) (http.Header, time.Duration) {
				t.Helper()
				var out client.EmailResult
				h, err := c.DoWithHeaders(ctx, http.MethodPost, "/sign-in/phone-number", client.PhoneSignInRequest{PhoneNumber: number, Password: pw, RememberMe: remember}, &out)
				if err != nil || out.Token == nil {
					t.Fatal("phone sign-in", err)
				}
				row, _, err := store.Session(ctx, *out.Token)
				if err != nil {
					t.Fatal(err)
				}
				return h, row.ExpiresAt.Sub(row.CreatedAt)
			}
			phone := browser(defaults)
			no, yes := false, true
			// Each persistent pass follows a browser-session pass, so the jar
			// always holds a marker to clear.
			for _, remember := range []*bool{&no, nil, &no, &yes} {
				h, life := signIn(phone, remember)
				session, _ := issued(h, "session_token")
				marker, cleared := issued(h, "dont_remember")
				if remember != nil && !*remember {
					if session == nil || session.MaxAge != 0 || !session.Expires.IsZero() || marker == nil || marker.Value == "" || cleared || life != 24*time.Hour {
						t.Fatal("rememberMe false did not give a browser-session cookie with the dont_remember marker:", session != nil, marker != nil, cleared, life)
					}
				} else if session == nil || session.MaxAge != int(7*24*time.Hour/time.Second) || marker != nil || !cleared || life != 7*24*time.Hour {
					t.Fatal("a true or omitted rememberMe did not give a persistent session and clear the marker:", session != nil, marker != nil, cleared, life)
				}
			}
			short := browser(serve(phonenumber.Options{SendOTP: send, Validate: valid}, time.Hour))
			if _, life := signIn(short, &no); life != time.Hour {
				t.Fatal("a rememberMe false session outlived a shorter SessionTTL:", life)
			}

			lifetime := func(n string, purpose auth.PhoneOTPPurpose) time.Duration {
				t.Helper()
				if db, ok := store.(*Store); ok {
					var created, expires time.Time
					if err := db.db.QueryRowContext(ctx, db.bind(`SELECT "createdAt","expiresAt" FROM "verification" WHERE "identifier"=?`), phoneProofKey(n, purpose).identifier).Scan(&created, &expires); err != nil {
						t.Fatal(err)
					}
					return expires.Sub(created)
				}
				r, err := store.(auth.PhoneAccountStore).ReadPhoneOTP(ctx, n, purpose)
				if err != nil || r == nil {
					t.Fatal("no stored phone code", err)
				}
				return r.ExpiresAt.Sub(r.CreatedAt)
			}
			custom := browser(serve(phonenumber.Options{SendOTP: send, Validate: valid, ExpiresIn: 90 * time.Second}, 0))
			if err := owner.SendPhoneNumberOTP(ctx, "+12025550161"); err != nil {
				t.Fatal(err)
			}
			if err := custom.SendPhoneNumberOTP(ctx, "+12025550162"); err != nil {
				t.Fatal(err)
			}
			if err := custom.RequestPhonePasswordReset(ctx, "+12025550164"); err != nil {
				t.Fatal(err)
			}
			if d, c, r := lifetime("+12025550161", auth.PhoneVerify), lifetime("+12025550162", auth.PhoneVerify), lifetime("+12025550164", auth.PhonePasswordReset); d != 5*time.Minute || c != 90*time.Second || r != 90*time.Second {
				t.Fatal("a sent phone code does not expire after the default five minutes or the configured ExpiresIn:", d, c, r)
			}

			silent := browser(serve(phonenumber.Options{Validate: valid}, 0))
			for _, n := range []string{"+12025550163", "2025550163"} {
				var e *auth.APIError
				if err := silent.SendPhoneNumberOTP(ctx, n); !errors.As(err, &e) || e.Status != 501 || e.Code != "SEND_OTP_NOT_IMPLEMENTED" || e.Message != "sendOTP not implemented" {
					t.Fatal("send-otp without SendOTP answered", err)
				}
			}
			if r, err := store.(auth.PhoneAccountStore).ReadPhoneOTP(ctx, "+12025550163", auth.PhoneVerify); err != nil || r != nil {
				t.Fatal("send-otp without SendOTP stored a code", err)
			}

			before, _ := texted()
			phoneError(t, phone.SendPhoneNumberOTP(ctx, "2025550160"), 400, "INVALID_PHONE_NUMBER")
			h, err := phone.DoWithHeaders(ctx, http.MethodPost, "/sign-in/phone-number", client.PhoneSignInRequest{PhoneNumber: "2025550160", Password: pw}, nil)
			phoneError(t, err, 400, "INVALID_PHONE_NUMBER")
			phoneError(t, phone.RequestPhonePasswordReset(ctx, "2025550160"), 400, "INVALID_PHONE_NUMBER")
			_, err = phone.VerifyPhoneNumber(ctx, auth.PhoneVerificationInput{PhoneNumber: "2025550160", Code: "000000"})
			phoneError(t, err, 400, "INVALID_PHONE_NUMBER")
			after, _ := texted()
			if set, _ := issued(h, "session_token"); set != nil || after != before {
				t.Fatal("a number the validator rejects was texted or signed in")
			}
		})
	}
}
