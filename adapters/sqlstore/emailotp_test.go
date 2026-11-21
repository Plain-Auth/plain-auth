package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/nabuhadba/go-better-auth"
	"github.com/nabuhadba/go-better-auth/plugins/emailotp"
)

func TestEmailOTPDeliveryAndProof(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := filepath.Join(t.TempDir(), "otp.db")
			if dialect != "sqlite" {
				dsn = os.Getenv("AUTH_TEST_" + strings.ToUpper(dialect) + "_DSN")
				if dsn == "" {
					t.Skip("requires a disposable local database")
				}
			}
			s, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			replica, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer replica.Close()
			email := strings.ToLower(rand.Text()) + "@example.test"
			const origin = "https://mail.example.test"
			var delivery emailotp.Message
			var issued atomic.Int64
			var calls int
			cfg := emailotp.Options{StoreOTP: "hashed", GenerateOTP: func(context.Context, string, emailotp.Purpose) (string, error) {
				return fmt.Sprintf("%06d", issued.Add(1)), nil
			}, Send: func(_ context.Context, m emailotp.Message) error { delivery = m; calls++; return nil }}
			makeAuth := func(store *Store, options emailotp.Options, gate bool, rate bool) *auth.Auth {
				t.Helper()
				p, err := emailotp.New(options)
				if err != nil {
					t.Fatal(err)
				}
				filter := auth.Plugin{ID: "test-password-policy", OnValidateNewPassword: func(_ context.Context, path, password string) error {
					if path == "/email-otp/reset-password" && password == "declined-credential" {
						return &auth.APIError{Status: 400, Code: "DECLINED", Message: "Password policy declined the value"}
					}
					return nil
				}}
				a, err := auth.New(auth.Options{Store: store, Secret: "local-email-otp-test-key-0000000000000", BaseURL: origin, EmailAndPassword: true, RequireEmailVerification: gate, RevokeSessionsOnPasswordReset: true, RateLimit: &rate, Plugins: []auth.Plugin{p, filter}})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			first, second := makeAuth(s, cfg, false, false), makeAuth(replica, cfg, false, false)
			call := func(a *auth.Auth, path string, body map[string]any, from string) *httptest.ResponseRecorder {
				t.Helper()
				raw, _ := json.Marshal(body)
				r := httptest.NewRequest("POST", origin+"/api/auth"+path, strings.NewReader(string(raw)))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", from)
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				return w
			}
			want := func(err error, code string) {
				t.Helper()
				var e *auth.APIError
				if !errors.As(err, &e) || e.Code != code {
					t.Fatalf("wanted %s, got %v", code, err)
				}
			}
			verifyStored := func(p emailotp.Purpose) string {
				t.Helper()
				var value string
				err := s.db.QueryRowContext(ctx, s.bind(`SELECT "value" FROM "verification" WHERE "identifier"=?`), string(p)+"-otp-"+email).Scan(&value)
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			for _, path := range []string{"/email-otp/request-password-reset", "/forget-password/email-otp", "/email-otp/send-verification-otp"} {
				w := call(first, path, map[string]any{"email": email, "type": "email-verification"}, origin)
				if w.Code != 200 || !strings.Contains(w.Body.String(), `"success":true`) || calls != 0 {
					t.Fatalf("private unknown mailbox request %s returned %d %q", path, w.Code, w.Body.String())
				}
			}
			cfgDisabled := cfg
			cfgDisabled.DisableSignUp = true
			closed := makeAuth(replica, cfgDisabled, false, false)
			if err = closed.SendEmailOTP(ctx, email, emailotp.SignIn); err != nil || calls != 0 {
				t.Fatal("disabled registration delivered a code", err)
			}
			w := call(first, "/email-otp/send-verification-otp", map[string]any{"email": strings.ToUpper(email), "type": "sign-in"}, origin)
			if w.Code != 200 || calls != 1 || delivery.OTP != "000001" || delivery.Email != email || delivery.Type != emailotp.SignIn || strings.Contains(w.Body.String(), delivery.OTP) {
				t.Fatalf("sign-in delivery disclosed data or sent the wrong message, HTTP %d", w.Code)
			}
			sum := sha256.Sum256([]byte(delivery.OTP))
			if verifyStored(emailotp.SignIn) != base64.RawURLEncoding.EncodeToString(sum[:])+":0" {
				t.Fatal("hashed canonical proof mismatch")
			}
			want(first.CheckEmailOTP(ctx, email, delivery.OTP, emailotp.SignIn), "USER_NOT_FOUND")
			want(first.CheckEmailOTP(ctx, email, delivery.OTP, emailotp.VerifyEmail), "INVALID_OTP")
			w = call(first, "/sign-in/email-otp", map[string]any{"email": email, "otp": delivery.OTP}, "https://foreign.example")
			if w.Code != 403 {
				t.Fatal("foreign sign-in origin accepted")
			}
			input := auth.EmailOTPSignInInput{Email: email, OTP: delivery.OTP, Name: "Inbox Owner"}
			image := "https://images.example.test/profile.png"
			input.Image = &image
			var wg sync.WaitGroup
			type login struct {
				result auth.AuthResult
				err    error
			}
			ch := make(chan login, 8)
			for i := range 8 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					a := []*auth.Auth{first, second}[i%2]
					r, e := a.SignInEmailOTP(ctx, input, auth.RequestMeta{})
					ch <- login{r, e}
				}()
			}
			wg.Wait()
			close(ch)
			winners := 0
			var owner auth.AuthResult
			for r := range ch {
				if r.err != nil {
					want(r.err, "INVALID_OTP")
					continue
				}
				winners++
				owner = r.result
			}
			if winners != 1 || owner.Token == "" || owner.User.Email != email || owner.User.Name != input.Name || !owner.User.EmailVerified || owner.User.Image == nil || *owner.User.Image != image {
				t.Fatalf("competing proofs produced %d sessions, owner=%+v", winners, owner.User)
			}
			if _, u, err := replica.Session(ctx, owner.Token); err != nil || u.ID != owner.User.ID {
				t.Fatal("persisted OTP login", err)
			}
			if err = closed.SendEmailOTP(ctx, email, emailotp.SignIn); err != nil {
				t.Fatal(err)
			}
			if existing, err := closed.SignInEmailOTP(ctx, auth.EmailOTPSignInInput{Email: email, OTP: delivery.OTP}, auth.RequestMeta{}); err != nil || existing.User.ID != owner.User.ID {
				t.Fatal("registration policy blocked an existing account", err)
			}
			late := "disabled-" + email
			if err = first.SendEmailOTP(ctx, late, emailotp.SignIn); err != nil {
				t.Fatal(err)
			}
			_, err = closed.SignInEmailOTP(ctx, auth.EmailOTPSignInInput{Email: late, OTP: delivery.OTP}, auth.RequestMeta{})
			want(err, "INVALID_OTP")
			if w = call(first, "/forget-password/email-otp", map[string]any{"email": email}, origin); w.Code != 200 || delivery.Email != email || delivery.Type != emailotp.ResetPassword {
				t.Fatal("recovery alias failed to deliver to the current owner")
			}
			if err = first.SendEmailOTP(ctx, email, emailotp.SignIn); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				want(second.CheckEmailOTP(ctx, email, "wrong", emailotp.SignIn), "INVALID_OTP")
			}
			want(first.CheckEmailOTP(ctx, email, delivery.OTP, emailotp.SignIn), "TOO_MANY_ATTEMPTS")
			want(first.CheckEmailOTP(ctx, email, delivery.OTP, emailotp.SignIn), "INVALID_OTP")
			if err = first.SendEmailOTP(ctx, email, emailotp.SignIn); err != nil {
				t.Fatal(err)
			}
			if _, err = s.db.ExecContext(ctx, s.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "identifier"=?`), s.date(time.Now().Add(-time.Minute)), "sign-in-otp-"+email); err != nil {
				t.Fatal(err)
			}
			want(first.CheckEmailOTP(ctx, email, delivery.OTP, emailotp.SignIn), "OTP_EXPIRED")
			if err = first.SendEmailOTP(ctx, email, emailotp.SignIn); err != nil {
				t.Fatal(err)
			}
			failures := make(chan error, 12)
			for i := range 12 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					failures <- []*auth.Auth{first, second}[i%2].CheckEmailOTP(ctx, email, "wrong", emailotp.SignIn)
				}()
			}
			wg.Wait()
			close(failures)
			locked := 0
			for e := range failures {
				var denied *auth.APIError
				if !errors.As(e, &denied) {
					t.Fatalf("concurrent retry failed: %v", e)
				}
				switch denied.Code {
				case "TOO_MANY_ATTEMPTS":
					locked++
				case "INVALID_OTP":
				default:
					t.Fatalf("unexpected retry response %s", denied.Code)
				}
			}
			if locked != 1 {
				t.Fatalf("retry budget exhausted %d times", locked)
			}
			want(first.CheckEmailOTP(ctx, email, delivery.OTP, emailotp.SignIn), "INVALID_OTP")
			cfgReuse := cfg
			cfgReuse.ResendStrategy = "reuse"
			cfgReuse.StoreOTP = "encrypted"
			cfgReuse.AllowedAttempts = 2
			cfgReuse.ExpiresIn = 11 * time.Minute
			reuser := makeAuth(replica, cfgReuse, false, false)
			if err = reuser.SendEmailOTP(ctx, email, emailotp.VerifyEmail); err != nil {
				t.Fatal(err)
			}
			firstCode := delivery.OTP
			var created, expires time.Time
			if err := s.db.QueryRowContext(ctx, s.bind(`SELECT "createdAt","expiresAt" FROM "verification" WHERE "identifier"=?`), "email-verification-otp-"+email).Scan(&created, &expires); err != nil || expires.Sub(created) != 11*time.Minute {
				t.Fatal("configured OTP lifetime was not persisted", err)
			}
			want(reuser.CheckEmailOTP(ctx, email, "wrong", emailotp.VerifyEmail), "INVALID_OTP")
			if err = reuser.SendEmailOTP(ctx, email, emailotp.VerifyEmail); err != nil {
				t.Fatal(err)
			}
			state := verifyStored(emailotp.VerifyEmail)
			if delivery.OTP != firstCode || strings.Contains(state, firstCode) || !strings.HasSuffix(state, ":1") {
				t.Fatal("encrypted resend lost proof or retry count")
			}
			if err = reuser.CheckEmailOTP(ctx, email, firstCode, emailotp.VerifyEmail); err != nil {
				t.Fatal("successful preflight did not preserve proof", err)
			}
			w = call(reuser, "/email-otp/verify-email", map[string]any{"email": email, "otp": firstCode}, origin)
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"token":null`) || len(w.Result().Cookies()) != 0 {
				t.Fatalf("verification issued unexpected session: %d %s", w.Code, w.Body)
			}
			_, err = reuser.VerifyEmailOTP(ctx, email, firstCode)
			want(err, "INVALID_OTP")
			cfgReuse.StoreOTP = "hashed"
			rotator := makeAuth(s, cfgReuse, false, false)
			if err = rotator.SendEmailOTP(ctx, email, emailotp.SignIn); err != nil {
				t.Fatal(err)
			}
			prior := delivery.OTP
			if err = rotator.SendEmailOTP(ctx, email, emailotp.SignIn); err != nil {
				t.Fatal(err)
			}
			if prior == delivery.OTP {
				t.Fatal("hashed resend failed to rotate")
			}
			want(rotator.CheckEmailOTP(ctx, email, prior, emailotp.SignIn), "INVALID_OTP")
			w = call(rotator, "/sign-in/email-otp", map[string]any{"email": email, "otp": delivery.OTP}, origin)
			if w.Code != 200 || len(w.Result().Cookies()) == 0 {
				t.Fatalf("HTTP sign-in did not issue a cookie %d %s", w.Code, w.Body)
			}
			w = call(first, "/email-otp/request-password-reset", map[string]any{"email": email}, origin)
			if w.Code != 200 || delivery.Type != emailotp.ResetPassword {
				t.Fatal("reset did not reach mailbox")
			}
			code := delivery.OTP
			want(first.ResetPasswordEmailOTP(ctx, email, code, "short"), "PASSWORD_TOO_SHORT")
			want(first.ResetPasswordEmailOTP(ctx, email, code, "declined-credential"), "DECLINED")
			w = call(second, "/email-otp/check-verification-otp", map[string]any{"email": email, "type": "forget-password", "otp": code}, origin)
			if w.Code != 200 {
				t.Fatal("valid OTP preflight failed", w.Body)
			}
			w = call(second, "/email-otp/reset-password", map[string]any{"email": email, "otp": code, "password": "strong-replacement"}, origin)
			if w.Code != 200 {
				t.Fatal("valid reset failed", w.Code, w.Body)
			}
			want(first.ResetPasswordEmailOTP(ctx, email, code, "new-replacement"), "INVALID_OTP")
			if _, _, err = s.Session(ctx, owner.Token); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("pre-reset session persisted", err)
			}
			passwordLogin, err := first.SignInEmail(ctx, auth.SignInInput{Email: email, Password: "strong-replacement"}, auth.RequestMeta{})
			if err != nil || passwordLogin.User.ID != owner.User.ID {
				t.Fatal("reset credential failed", err)
			}
			if err = first.SendEmailOTP(ctx, email, emailotp.ResetPassword); err != nil {
				t.Fatal(err)
			}
			stale := delivery.OTP
			// A compatible preflight can reinsert the same proof with a different physical ID.
			if _, err = s.db.ExecContext(ctx, s.bind(`UPDATE "verification" SET "id"=? WHERE "identifier"=?`), rand.Text(), "forget-password-otp-"+email); err != nil {
				t.Fatal(err)
			}
			if _, err = s.db.ExecContext(ctx, s.bind(`UPDATE "user" SET "email"=? WHERE "id"=?`), "former-"+email, owner.User.ID); err != nil {
				t.Fatal(err)
			}
			reassigned, err := first.SignUpEmail(ctx, auth.SignUpInput{Email: email, Password: "credential-for-new-owner", Name: "Other"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			want(second.ResetPasswordEmailOTP(ctx, email, stale, "reset-other-owner"), "INVALID_OTP")
			if err = first.SendEmailOTP(ctx, email, emailotp.SignIn); err != nil {
				t.Fatal(err)
			}
			verified, err := second.SignInEmailOTP(ctx, auth.EmailOTPSignInInput{Email: email, OTP: delivery.OTP}, auth.RequestMeta{})
			if err != nil || !verified.User.EmailVerified || verified.User.ID != reassigned.User.ID {
				t.Fatal("unverified mailbox promotion", err)
			}
			if _, _, err = s.Credential(ctx, email); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("unproven credential remained after sign-in", err)
			}
			if _, _, err = s.Session(ctx, reassigned.Token); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("unproven session remained after sign-in", err)
			}
			cfgGate := cfg
			cfgGate.SendVerificationOnSignUp = true
			cfgGate.StoreOTP = "plain"
			cfgGate.GenerateOTP = nil
			gate := makeAuth(s, cfgGate, true, false)
			other := "gate-" + email
			registered, err := gate.SignUpEmail(ctx, auth.SignUpInput{Email: other, Password: "password-for-verified-inbox"}, auth.RequestMeta{})
			if err != nil || registered.Token != "" || delivery.Type != emailotp.VerifyEmail || delivery.Email != other || len(delivery.OTP) != 6 {
				t.Fatal("gated registration or default six-digit mail failed", err)
			}
			if _, err = gate.SignInEmail(ctx, auth.SignInInput{Email: other, Password: "password-for-verified-inbox"}, auth.RequestMeta{}); err == nil {
				t.Fatal("unverified account authenticated")
			}
			v, err := gate.VerifyEmailOTP(ctx, other, delivery.OTP)
			if err != nil || !v.EmailVerified || v.ID != registered.User.ID {
				t.Fatal("gated verification", err)
			}
			if _, err = gate.SignInEmail(ctx, auth.SignInInput{Email: other, Password: "password-for-verified-inbox"}, auth.RequestMeta{}); err != nil {
				t.Fatal("verified account could not sign in", err)
			}
			cfgGate.SendVerificationOnSignUp = false
			cfgGate.OverrideDefaultEmailVerification = true
			cfgGate.Length = 8
			override := makeAuth(s, cfgGate, true, false)
			overEmail := "override-" + email
			_, err = override.SignUpEmail(ctx, auth.SignUpInput{Email: overEmail, Password: "password-for-override-inbox"}, auth.RequestMeta{})
			if err != nil || delivery.Email != overEmail || len(delivery.OTP) != 8 {
				t.Fatal("default verification override did not deliver configured code length", err)
			}
			customLimit := cfg
			customLimit.RateLimit = &auth.RateLimitRule{Max: 1, Window: time.Minute}
			restricted := makeAuth(s, customLimit, false, true)
			if w = call(restricted, "/email-otp/send-verification-otp", map[string]any{"email": "missing-" + email, "type": "forget-password"}, origin); w.Code != 200 {
				t.Fatal("custom limit denied first request")
			}
			if w = call(restricted, "/email-otp/send-verification-otp", map[string]any{"email": "missing-" + email, "type": "forget-password"}, origin); w.Code != 429 {
				t.Fatal("custom email OTP rate limit was ignored")
			}
			limited := makeAuth(s, cfg, false, true)
			for range 3 {
				if w = call(limited, "/email-otp/request-password-reset", map[string]any{"email": "missing-" + email}, origin); w.Code != 200 {
					t.Fatal("rate limit applied early")
				}
			}
			if w = call(limited, "/email-otp/request-password-reset", map[string]any{"email": "missing-" + email}, origin); w.Code != 429 {
				t.Fatal("default endpoint rate limit was not applied", w.Code)
			}
		})
	}
}
