package sqlstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
)

func TestPasswordResetHookAfterCommit(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store, peer := phoneStores(t, dialect)
			for index, path := range []string{"/reset-password", "/email-otp/reset-password", "/phone-number/reset-password"} {
				for _, fail := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/fail=%t", strings.TrimPrefix(path, "/"), fail), func(t *testing.T) {
						ctx := t.Context()
						must := func(err error) {
							t.Helper()
							if err != nil {
								t.Fatal(err)
							}
						}
						email := fmt.Sprintf("owner-%d-%t@example.test", index, fail)
						number := fmt.Sprintf("+1202555010%d", index*2)
						if fail {
							number = fmt.Sprintf("+1202555010%d", index*2+1)
						}
						var proof string
						sms := func(_ context.Context, m auth.PhoneOTPMessage) error { proof = m.Code; return nil }
						phone, err := auth.NewPhoneNumber(auth.PhoneNumberOptions{SendOTP: sms, SendPasswordResetOTP: sms, RequireVerification: true})
						must(err)
						mail, err := auth.NewEmailOTP(auth.EmailOTPOptions{Send: func(_ context.Context, m auth.EmailOTPMessage) error { proof = m.OTP; return nil }})
						must(err)
						const password = "new local password"
						digest := func(s string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s))) }
						off := false
						observed, resume := make(chan struct{}), make(chan struct{})
						observerError := errors.New("private notification detail")
						var calls atomic.Int32
						var original auth.AuthResult
						opts := auth.Options{Store: store, BaseURL: "https://account.test", Secret: strings.Repeat("x", 40), EmailAndPassword: true, RateLimit: &off,
							RevokeSessionsOnPasswordReset: fail, Plugins: []auth.Plugin{mail, phone},
							PasswordHash:      func(_ context.Context, s string) (string, error) { return digest(s), nil },
							PasswordVerify:    func(_ context.Context, hashed, password string) (bool, error) { return digest(password) == hashed, nil },
							SendResetPassword: func(_ context.Context, m auth.MailLink) error { proof = m.Token; return nil },
							OnPasswordReset: func(ctx context.Context, u auth.User, r *http.Request) error {
								if calls.Add(1) != 1 {
									return errors.New("unexpected second password reset callback")
								}
								defer close(observed)
								if u.ID != original.User.ID || u.Email != email || u.Name != "Owner" || u.EmailVerified {
									t.Error("callback owner did not match the pre-verification account")
								}
								if path == "/phone-number/reset-password" && (u.PhoneNumber == nil || *u.PhoneNumber != number || u.PhoneNumberVerified == nil || !*u.PhoneNumberVerified) {
									t.Error("missing bound verified phone profile")
								}
								if fail {
									if r == nil || r.URL.Path != "/api/auth"+path || r.Header.Get("X-Reset-Fixture") != "present" || r.Context() != ctx {
										t.Error("mounted callback lost the original request")
									}
								} else if r != nil {
									t.Error("native recovery unexpectedly acquired a request")
								}
								live, hash, err := peer.Credential(ctx, email)
								if err != nil || live.ID != u.ID || hash != digest(password) || live.EmailVerified {
									t.Error("callback preceded credential commit or followed email promotion", err)
								}
								_, _, err = peer.Session(ctx, original.Token)
								if fail && !errors.Is(err, auth.ErrNotFound) || !fail && err != nil {
									t.Error("incorrect session state inside observer", err)
								}
								return nil
							},
						}
						// The callback runs after store locks are released. Keep it in progress
						// while another auth instance attempts the same proof.
						observe := opts.OnPasswordReset
						opts.OnPasswordReset = func(ctx context.Context, u auth.User, r *http.Request) error {
							if err := observe(ctx, u, r); err != nil {
								return err
							}
							select {
							case <-resume:
							case <-time.After(10 * time.Second):
								return errors.New("reset observer timed out")
							}
							if fail {
								return observerError
							}
							return nil
						}
						a, err := auth.New(opts)
						must(err)
						opts.Store = peer
						b, err := auth.New(opts)
						must(err)
						original, err = a.SignUpEmail(ctx, auth.SignUpInput{Name: "Owner", Email: email, Password: "initial password"}, auth.RequestMeta{})
						must(err)
						switch path {
						case "/reset-password":
							must(a.RequestPasswordReset(ctx, email, ""))
						case "/email-otp/reset-password":
							must(a.SendEmailOTP(ctx, email, auth.OTPResetPassword))
						case "/phone-number/reset-password":
							r := httptest.NewRequest("GET", "/", nil)
							r.AddCookie(a.SessionCookie(original.Token, true))
							must(a.SendPhoneNumberOTP(ctx, number))
							_, err = a.VerifyPhoneNumber(ctx, r.Header, auth.PhoneVerificationInput{PhoneNumber: number, Code: proof, UpdatePhoneNumber: true, DisableSession: true}, auth.RequestMeta{})
							must(err)
							must(a.RequestPhonePasswordReset(ctx, number))
						}
						if proof == "" {
							t.Fatal("missing reset proof")
						}
						reset := func(node *auth.Auth) error {
							switch path {
							case "/reset-password":
								return node.ResetPassword(ctx, proof, password)
							case "/email-otp/reset-password":
								return node.ResetPasswordEmailOTP(ctx, email, proof, password)
							default:
								return node.ResetPhonePassword(ctx, number, proof, password)
							}
						}
						finished := make(chan error, 1)
						go func() {
							if !fail {
								finished <- reset(a)
								return
							}
							fields := map[string]string{"token": proof, "newPassword": password}
							if path == "/email-otp/reset-password" {
								fields = map[string]string{"email": email, "otp": proof, "password": password}
							}
							if path == "/phone-number/reset-password" {
								fields = map[string]string{"phoneNumber": number, "otp": proof, "newPassword": password}
							}
							data, err := json.Marshal(fields)
							if err != nil {
								finished <- err
								return
							}
							r := httptest.NewRequest(http.MethodPost, "https://account.test/api/auth"+path, bytes.NewReader(data))
							r.Header.Set("Origin", "https://account.test")
							r.Header.Set("Content-Type", "application/json")
							r.Header.Set("X-Reset-Fixture", "present")
							w := httptest.NewRecorder()
							a.ServeHTTP(w, r)
							if w.Code != 500 || strings.Contains(w.Body.String(), observerError.Error()) {
								finished <- fmt.Errorf("unexpected public callback error: %d %s", w.Code, w.Body.String())
								return
							}
							finished <- nil
						}()
						select {
						case <-observed:
						case err := <-finished:
							t.Fatalf("reset finished before callback: %v", err)
						case <-time.After(8 * time.Second):
							t.Fatal("callback blocked before observing committed state")
						}
						replayErr := reset(b)
						close(resume)
						if replayErr == nil {
							t.Fatal("another instance reused a committed proof")
						}
						must(<-finished)
						if calls.Load() != 1 {
							t.Fatalf("ran callback %d times", calls.Load())
						}
						u, hash, err := peer.Credential(ctx, email)
						must(err)
						if hash != digest(password) || u.EmailVerified != (path == "/email-otp/reset-password" && !fail) {
							t.Fatal("credential or email verification differed after callback")
						}
					})
				}
			}
		})
	}
}

func TestResetObserverCannotVerifyAChangedMailbox(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store, peer := phoneStores(t, dialect)
			ctx := t.Context()
			const address = "resume@example.test"
			// These distinct mailboxes compare equal under common MySQL collations.
			const replacement = "résumé@example.test"
			var code string
			plugin, err := auth.NewEmailOTP(auth.EmailOTPOptions{Send: func(_ context.Context, m auth.EmailOTPMessage) error { code = m.OTP; return nil }})
			if err != nil {
				t.Fatal(err)
			}
			changes := peer.(interface {
				ChangeAccountEmail(context.Context, string, string, string, bool, time.Time) (auth.User, error)
			})
			opts := auth.Options{Store: store, BaseURL: "https://auth.example.test", Secret: strings.Repeat("s", 40), EmailAndPassword: true, Plugins: []auth.Plugin{plugin}, OnPasswordReset: func(ctx context.Context, u auth.User, _ *http.Request) error {
				_, err := changes.ChangeAccountEmail(ctx, u.ID, address, replacement, false, time.Now())
				return err
			}}
			a, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = a.SignUpEmail(ctx, auth.SignUpInput{Name: "Owner", Email: address, Password: "before reset"}, auth.RequestMeta{}); err != nil {
				t.Fatal(err)
			}
			if err = a.SendEmailOTP(ctx, address, auth.OTPResetPassword); err != nil {
				t.Fatal(err)
			}
			err = a.ResetPasswordEmailOTP(ctx, address, code, "after reset")
			if !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("post-callback verification accepted another mailbox", err)
			}
			u, hash, err := peer.Credential(ctx, replacement)
			if err != nil || u.EmailVerified || u.Email != replacement {
				t.Fatal("a new mailbox acquired the old verification", err)
			}
			valid, err := auth.VerifyPasswordHash(ctx, hash, "after reset")
			if err != nil || !valid {
				t.Fatal("changing the address rolled back the credential", err)
			}
			if err = a.ResetPasswordEmailOTP(ctx, address, code, "replay reset"); err == nil {
				t.Fatal("changing the address restored the proof")
			}
		})
	}
}
