package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/emailotp"
)

func TestEmailOTPConcurrentMemory(t *testing.T) {
	s := New()
	ctx := t.Context()
	const email = "local@example.test"
	var calls int
	p, err := emailotp.New(emailotp.Options{AllowedAttempts: 2,
		GenerateOTP: func(ctx context.Context, email string, _ emailotp.Purpose) (string, error) {
			// User callbacks may read the same store while preparing a proof.
			_, err := s.FindAccountUser(ctx, email)
			if err != nil && !errors.Is(err, auth.ErrNotFound) {
				return "", err
			}
			return "012345", nil
		},
		Send: func(context.Context, emailotp.Message) error { calls++; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	makeAuth := func() *auth.Auth {
		t.Helper()
		a, err := auth.New(auth.Options{Store: s, BaseURL: "https://local.example", Secret: "local-testing-email-otp-secret-0001x", Plugins: []auth.Plugin{p}, EmailAndPassword: true, RevokeSessionsOnPasswordReset: true})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	first, other := makeAuth(), makeAuth()
	old, err := first.SignUpEmail(ctx, auth.SignUpInput{Email: email, Name: "Inbox", Password: "initial-password"}, auth.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if err = first.SendEmailOTP(ctx, email, emailotp.SignIn); err != nil || calls != 1 {
		t.Fatal("memory send", err)
	}
	var wg sync.WaitGroup
	type result struct {
		r   auth.AuthResult
		err error
	}
	results := make(chan result, 10)
	for i := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := []*auth.Auth{first, other}[i%2].SignInEmailOTP(ctx, auth.EmailOTPSignInInput{Email: email, OTP: "012345"}, auth.RequestMeta{})
			results <- result{r, err}
		}()
	}
	wg.Wait()
	close(results)
	var login auth.AuthResult
	count := 0
	for v := range results {
		if v.err == nil {
			count++
			login = v.r
		} else {
			var api *auth.APIError
			if !errors.As(v.err, &api) || api.Code != "INVALID_OTP" {
				t.Fatal(v.err)
			}
		}
	}
	if count != 1 || login.User.ID != old.User.ID || !login.User.EmailVerified {
		t.Fatal("memory proof was not single-use", count)
	}
	if _, _, err = s.Credential(ctx, email); !errors.Is(err, auth.ErrNotFound) {
		t.Fatal("unproven credential survived", err)
	}
	if _, _, err = s.Session(ctx, old.Token); !errors.Is(err, auth.ErrNotFound) {
		t.Fatal("unproven session survived", err)
	}
	code, err := first.CreateEmailOTP(ctx, email, emailotp.ResetPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err = other.ResetPasswordEmailOTP(ctx, email, code, "verified-password"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Session(ctx, login.Token); !errors.Is(err, auth.ErrNotFound) {
		t.Fatal("reset left original session live", err)
	}
	if _, err = other.SignInEmail(ctx, auth.SignInInput{Email: email, Password: "verified-password"}, auth.RequestMeta{}); err != nil {
		t.Fatal("reset failed to establish a credential", err)
	}
	code, err = first.CreateEmailOTP(ctx, email, emailotp.VerifyEmail)
	if err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 8)
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- []*auth.Auth{first, other}[i%2].CheckEmailOTP(ctx, email, "bad", emailotp.VerifyEmail)
		}()
	}
	wg.Wait()
	close(errs)
	exhausted := 0
	for err := range errs {
		var api *auth.APIError
		if !errors.As(err, &api) {
			t.Fatal("invalid memory result", err)
		}
		if api.Code == "TOO_MANY_ATTEMPTS" {
			exhausted++
		}
	}
	if exhausted != 1 {
		t.Fatalf("memory retry limit exhausted %d times", exhausted)
	}
	if _, err = other.VerifyEmailOTP(ctx, email, code); err == nil {
		t.Fatal("exhausted memory proof remained live")
	}
	req := auth.EmailOTPRequest{Email: email, Purpose: emailotp.VerifyEmail, Now: time.Now()}
	_, err = s.SaveEmailOTP(ctx, req, false, req.Now.Add(time.Minute), func(*auth.EmailOTPRecord) (string, string, int, error) { return "123", "123", 0, nil })
	if err != nil {
		t.Fatal(err)
	}
	if rec, err := s.ReadEmailOTP(ctx, auth.EmailOTPRequest{Email: email, Purpose: emailotp.VerifyEmail, Now: req.Now.Add(time.Minute)}); err != nil || rec != nil {
		t.Fatal("expired memory proof was readable", err)
	}
}
