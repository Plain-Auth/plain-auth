package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/plugins/bearer"
	"github.com/Stonewrit/stonewrit-auth/plugins/emailotp"
)

func TestEmailOTPAddressChangeAndTrustedOperations(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := filepath.Join(t.TempDir(), "addresses.db")
			if dialect != "sqlite" {
				dsn = os.Getenv("AUTH_TEST_" + strings.ToUpper(dialect) + "_DSN")
				if dsn == "" {
					t.Skip("requires disposable local database")
				}
			}
			s, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			other, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			const origin = "https://email-otp.example.test"
			var mu sync.Mutex
			var sent []emailotp.Message
			cfg := emailotp.Options{Send: func(_ context.Context, m emailotp.Message) error {
				mu.Lock()
				defer mu.Unlock()
				sent = append(sent, m)
				return nil
			}, ChangeEmail: emailotp.ChangeOptions{Enabled: true, VerifyCurrentEmail: true}, AutoSignInAfterVerification: true}
			makeAuth := func(s *Store, o emailotp.Options) *auth.Auth {
				t.Helper()
				p, err := emailotp.New(o)
				if err != nil {
					t.Fatal(err)
				}
				b := false
				a, err := auth.New(auth.Options{Store: s, Secret: "otp-extended-synthetic-test-secrets-0001", BaseURL: origin, EmailAndPassword: true, RateLimit: &b, Plugins: []auth.Plugin{p, bearer.New(bearer.Options{})}})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			first, second := makeAuth(s, cfg), makeAuth(other, cfg)
			email := strings.ToLower(rand.Text()) + "@example.test"
			malformed := cfg
			malformed.Encrypt = func(context.Context, string) (string, error) { return "", nil }
			if _, err := emailotp.New(malformed); err == nil {
				t.Fatal("accepted unpaired storage transforms")
			}
			failing := cfg
			failing.Send = func(context.Context, emailotp.Message) error { return errors.New("test sender unavailable") }
			if err := makeAuth(s, failing).SendEmailOTP(ctx, "sender-"+email, emailotp.SignIn); err == nil {
				t.Fatal("sender failure was hidden")
			}
			fallback := cfg
			fallback.GenerateOTP = func(context.Context, string, emailotp.Purpose) (string, error) { return "", nil }
			generated, err := makeAuth(s, fallback).CreateEmailOTP(ctx, "fallback-"+email, emailotp.VerifyEmail)
			if err != nil || len(generated) != 6 || strings.Trim(generated, "0123456789") != "" {
				t.Fatal("custom generator fallback did not generate six decimal digits", err)
			}
			unknown, err := first.ReadEmailOTP(ctx, email, emailotp.VerifyEmail)
			if err != nil || unknown != nil {
				t.Fatal("missing trusted proof must return nil", err)
			}
			code, err := first.CreateEmailOTP(ctx, email, emailotp.SignIn)
			if err != nil || code == "" || len(sent) != 0 {
				t.Fatal("trusted creation unexpectedly sent email", err)
			}
			read, err := second.ReadEmailOTP(ctx, email, emailotp.SignIn)
			if err != nil || read == nil || *read != code {
				t.Fatal("server-only read failed", err)
			}
			login, err := first.SignInEmailOTP(ctx, auth.EmailOTPSignInInput{Email: email, OTP: code}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			h := http.Header{"Authorization": {"Bearer " + login.Token}}
			otherEmail := "second-" + email
			code, err = first.CreateEmailOTP(ctx, otherEmail, emailotp.SignIn)
			if err != nil {
				t.Fatal(err)
			}
			otherLogin, err := first.SignInEmailOTP(ctx, auth.EmailOTPSignInInput{Email: otherEmail, OTP: code}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			foreign := http.Header{"Authorization": {"Bearer " + otherLogin.Token}}
			if err = first.RequestEmailChangeOTP(ctx, nil, "new-"+email, ""); err == nil {
				t.Fatal("anonymous address change succeeded")
			}
			if err = first.RequestEmailChangeOTP(ctx, h, "new-"+email, ""); err == nil {
				t.Fatal("missing current email proof succeeded")
			}
			if err = first.RequestEmailChangeOTP(ctx, h, email, ""); err == nil {
				t.Fatal("same address change succeeded")
			}
			current, err := first.CreateEmailOTP(ctx, email, emailotp.VerifyEmail)
			if err != nil {
				t.Fatal(err)
			}
			if err = second.RequestEmailChangeOTP(ctx, h, otherEmail, current); err != nil || len(sent) != 0 {
				t.Fatal("occupied destination disclosed or delivered", err)
			}
			if err = first.CheckEmailOTP(ctx, email, current, emailotp.VerifyEmail); err == nil {
				t.Fatal("occupied destination retained current proof")
			}
			current, err = first.CreateEmailOTP(ctx, email, emailotp.VerifyEmail)
			if err != nil {
				t.Fatal(err)
			}
			newEmail := "new-" + email
			var wg sync.WaitGroup
			out := make(chan error, 2)
			for _, a := range []*auth.Auth{first, second} {
				wg.Add(1)
				go func() { defer wg.Done(); out <- a.RequestEmailChangeOTP(ctx, h, newEmail, current) }()
			}
			wg.Wait()
			close(out)
			successes := 0
			for err := range out {
				if err == nil {
					successes++
				}
			}
			if successes != 1 || len(sent) != 1 || sent[0].Email != newEmail || sent[0].Type != emailotp.ChangeEmail {
				t.Fatalf("one current proof authorized %d changes or delivered the wrong destination", successes)
			}
			newCode := sent[0].OTP
			if err = second.ChangeEmailOTP(ctx, foreign, newEmail, newCode); err == nil {
				t.Fatal("another account consumed the change code")
			}
			if err = second.ChangeEmailOTP(ctx, h, newEmail, newCode); err != nil {
				t.Fatal("destination confirmation failed", err)
			}
			user, err := s.FindAccountUser(ctx, newEmail)
			if err != nil || user.ID != login.User.ID || !user.EmailVerified {
				t.Fatal("mailbox reassignment changed identity", err)
			}
			if _, err = s.FindAccountUser(ctx, email); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("old address still belongs to the account", err)
			}
			plain := cfg
			plain.ChangeEmail.VerifyCurrentEmail = false
			simple := makeAuth(s, plain)
			if err = simple.RequestEmailChangeOTP(ctx, h, "stale-"+email, ""); err != nil {
				t.Fatal(err)
			}
			pending := sent[len(sent)-1].OTP
			if err = simple.RequestEmailChangeOTP(ctx, h, "alternative-"+email, ""); err != nil {
				t.Fatal(err)
			}
			if err = simple.ChangeEmailOTP(ctx, h, "alternative-"+email, sent[len(sent)-1].OTP); err != nil {
				t.Fatal(err)
			}
			if err = simple.ChangeEmailOTP(ctx, h, "stale-"+email, pending); err == nil {
				t.Fatal("proof survived a change of source mailbox")
			}
			if err = simple.RequestEmailChangeOTP(ctx, h, "revoked-"+email, ""); err != nil {
				t.Fatal(err)
			}
			revoked := sent[len(sent)-1].OTP
			if err = s.DeleteSession(ctx, login.Token); err != nil {
				t.Fatal(err)
			}
			if err = simple.ChangeEmailOTP(ctx, h, "revoked-"+email, revoked); err == nil {
				t.Fatal("revoked session changed email")
			}
			cfg.Hash = func(_ context.Context, plain string) (string, error) {
				sum := sha256.Sum256([]byte("test-only:" + plain))
				return hex.EncodeToString(sum[:]), nil
			}
			hasher := makeAuth(s, cfg)
			code, err = hasher.CreateEmailOTP(ctx, otherEmail, emailotp.VerifyEmail)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = hasher.ReadEmailOTP(ctx, otherEmail, emailotp.VerifyEmail); err == nil {
				t.Fatal("server recovered a custom-hashed code")
			}
			res, err := hasher.CompleteEmailVerificationOTP(ctx, otherEmail, code, auth.RequestMeta{})
			if err != nil || res.Token == "" || res.User.ID != otherLogin.User.ID {
				t.Fatal("verification did not issue the configured session", err)
			}
			if _, _, err = s.Session(ctx, res.Token); err != nil {
				t.Fatal(err)
			}
			cfg.Hash = nil
			// Synthetic reversible codec exercises the callback contract.
			cfg.Encrypt = func(_ context.Context, input string) (string, error) {
				return base64.StdEncoding.EncodeToString([]byte(input)), nil
			}
			cfg.Decrypt = func(_ context.Context, input string) (string, error) {
				raw, err := base64.StdEncoding.DecodeString(input)
				return string(raw), err
			}
			cfg.ResendStrategy = "reuse"
			codec := makeAuth(s, cfg)
			if err = codec.SendEmailOTP(ctx, otherEmail, emailotp.VerifyEmail); err != nil {
				t.Fatal(err)
			}
			firstCode := sent[len(sent)-1].OTP
			if err = codec.SendEmailOTP(ctx, otherEmail, emailotp.VerifyEmail); err != nil {
				t.Fatal(err)
			}
			read, err = codec.ReadEmailOTP(ctx, otherEmail, emailotp.VerifyEmail)
			if err != nil || read == nil || *read != firstCode || sent[len(sent)-1].OTP != firstCode {
				t.Fatal("custom recoverable resend failed", err)
			}
			if _, err = s.db.ExecContext(ctx, s.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "identifier"=?`), s.date(time.Now().Add(-time.Minute)), "email-verification-otp-"+otherEmail); err != nil {
				t.Fatal(err)
			}
			if read, err = codec.ReadEmailOTP(ctx, otherEmail, emailotp.VerifyEmail); err != nil || read != nil {
				t.Fatal("trusted read returned an expired proof", err)
			}
			for _, endpoint := range []string{"create-verification-otp", "get-verification-otp"} {
				for _, method := range []string{"GET", "POST"} {
					w := httptest.NewRecorder()
					first.ServeHTTP(w, httptest.NewRequest(method, origin+"/api/auth/email-otp/"+endpoint, nil))
					if w.Code != 404 {
						t.Fatal("trusted accessor had an HTTP route", method, endpoint, w.Code)
					}
				}
			}
		})
	}
}
