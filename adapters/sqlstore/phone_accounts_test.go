package sqlstore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/client"
	"github.com/Stonewrit/stonewrit-auth/plugins/phonenumber"
	"github.com/Stonewrit/stonewrit-auth/plugins/twofactor"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

func TestPhoneAccounts(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			store, _ := phoneStores(t, dialect)
			srv := httptest.NewUnstartedServer(nil)
			number := "+12025550199"
			var msg phonenumber.Message
			var verified atomic.Int32
			deliver := func(_ context.Context, m phonenumber.Message) error { msg = m; return nil }
			p, err := phonenumber.New(phonenumber.Options{SendOTP: deliver, SendPasswordResetOTP: deliver, RequireVerification: true, SignUpOnVerification: &phonenumber.SignUpOptions{GetTempEmail: func(n string) string { return n[1:] + "@phone.test" }, GetTempName: func(string) string { return "Phone user" }}, OnVerification: func(_ context.Context, n string, u auth.User) error {
				if u.ID == "" || *u.PhoneNumber != n {
					t.Error("callback user mismatch")
				}
				verified.Add(1)
				return nil
			}})
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(err)
			off := false
			a, err := auth.New(auth.Options{Plugins: []auth.Plugin{p}, Store: store, BaseURL: "http://" + srv.Listener.Addr().String(), Secret: strings.Repeat("s", 48), RateLimit: &off, EmailAndPassword: true, RevokeSessionsOnPasswordReset: true})
			must(err)
			srv.Config.Handler = a
			srv.Start()
			defer srv.Close()
			browser, err := client.New(srv.URL, nil)
			must(err)
			other, err := client.New(srv.URL, nil)
			must(err)
			must(browser.RequestPhonePasswordReset(ctx, number))
			if msg.Code != "" {
				t.Fatal("reset SMS sent to an unknown number")
			}
			must(browser.SendPhoneNumberOTP(ctx, number))
			v := auth.PhoneVerificationInput{PhoneNumber: number, Code: msg.Code, DisableSession: true}
			unauthed := v
			unauthed.UpdatePhoneNumber = true
			_, err = browser.VerifyPhoneNumber(ctx, unauthed)
			if err == nil {
				t.Fatal("unauthenticated phone link allowed")
			}
			result, err := browser.VerifyPhoneNumber(ctx, v)
			must(err)
			if !result.Status || result.Token != nil || result.User.Name != "Phone user" || result.User.PhoneNumberFields == nil || *result.User.PhoneNumber != number || !*result.User.PhoneNumberVerified || result.User.EmailVerified {
				t.Fatalf("unexpected phone signup fields: %#v", result.User)
			}
			noSession, err := browser.GetSession(ctx)
			must(err)
			if noSession != nil {
				t.Fatal("disableSession issued a session")
			}
			initialID := result.User.ID
			_, err = browser.VerifyPhoneNumber(ctx, v)
			phoneError(t, err, 400, "OTP_NOT_FOUND")
			must(browser.SendPhoneNumberOTP(ctx, number))
			result, err = browser.VerifyPhoneNumber(ctx, auth.PhoneVerificationInput{PhoneNumber: number, Code: msg.Code})
			must(err)
			if result.Token == nil || result.User.ID != initialID {
				t.Fatal("returning verification session missing")
			}
			must(browser.RequestPhonePasswordReset(ctx, number))
			if msg.Purpose != auth.PhonePasswordReset {
				t.Fatal("recovery did not use its own delivery channel")
			}
			code := msg.Code
			phoneError(t, browser.ResetPhonePassword(ctx, number, "wrong", "correct-phrase-129"), 400, "INVALID_OTP")
			must(browser.ResetPhonePassword(ctx, number, code, "correct-phrase-129"))
			phoneError(t, browser.ResetPhonePassword(ctx, number, code, "correct-phrase-129"), 400, "OTP_NOT_FOUND")
			noSession, err = browser.GetSession(ctx)
			must(err)
			if noSession != nil {
				t.Fatal("reset failed to revoke original session")
			}
			_, err = browser.SignInPhoneNumber(ctx, client.PhoneSignInRequest{PhoneNumber: number, Password: "wrong-password"})
			phoneError(t, err, 401, "INVALID_PHONE_NUMBER_OR_PASSWORD")
			flag := false
			login, err := browser.SignInPhoneNumber(ctx, client.PhoneSignInRequest{PhoneNumber: number, Password: "correct-phrase-129", RememberMe: &flag})
			must(err)
			if login.Token == nil || login.User.ID != initialID {
				t.Fatal("phone login did not bind the reset credential")
			}
			_, err = other.SignUpEmail(ctx, client.SignUpRequest{Email: "another@example.test", Name: "Another", Password: "the-other-password"})
			must(err)
			must(other.SendPhoneNumberOTP(ctx, number))
			_, err = other.VerifyPhoneNumber(ctx, auth.PhoneVerificationInput{PhoneNumber: number, Code: msg.Code, UpdatePhoneNumber: true})
			phoneError(t, err, 400, "PHONE_NUMBER_EXIST")
			must(browser.RequestPhonePasswordReset(ctx, number))
			stale := msg.Code
			err = browser.Do(ctx, http.MethodPost, "/update-user", map[string]any{"phoneNumber": "+12025550201", "phoneNumberVerified": true}, nil)
			phoneError(t, err, 400, "PHONE_NUMBER_CANNOT_BE_UPDATED")
			barrier := &phoneCredentialBarrier{Store: store, AccountStore: store.(auth.AccountStore), PhoneAccountStore: store.(auth.PhoneAccountStore), read: make(chan struct{}), resume: make(chan struct{})}
			staleServer, err := auth.New(auth.Options{Store: barrier, BaseURL: srv.URL, Secret: strings.Repeat("s", 48), Plugins: []auth.Plugin{p}})
			must(err)
			pending := make(chan error, 1)
			go func() {
				_, err := staleServer.SignInPhoneNumber(ctx, number, "correct-phrase-129", auth.RequestMeta{})
				pending <- err
			}()
			<-barrier.read
			must(browser.Do(ctx, http.MethodPost, "/update-user", map[string]any{"phoneNumber": nil, "phoneNumberVerified": true}, nil))
			close(barrier.resume)
			phoneError(t, <-pending, 401, "INVALID_PHONE_NUMBER_OR_PASSWORD")
			s, err := browser.GetSession(ctx)
			must(err)
			if s.User.PhoneNumber != nil || s.User.PhoneNumberVerified == nil || *s.User.PhoneNumberVerified {
				t.Fatal("disassociation retained verified status")
			}
			must(other.SendPhoneNumberOTP(ctx, number))
			s, err = other.GetSession(ctx)
			must(err)
			linked, err := other.VerifyPhoneNumber(ctx, auth.PhoneVerificationInput{PhoneNumber: number, Code: msg.Code, UpdatePhoneNumber: true})
			must(err)
			if linked.Token == nil || *linked.Token != s.Session.Token || linked.User.ID != s.User.ID || *linked.User.PhoneNumber != number {
				t.Fatal("link did not preserve the owner's session")
			}
			phoneError(t, other.ResetPhonePassword(ctx, number, stale, "bad-replacement"), 400, "INVALID_OTP")
			_, err = browser.SignInPhoneNumber(ctx, client.PhoneSignInRequest{PhoneNumber: number, Password: "the-other-password"})
			must(err)
			if verified.Load() != 3 {
				t.Fatalf("callback called %d times", verified.Load())
			}
			err = other.Do(ctx, http.MethodPost, "/sign-up/email", map[string]any{"name": "Third", "email": "third@example.test", "password": "passphrase-320", "phoneNumber": "+12025550000", "phoneNumberVerified": true}, nil)
			phoneError(t, err, 400, "PHONE_NUMBER_CANNOT_BE_SET")
		})
	}
}

func TestPhoneExternalGeneration(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			s, peer := phoneStores(t, dialect)
			start, release := make(chan struct{}), make(chan struct{})
			limit := 1
			p, err := phonenumber.New(phonenumber.Options{AllowedAttempts: &limit, SendOTP: func(context.Context, phonenumber.Message) error { return nil }, VerifyOTP: func(ctx context.Context, m phonenumber.Message) (bool, error) {
				if m.Code == "old-generation" {
					close(start)
					select {
					case <-release:
					case <-ctx.Done():
						return false, ctx.Err()
					}
				}
				return true, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			makeAuth := func(s auth.Store) *auth.Auth {
				a, e := auth.New(auth.Options{Plugins: []auth.Plugin{p}, Store: s, BaseURL: "http://localhost:5521", Secret: strings.Repeat("s", 48)})
				if e != nil {
					t.Fatal(e)
				}
				return a
			}
			first, second := makeAuth(s), makeAuth(peer)
			ctx := t.Context()
			n := "+15550104"
			if err = first.SendPhoneNumberOTP(ctx, n); err != nil {
				t.Fatal(err)
			}
			completed := make(chan error, 1)
			go func() { completed <- first.ConsumePhoneNumberOTP(ctx, n, "old-generation") }()
			<-start
			err = second.SendPhoneNumberOTP(ctx, n)
			close(release)
			if err != nil {
				t.Fatal(err)
			}
			phoneError(t, <-completed, 400, "INVALID_OTP")
			if err = first.ConsumePhoneNumberOTP(ctx, n, "new-generation"); err != nil {
				t.Fatal("stale provider verdict spent the new issuance", err)
			}
			phoneError(t, second.ConsumePhoneNumberOTP(ctx, n, "new-generation"), 400, "OTP_NOT_FOUND")
			zero := 0
			p, err = phonenumber.New(phonenumber.Options{AllowedAttempts: &zero, SendOTP: func(context.Context, phonenumber.Message) error { return nil }})
			if err != nil {
				t.Fatal(err)
			}
			disabled := makeAuth(s)
			if err := disabled.SendPhoneNumberOTP(ctx, n); err != nil {
				t.Fatal(err)
			}
			phoneError(t, disabled.ConsumePhoneNumberOTP(ctx, n, "any"), 403, "TOO_MANY_ATTEMPTS")
		})
	}
}

type phoneCredentialBarrier struct {
	auth.Store
	auth.AccountStore
	auth.PhoneAccountStore
	read   chan struct{}
	resume chan struct{}
}

func (s *phoneCredentialBarrier) PhoneCredential(ctx context.Context, n string) (auth.User, string, error) {
	u, hash, err := s.PhoneAccountStore.PhoneCredential(ctx, n)
	close(s.read)
	select {
	case <-s.resume:
	case <-ctx.Done():
		return auth.User{}, "", ctx.Err()
	}
	return u, hash, err
}

func TestPhoneAccountPolicies(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"phone-number", "two-factor", "admin"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(err)
			defer store.Close()
			var msg phonenumber.Message
			send := func(_ context.Context, m phonenumber.Message) error { msg = m; return nil }
			phone, err := phonenumber.New(phonenumber.Options{SendOTP: send, SendPasswordResetOTP: send, RequireVerification: true})
			must(err)
			srv := httptest.NewUnstartedServer(nil)
			off := false
			admin, err := auth.NewAdmin(auth.AdminOptions{})
			must(err)
			opts := auth.Options{Store: store, BaseURL: "http://" + srv.Listener.Addr().String(), Secret: strings.Repeat("k", 48), EmailAndPassword: true, RateLimit: &off, Plugins: []auth.Plugin{phone, twofactor.New(twofactor.Options{SkipVerificationOnEnable: true}), admin}}
			a, err := auth.New(opts)
			must(err)
			srv.Config.Handler = a
			srv.Start()
			defer srv.Close()
			owner, err := client.New(srv.URL, nil)
			must(err)
			const pw = "phone-with-factor-pass"
			const n = "+12025550071"
			begin, err := owner.SignUpEmail(ctx, client.SignUpRequest{Email: "owner@example.test", Name: "Owner", Password: pw})
			must(err)
			// An imported, unverified number may request verification. Its reset response must mask eligibility.
			_, err = store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "phoneNumber"=?,"phoneNumberVerified"=? WHERE "id"=?`), n, false, begin.User.ID)
			must(err)
			must(owner.RequestPhonePasswordReset(ctx, n))
			if msg.Code != "" {
				t.Fatal("unverified reset leaked a delivery")
			}
			_, err = owner.SignInPhoneNumber(ctx, client.PhoneSignInRequest{PhoneNumber: n, Password: pw})
			phoneError(t, err, 401, "PHONE_NUMBER_NOT_VERIFIED")
			if msg.Code == "" || msg.Purpose != auth.PhoneVerify {
				t.Fatal("unverified sign-in failed to request proof")
			}
			_, err = owner.VerifyPhoneNumber(ctx, auth.PhoneVerificationInput{PhoneNumber: n, Code: msg.Code, DisableSession: true})
			must(err)
			enrollment, err := owner.EnableTOTP(ctx, pw, "Phone test")
			must(err)
			browser, err := client.New(srv.URL, nil)
			must(err)
			pwResult, err := browser.SignInPhoneNumber(ctx, client.PhoneSignInRequest{PhoneNumber: n, Password: pw})
			must(err)
			if !pwResult.TwoFactorRedirect || pwResult.Token != nil {
				t.Fatal("phone password sign-in bypassed MFA")
			}
			noSession, err := browser.GetSession(ctx)
			must(err)
			if noSession != nil {
				t.Fatal("factor challenge authenticated as session")
			}
			must(browser.SendPhoneNumberOTP(ctx, n))
			otpResult, err := browser.VerifyPhoneNumber(ctx, auth.PhoneVerificationInput{PhoneNumber: n, Code: msg.Code})
			must(err)
			if !otpResult.TwoFactorRedirect || otpResult.Token != nil {
				t.Fatal("phone proof sign-in bypassed MFA")
			}
			verified, err := browser.VerifyBackupCode(ctx, enrollment.BackupCodes[0], false)
			must(err)
			if verified.Token == nil || verified.User.ID != begin.User.ID {
				t.Fatal("phone challenge could not finish enrolled factor")
			}
			// A process started before migration must respect another process's enrollment, too.
			other, err := Open(ctx, dialect, dsn)
			must(err)
			defer other.Close()
			other.factorSchema = false
			opts.Store = other
			opts.Plugins = []auth.Plugin{phone}
			legacy, err := auth.New(opts)
			must(err)
			must(legacy.SendPhoneNumberOTP(ctx, n))
			_, err = legacy.VerifyPhoneNumber(ctx, nil, auth.PhoneVerificationInput{PhoneNumber: n, Code: msg.Code}, auth.RequestMeta{})
			phoneError(t, err, 403, "TWO_FACTOR_REQUIRED")
			_, err = store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "banned"=? WHERE "id"=?`), true, begin.User.ID)
			must(err)
			_, err = browser.SignInPhoneNumber(ctx, client.PhoneSignInRequest{PhoneNumber: n, Password: pw})
			phoneError(t, err, 403, "BANNED_USER")
			must(browser.SendPhoneNumberOTP(ctx, n))
			_, err = browser.VerifyPhoneNumber(ctx, auth.PhoneVerificationInput{PhoneNumber: n, Code: msg.Code})
			phoneError(t, err, 403, "BANNED_USER")
		})
	}
}
