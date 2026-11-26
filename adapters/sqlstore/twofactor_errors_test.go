package sqlstore

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/twofactor"
)

// Every two-factor error answers with its status, code and message from the
// error table, from the factor routes, sign-in and the Go calls.
func TestTwoFactorErrorCodesAcrossEngines(t *testing.T) {
	var mu sync.Mutex
	var sent twofactor.OTPMessage
	send := func(_ context.Context, m twofactor.OTPMessage) error {
		mu.Lock()
		defer mu.Unlock()
		sent = m
		return nil
	}
	lastCode := func() string {
		mu.Lock()
		defer mu.Unlock()
		return sent.Code
	}
	withFactorDatabases(t, twofactor.Options{OTP: twofactor.OTPOptions{AllowedAttempts: 1, Send: send}}, func(h *factorHarness) {
		t := h.t
		ctx := t.Context()
		const password = "private-fixture-credential"
		const lockedMessage = "Too many failed verification attempts. Your account is temporarily locked. Please try again later."
		noSend := h.instance(twofactor.Options{})
		totpOff := h.instance(twofactor.Options{TOTP: twofactor.TOTPOptions{Disabled: true}})
		plain := h.instance(twofactor.Options{Backup: twofactor.BackupOptions{Store: "plain"}})
		pw := map[string]string{"password": password}
		otp := map[string]string{"method": "otp", "password": password}
		guess := map[string]string{"code": "abcdef"}
		backup := map[string]string{"code": "abcde-fghij"}
		delivered := map[string]string{"code": "123456"}
		post := func(a *auth.Auth, path string, body any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
			t.Helper()
			data, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", "https://factor.example/api/auth/"+path, strings.NewReader(string(data)))
			r.Header.Set("Origin", "https://factor.example")
			r.Header.Set("Content-Type", "application/json")
			for _, c := range cookies {
				if c != nil {
					r.AddCookie(c)
				}
			}
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			return w
		}
		answer := func(w *httptest.ResponseRecorder, status int, code, message, marker string) {
			t.Helper()
			var got struct{ Code, Message string }
			if w.Code != status || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Code != code || got.Message != message {
				t.Fatalf("%s: %d %s", marker, w.Code, w.Body)
			}
		}
		refused := func(err error, status int, code, message, marker string) {
			t.Helper()
			var api *auth.APIError
			if !errors.As(err, &api) || api.Status != status || api.Code != code || api.Message != message {
				t.Fatalf("%s: %v", marker, err)
			}
		}
		signUp := func() (string, string, *http.Cookie) {
			t.Helper()
			email := strings.ToLower(rand.Text()) + "@example.test"
			reg, err := h.first.SignUpEmail(ctx, auth.SignUpInput{Email: email, Password: password, Name: "Mailbox"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			return reg.User.ID, email, h.first.SessionCookie(reg.Token, true)
		}
		signIn := func(a *auth.Auth, email string) *httptest.ResponseRecorder {
			return post(a, "sign-in/email", map[string]string{"email": email, "password": password})
		}
		exec := func(query string, args ...any) {
			t.Helper()
			if _, err := h.store.db.ExecContext(ctx, h.store.bind(query), args...); err != nil {
				t.Fatal(err)
			}
		}
		lock := func(userID string) {
			exec(`UPDATE "twoFactor" SET "lockedUntil"=? WHERE "userId"=?`, h.store.date(time.Now().Add(time.Hour)), userID)
		}

		// An account with no factor record.
		freshID, _, fresh := signUp()
		answer(post(h.first, "two-factor/send-otp", map[string]any{}, fresh), 400, "OTP_NOT_ENABLED", "OTP not enabled", "send-otp for an account without delivered codes did not answer OTP_NOT_ENABLED")
		answer(post(h.first, "two-factor/verify-otp", delivered, fresh), 400, "OTP_NOT_ENABLED", "OTP not enabled", "verify-otp for an account without delivered codes did not answer OTP_NOT_ENABLED")
		answer(post(noSend, "two-factor/enable", otp, fresh), 400, "OTP_NOT_CONFIGURED", "OTP is not available", "delivered-code enrollment without a sender did not answer OTP_NOT_CONFIGURED")
		answer(post(totpOff, "two-factor/enable", pw, fresh), 400, "TOTP_NOT_CONFIGURED", "TOTP is not available", "authenticator enrollment while disabled did not answer TOTP_NOT_CONFIGURED")
		answer(post(h.first, "two-factor/get-totp-uri", pw, fresh), 400, "TOTP_NOT_ENABLED", "TOTP not enabled", "get-totp-uri without a record did not answer TOTP_NOT_ENABLED")
		answer(post(h.first, "two-factor/verify-totp", guess, fresh), 400, "TOTP_NOT_ENABLED", "TOTP not enabled", "verify-totp without a record did not answer TOTP_NOT_ENABLED")
		answer(post(h.first, "two-factor/generate-backup-codes", pw, fresh), 400, "TWO_FACTOR_NOT_ENABLED", "Two factor isn't enabled", "generate-backup-codes without a record did not answer TWO_FACTOR_NOT_ENABLED")
		answer(post(h.first, "two-factor/verify-backup-code", backup, fresh), 400, "BACKUP_CODES_NOT_ENABLED", "Backup codes aren't enabled", "verify-backup-code without a record did not answer BACKUP_CODES_NOT_ENABLED")
		_, err := h.first.ViewBackupCodes(ctx, freshID)
		refused(err, 400, "BACKUP_CODES_NOT_ENABLED", "Backup codes aren't enabled", "ViewBackupCodes without a record did not answer BACKUP_CODES_NOT_ENABLED")
		_, err = h.first.ViewBackupCodes(ctx, "missing-account")
		refused(err, 400, "BACKUP_CODES_NOT_ENABLED", "Backup codes aren't enabled", "ViewBackupCodes for an unknown account did not answer BACKUP_CODES_NOT_ENABLED")

		// No session or challenge cookie.
		answer(post(noSend, "two-factor/send-otp", map[string]any{}), 400, "OTP_NOT_CONFIGURED", "otp isn't configured", "send-otp without a sender did not answer OTP_NOT_CONFIGURED before the challenge")
		answer(post(h.first, "two-factor/verify-totp", guess), 401, "INVALID_TWO_FACTOR_COOKIE", "Invalid two factor cookie", "a proof without a challenge did not answer INVALID_TWO_FACTOR_COOKIE")

		// An account enrolled with delivered codes alone.
		otpID, otpEmail, otpFirst := signUp()
		enabled := post(h.first, "two-factor/enable", otp, otpFirst)
		if enabled.Code != 200 {
			t.Fatal("delivered-code enrollment failed", enabled.Code, enabled.Body)
		}
		otpSession := h.cookie(enabled, "session_token")
		answer(post(h.first, "two-factor/get-totp-uri", pw, otpSession), 400, "TOTP_NOT_ENABLED", "TOTP not enabled", "get-totp-uri for a delivered-code account did not answer TOTP_NOT_ENABLED")
		answer(post(h.first, "two-factor/generate-backup-codes", pw, otpSession), 400, "TWO_FACTOR_NOT_ENABLED", "Two factor isn't enabled", "generate-backup-codes for a delivered-code account did not answer TWO_FACTOR_NOT_ENABLED")
		otpChallenge := h.cookie(signIn(h.first, otpEmail), "two_factor")
		answer(post(h.first, "two-factor/verify-totp", guess, otpChallenge), 400, "TOTP_NOT_ENABLED", "TOTP not enabled", "verify-totp for a delivered-code sign-in did not answer TOTP_NOT_ENABLED")
		answer(post(h.first, "two-factor/verify-backup-code", backup, otpChallenge), 400, "BACKUP_CODES_NOT_ENABLED", "Backup codes aren't enabled", "verify-backup-code for a delivered-code sign-in did not answer BACKUP_CODES_NOT_ENABLED")
		answer(signIn(noSend, otpEmail), 400, "TOTP_NOT_CONFIGURED", "TOTP is not available", "a sign-in with no usable factor did not answer TOTP_NOT_CONFIGURED")
		lock(otpID)
		answer(post(h.first, "two-factor/verify-backup-code", backup, otpChallenge), 400, "BACKUP_CODES_NOT_ENABLED", "Backup codes aren't enabled", "a locked delivered-code sign-in's backup code was refused by the lock before BACKUP_CODES_NOT_ENABLED")
		answer(post(h.first, "two-factor/verify-totp", guess, otpChallenge), 400, "TOTP_NOT_ENABLED", "TOTP not enabled", "a locked delivered-code sign-in's authenticator code was refused by the lock before TOTP_NOT_ENABLED")
		answer(post(h.first, "two-factor/verify-otp", delivered, otpChallenge), 429, "ACCOUNT_TEMPORARILY_LOCKED", lockedMessage, "a locked delivered-code sign-in's delivered code did not answer ACCOUNT_TEMPORARILY_LOCKED")

		// A delivered-code account upgrading to an authenticator.
		_, upEmail, upFirst := signUp()
		enabled = post(h.first, "two-factor/enable", otp, upFirst)
		if enabled.Code != 200 {
			t.Fatal("delivered-code enrollment failed", enabled.Code, enabled.Body)
		}
		upSession := h.cookie(enabled, "session_token")
		var upgrade struct{ BackupCodes []string }
		if w := post(h.first, "two-factor/enable", pw, upSession); w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &upgrade) != nil || len(upgrade.BackupCodes) == 0 {
			t.Fatal("an authenticator upgrade returned no backup codes", w.Code, w.Body)
		}
		upChallenge := h.cookie(signIn(h.first, upEmail), "two_factor")
		answer(post(h.first, "two-factor/verify-totp", guess, upChallenge), 400, "TOTP_NOT_ENABLED", "TOTP not enabled", "verify-totp for an unconfirmed authenticator during sign-in did not answer TOTP_NOT_ENABLED")
		answer(post(h.first, "two-factor/verify-backup-code", map[string]string{"code": upgrade.BackupCodes[0]}, upChallenge), 400, "BACKUP_CODES_NOT_ENABLED", "Backup codes aren't enabled", "an unconfirmed enrollment's backup code during sign-in did not answer BACKUP_CODES_NOT_ENABLED")
		var regenerated struct{ BackupCodes []string }
		if w := post(h.first, "two-factor/generate-backup-codes", pw, upSession); w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &regenerated) != nil || len(regenerated.BackupCodes) != 10 {
			t.Fatal("generate-backup-codes for an enabled account awaiting authenticator confirmation was refused", w.Code, w.Body)
		}

		// An authenticator enrollment that was never confirmed.
		_, _, unconfirmed := signUp()
		var started struct{ BackupCodes []string }
		if w := post(h.first, "two-factor/enable", pw, unconfirmed); w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &started) != nil || len(started.BackupCodes) == 0 {
			t.Fatal("an authenticator enrollment returned no backup codes", w.Code, w.Body)
		}
		answer(post(h.first, "two-factor/generate-backup-codes", pw, unconfirmed), 400, "TWO_FACTOR_NOT_ENABLED", "Two factor isn't enabled", "generate-backup-codes before the authenticator was confirmed did not answer TWO_FACTOR_NOT_ENABLED")
		answer(post(h.first, "two-factor/verify-backup-code", map[string]string{"code": started.BackupCodes[0]}, unconfirmed), 400, "BACKUP_CODES_NOT_ENABLED", "Backup codes aren't enabled", "an unconfirmed enrollment's backup code from a session did not answer BACKUP_CODES_NOT_ENABLED")

		// An enrolled authenticator.
		owner := h.enroll()
		answer(post(h.first, "two-factor/enable", pw, owner.session), 400, "TOTP_ALREADY_ENABLED", "TOTP is already enabled", "enable for a confirmed authenticator did not answer TOTP_ALREADY_ENABLED")
		answer(post(totpOff, "two-factor/get-totp-uri", pw, owner.session), 400, "TOTP_NOT_CONFIGURED", "totp isn't configured", "get-totp-uri while disabled did not answer TOTP_NOT_CONFIGURED")
		_, err = totpOff.GenerateTOTP("raw-secret")
		refused(err, 400, "TOTP_NOT_CONFIGURED", "totp isn't configured", "GenerateTOTP while disabled did not answer TOTP_NOT_CONFIGURED")
		answer(post(h.first, "two-factor/generate-backup-codes", map[string]string{"password": "not-the-credential"}, owner.session), 400, "INVALID_PASSWORD", "Invalid password", "generate-backup-codes with a wrong password did not answer INVALID_PASSWORD")
		proofs := h.challenge(h.first, owner)
		answer(post(totpOff, "two-factor/verify-totp", guess, proofs), 400, "TOTP_NOT_CONFIGURED", "totp isn't configured", "verify-totp while disabled did not answer TOTP_NOT_CONFIGURED")
		answer(post(h.first, "two-factor/verify-backup-code", map[string]string{"code": "wrong-code"}, proofs), 401, "INVALID_BACKUP_CODE", "Invalid backup code", "a wrong backup code did not answer INVALID_BACKUP_CODE")
		answer(post(h.first, "two-factor/verify-totp", guess, proofs), 401, "INVALID_CODE", "Invalid code", "a wrong authenticator code did not answer INVALID_CODE")
		answer(post(h.first, "two-factor/verify-otp", delivered, proofs), 400, "OTP_HAS_EXPIRED", "OTP has expired", "verify-otp before any code was sent did not answer OTP_HAS_EXPIRED")
		answer(post(noSend, "two-factor/verify-otp", delivered, proofs), 400, "OTP_HAS_EXPIRED", "OTP has expired", "verify-otp without a sender did not answer OTP_HAS_EXPIRED")
		codes := h.challenge(h.first, owner)
		h.request(h.first, "two-factor/send-otp", map[string]any{}, 200, codes)
		answer(post(h.first, "two-factor/verify-otp", map[string]string{"code": "x"}, codes), 401, "INVALID_CODE", "Invalid code", "a wrong delivered code did not answer INVALID_CODE")
		answer(post(h.first, "two-factor/verify-otp", map[string]string{"code": lastCode()}, codes), 400, "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE", "Too many attempts. Please request a new code.", "a delivered code past its attempts did not answer TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE")

		// The fifth failed proof ends the challenge.
		capped := h.enroll()
		spent := h.challenge(h.first, capped)
		for range 5 {
			post(h.first, "two-factor/verify-totp", guess, spent)
		}
		answer(post(h.first, "two-factor/verify-totp", guess, spent), 401, "INVALID_TWO_FACTOR_COOKIE", "Invalid two factor cookie", "the proof after five failures did not answer INVALID_TWO_FACTOR_COOKIE")

		// A locked account.
		held := h.enroll()
		heldChallenge := h.challenge(h.first, held)
		lock(held.userID)
		answer(post(h.first, "two-factor/verify-totp", guess, heldChallenge), 429, "ACCOUNT_TEMPORARILY_LOCKED", lockedMessage, "a locked account's sign-in proof did not answer ACCOUNT_TEMPORARILY_LOCKED")
		answer(post(h.first, "two-factor/verify-totp", guess, held.session), 429, "ACCOUNT_TEMPORARILY_LOCKED", lockedMessage, "a locked account's signed-in proof did not answer ACCOUNT_TEMPORARILY_LOCKED")
		answer(post(h.first, "two-factor/send-otp", map[string]any{}, heldChallenge), 429, "ACCOUNT_TEMPORARILY_LOCKED", lockedMessage, "a locked account's code request did not answer ACCOUNT_TEMPORARILY_LOCKED")

		// An account enrolled by the user flag alone.
		flagID, flagEmail, flagSession := signUp()
		exec(`UPDATE "user" SET "twoFactorEnabled"=? WHERE "id"=?`, true, flagID)
		flagChallenge := h.cookie(signIn(h.first, flagEmail), "two_factor")
		answer(post(h.first, "two-factor/verify-otp", delivered, flagChallenge), 400, "OTP_HAS_EXPIRED", "OTP has expired", "verify-otp for a flag-only account did not answer OTP_HAS_EXPIRED")
		off := post(h.first, "two-factor/disable", pw, flagSession)
		if after := signIn(h.first, flagEmail); off.Code != 200 || after.Code != 200 || strings.Contains(after.Body.String(), "twoFactorRedirect") {
			t.Fatal("a flag-only account could not turn its second factor off", off.Code, off.Body, after.Body)
		}

		// Stored codes that are not a JSON list once read.
		unreadable := h.enroll()
		exec(`UPDATE "twoFactor" SET "backupCodes"=? WHERE "userId"=?`, "not-json", unreadable.userID)
		_, err = plain.ViewBackupCodes(ctx, unreadable.userID)
		refused(err, 400, "INVALID_BACKUP_CODE", "Invalid backup code", "ViewBackupCodes for unreadable codes did not answer INVALID_BACKUP_CODE")
		answer(post(plain, "two-factor/verify-backup-code", backup, unreadable.session), 401, "INVALID_BACKUP_CODE", "Invalid backup code", "verify-backup-code against unreadable codes did not answer INVALID_BACKUP_CODE")
	})
}
