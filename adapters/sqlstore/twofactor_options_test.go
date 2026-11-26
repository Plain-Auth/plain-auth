package sqlstore

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/twofactor"
	"github.com/pquerna/otp/totp"
)

// instance opens one more server on the harness's database with other
// two-factor options.
func (h *factorHarness) instance(opts twofactor.Options) *auth.Auth {
	h.t.Helper()
	off := false
	a, err := auth.New(auth.Options{Store: h.store, BaseURL: "https://factor.example", Secret: "synthetic-factor-secret-0001-0123456789", EmailAndPassword: true, RateLimit: &off, Plugins: []auth.Plugin{twofactor.New(opts)}})
	if err != nil {
		h.t.Fatal(err)
	}
	return a
}

// passwordless adds a verified account without a credential password and
// returns its ID and a signed-in session cookie.
func (h *factorHarness) passwordless() (string, *http.Cookie) {
	h.t.Helper()
	ctx := h.t.Context()
	id := rand.Text()
	now := time.Now().UTC().Truncate(time.Millisecond)
	if _, err := h.store.db.ExecContext(ctx, h.store.bind(`INSERT INTO "user" ("id","email","name","emailVerified","createdAt","updatedAt") VALUES (?,?,?,true,?,?)`), id, strings.ToLower(id)+"@passwordless.test", "Mailbox", h.store.date(now), h.store.date(now)); err != nil {
		h.t.Fatal(err)
	}
	session := auth.StoredSession{Session: auth.Session{ID: rand.Text(), Token: rand.Text(), UserID: id, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
	if err := h.store.CreateSession(ctx, session); err != nil {
		h.t.Fatal(err)
	}
	return id, h.first.SessionCookie(session.Token, true)
}

// answer posts body, requires the status and, when code is set, the error
// code of the JSON answer.
func (h *factorHarness) answer(a *auth.Auth, path string, body any, status int, code string, cookies ...*http.Cookie) {
	h.t.Helper()
	w := h.request(a, path, body, status, cookies...)
	var got struct{ Code string }
	if code != "" && (json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Code != code) {
		h.t.Fatalf("%s answered %s, want %s", path, w.Body, code)
	}
}

// Under a passwordless switch, an account without a password manages its
// factors without one, an account with a password must still send it, and a
// sent password must be a string; without a switch the password is
// required.
func TestFactorManagementPasswords(t *testing.T) {
	on, off := true, false
	withFactorDatabases(t, twofactor.Options{AllowPasswordless: true}, func(h *factorHarness) {
		t := h.t
		wide := h.first
		narrowed := h.instance(twofactor.Options{AllowPasswordless: true, TOTP: twofactor.TOTPOptions{AllowPasswordless: &off}, Backup: twofactor.BackupOptions{AllowPasswordless: &off}})
		widened := h.instance(twofactor.Options{TOTP: twofactor.TOTPOptions{AllowPasswordless: &on}, Backup: twofactor.BackupOptions{AllowPasswordless: &on}})
		strict := h.instance(twofactor.Options{})
		none := map[string]any{}
		wrong := map[string]any{"password": "not-the-credential"}

		id, session := h.passwordless()
		enabled := h.request(wide, "two-factor/enable", none, 200, session)
		var setup struct{ TOTPURI string }
		if err := json.Unmarshal(enabled.Body.Bytes(), &setup); err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(setup.TOTPURI)
		if err != nil {
			t.Fatal(err)
		}
		code, err := totp.GenerateCode(u.Query().Get("secret"), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		session = h.cookie(h.request(h.second, "two-factor/verify-totp", map[string]any{"code": code}, 200, session), "session_token")

		// Under the plugin-wide switch a passwordless account reads its URI and replaces its backup codes without a password.
		uri := h.request(wide, "two-factor/get-totp-uri", none, 200, session)
		var codes struct{ BackupCodes []string }
		backups := h.request(wide, "two-factor/generate-backup-codes", none, 200, session)
		if !strings.Contains(uri.Body.String(), u.Query().Get("secret")) || json.Unmarshal(backups.Body.Bytes(), &codes) != nil || len(codes.BackupCodes) != 10 {
			t.Fatal("passwordless management without a password failed", uri.Body, backups.Body)
		}
		// Each method's own switch overrides the plugin-wide one, in both directions.
		h.answer(narrowed, "two-factor/get-totp-uri", none, 400, "VALIDATION_ERROR", session)
		h.answer(narrowed, "two-factor/get-totp-uri", wrong, 400, "INVALID_PASSWORD", session)
		h.answer(narrowed, "two-factor/generate-backup-codes", none, 400, "VALIDATION_ERROR", session)
		h.answer(widened, "two-factor/get-totp-uri", none, 200, "", session)
		h.answer(widened, "two-factor/get-totp-uri", wrong, 200, "", session)
		h.answer(widened, "two-factor/generate-backup-codes", none, 200, "", session)
		h.answer(widened, "two-factor/disable", none, 400, "VALIDATION_ERROR", session)
		// A password that is sent must be a string, even where it is not needed.
		h.answer(wide, "two-factor/get-totp-uri", map[string]any{"password": nil}, 400, "VALIDATION_ERROR", session)
		h.answer(widened, "two-factor/get-totp-uri", map[string]any{"password": 5}, 400, "VALIDATION_ERROR", session)
		h.answer(wide, "two-factor/generate-backup-codes", map[string]any{"password": 5}, 400, "VALIDATION_ERROR", session)
		h.answer(wide, "two-factor/disable", map[string]any{"password": 5}, 400, "VALIDATION_ERROR", session)

		owner := h.enroll()
		// An account with a password must still send it: left out or wrong, it is refused as INVALID_PASSWORD.
		for _, a := range []*auth.Auth{wide, widened} {
			for _, path := range []string{"two-factor/get-totp-uri", "two-factor/generate-backup-codes"} {
				h.answer(a, path, none, 400, "INVALID_PASSWORD", owner.session)
				h.answer(a, path, wrong, 400, "INVALID_PASSWORD", owner.session)
			}
		}
		for _, path := range []string{"two-factor/enable", "two-factor/disable"} {
			h.answer(wide, path, none, 400, "INVALID_PASSWORD", owner.session)
			h.answer(wide, path, wrong, 400, "INVALID_PASSWORD", owner.session)
		}
		h.answer(wide, "two-factor/get-totp-uri", map[string]any{"password": nil}, 400, "VALIDATION_ERROR", owner.session)
		h.answer(widened, "two-factor/generate-backup-codes", map[string]any{"password": owner.input.Password}, 200, "", owner.session)
		// Without a passwordless switch the password is a required string field.
		for _, path := range []string{"two-factor/get-totp-uri", "two-factor/generate-backup-codes"} {
			h.answer(strict, path, none, 400, "VALIDATION_ERROR", owner.session)
			h.answer(strict, path, wrong, 400, "INVALID_PASSWORD", owner.session)
		}
		h.answer(strict, "two-factor/get-totp-uri", map[string]any{"password": owner.input.Password}, 200, "", owner.session)

		// The plugin-wide switch also lets the passwordless account disable its factor without a password.
		h.answer(wide, "two-factor/disable", none, 200, "", session)
		var left int
		if err := h.store.db.QueryRowContext(t.Context(), h.store.bind(`SELECT count(*) FROM "twoFactor" WHERE "userId"=?`), id).Scan(&left); err != nil || left != 0 {
			t.Fatal("passwordless disable kept the factor", left, err)
		}
	})
}

// challenge signs u in with its password on a and returns the challenge
// cookie.
func (h *factorHarness) challenge(a *auth.Auth, u enrolledAccount) *http.Cookie {
	h.t.Helper()
	return h.cookie(h.request(a, "sign-in/email", map[string]string{"email": u.input.Email, "password": u.input.Password}, 200), "two_factor")
}

// lifetime reads how long the verification row stored under identifier
// lives.
func (h *factorHarness) lifetime(identifier string) time.Duration {
	h.t.Helper()
	var created, expires time.Time
	if err := h.store.db.QueryRowContext(h.t.Context(), h.store.bind(`SELECT "createdAt","expiresAt" FROM "verification" WHERE "identifier"=?`), identifier).Scan(&created, &expires); err != nil {
		h.t.Fatal(err)
	}
	return expires.Sub(created)
}

// Without options, backup codes are five characters, a hyphen and five more;
// a delivered code is six digits; a challenge lasts ten minutes; and a
// remembered browser lasts thirty days, renewed at each trusted sign-in.
func TestTwoFactorDefaults(t *testing.T) {
	var mu sync.Mutex
	var delivered []twofactor.OTPMessage
	capture := func(_ context.Context, m twofactor.OTPMessage) error {
		mu.Lock()
		defer mu.Unlock()
		delivered = append(delivered, m)
		return nil
	}
	withFactorDatabases(t, twofactor.Options{OTP: twofactor.OTPOptions{Send: capture}}, func(h *factorHarness) {
		t := h.t
		mu.Lock()
		delivered = nil
		mu.Unlock()
		owner := h.enroll()
		for _, c := range owner.backups {
			if len(c) != 11 || c[5] != '-' || strings.Trim(c[:5]+c[6:], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != "" {
				t.Fatalf("default backup code %q is not five characters, a hyphen and five more", c)
			}
		}
		challenge := h.challenge(h.first, owner)
		if life := h.lifetime(h.first.VerifySignedSessionToken(challenge.Value)); challenge.MaxAge != 600 || life != 10*time.Minute {
			t.Fatal("default challenge does not last ten minutes in the cookie and the store", challenge.MaxAge, life)
		}
		h.answer(h.first, "two-factor/send-otp", map[string]any{"trustDevice": "yes"}, 400, "VALIDATION_ERROR")
		h.answer(h.first, "two-factor/send-otp", map[string]any{"trustDevice": "yes"}, 400, "VALIDATION_ERROR", challenge)
		mu.Lock()
		refused := len(delivered)
		mu.Unlock()
		if refused != 0 {
			t.Fatal("a refused send-otp delivered a code")
		}
		sentReply := h.request(h.second, "two-factor/send-otp", map[string]any{"trustDevice": true}, 200, challenge)
		mu.Lock()
		sent := delivered
		mu.Unlock()
		if len(sent) != 1 || len(sent[0].Code) != 6 || strings.Trim(sent[0].Code, "0123456789") != "" {
			t.Fatal("default delivered code is not six decimal digits", sent)
		}
		delivered := h.request(h.first, "two-factor/verify-otp", map[string]any{"code": sent[0].Code}, 200, challenge)
		h.cookie(delivered, "session_token")
		// setsCookie reports whether w sets, rather than expires, the named cookie.
		setsCookie := func(w *httptest.ResponseRecorder, name string) bool {
			for _, c := range w.Result().Cookies() {
				if strings.HasSuffix(c.Name, "."+name) && c.MaxAge >= 0 {
					return true
				}
			}
			return false
		}
		if setsCookie(sentReply, "trust_device") || setsCookie(delivered, "trust_device") {
			t.Fatal("trustDevice on send-otp remembered the browser")
		}

		login := h.request(h.first, "sign-in/email", map[string]any{"email": owner.input.Email, "password": owner.input.Password, "rememberMe": false}, 200)
		challenge, marker := h.cookie(login, "two_factor"), h.cookie(login, "dont_remember")
		code, err := totp.GenerateCode(owner.secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		h.answer(h.second, "two-factor/verify-totp", map[string]any{"code": code, "trustDevice": "yes"}, 400, "VALIDATION_ERROR", challenge, marker)
		proved := h.request(h.second, "two-factor/verify-totp", map[string]any{"code": code, "trustDevice": true}, 200, challenge, marker)
		cleared := false
		for _, c := range proved.Result().Cookies() {
			cleared = cleared || strings.HasSuffix(c.Name, ".dont_remember") && c.MaxAge < 0
		}
		if !cleared {
			t.Fatal("trustDevice kept the don't-remember marker")
		}
		trust := h.cookie(proved, "trust_device")
		grant := strings.TrimPrefix(h.first.VerifySignedSessionToken(trust.Value), h.first.TrustedDeviceCookieName()+"|"+owner.userID+"|")
		if life := h.lifetime(grant); trust.MaxAge != 30*24*60*60 || life != 30*24*time.Hour {
			t.Fatal("default remembered browser does not last thirty days in the cookie and the store", trust.MaxAge, life)
		}
		again := h.request(h.first, "sign-in/email", map[string]string{"email": owner.input.Email, "password": owner.input.Password}, 200, trust)
		if strings.Contains(again.Body.String(), "twoFactorRedirect") || h.cookie(again, "trust_device").MaxAge != 30*24*60*60 {
			t.Fatal("the remembered browser did not skip the challenge and renew for thirty days", again.Body)
		}
	})
}

// With authenticators disabled, enrollment, URI reads and sign-in codes
// answer TOTP_NOT_CONFIGURED without comparing or counting a code, sign-in
// offers no authenticator, and backup codes still work.
func TestDisabledAuthenticator(t *testing.T) {
	withFactorDatabases(t, twofactor.Options{}, func(h *factorHarness) {
		t := h.t
		ctx := t.Context()
		owner := h.enroll()
		off := h.instance(twofactor.Options{TOTP: twofactor.TOTPOptions{Disabled: true}})
		const password = "private-fixture-credential"
		fresh, err := h.first.SignUpEmail(ctx, auth.SignUpInput{Email: strings.ToLower(rand.Text()) + "@example.test", Password: password, Name: "Fresh"}, auth.RequestMeta{})
		if err != nil {
			t.Fatal(err)
		}
		h.answer(off, "two-factor/enable", map[string]any{"password": password}, 400, "TOTP_NOT_CONFIGURED", h.first.SessionCookie(fresh.Token, true))
		h.answer(off, "two-factor/get-totp-uri", map[string]any{"password": owner.input.Password}, 400, "TOTP_NOT_CONFIGURED", owner.session)
		login := h.request(off, "sign-in/email", map[string]string{"email": owner.input.Email, "password": owner.input.Password}, 200)
		if !strings.Contains(login.Body.String(), `"twoFactorMethods":[]`) || !strings.Contains(login.Body.String(), `"twoFactorRedirect":true`) {
			t.Fatal("sign-in offered totp after authenticators were disabled", login.Body)
		}
		challenge := h.cookie(login, "two_factor")
		for _, at := range []time.Time{time.Now().Add(5 * time.Minute), time.Now()} {
			code, err := totp.GenerateCode(owner.secret, at)
			if err != nil {
				t.Fatal(err)
			}
			h.answer(off, "two-factor/verify-totp", map[string]any{"code": code}, 400, "TOTP_NOT_CONFIGURED", challenge)
		}
		var attempts string
		var failures int
		if err := h.store.db.QueryRowContext(ctx, h.store.bind(`SELECT "value" FROM "verification" WHERE "identifier"=?`), "2fa-attempts-"+h.first.VerifySignedSessionToken(challenge.Value)).Scan(&attempts); err != nil {
			t.Fatal(err)
		}
		if err := h.store.db.QueryRowContext(ctx, h.store.bind(`SELECT "failedVerificationCount" FROM "twoFactor" WHERE "userId"=?`), owner.userID).Scan(&failures); err != nil || attempts != "0" || failures != 0 {
			t.Fatal("a disabled authenticator counted the proof", attempts, failures, err)
		}
		h.cookie(h.request(off, "two-factor/verify-backup-code", map[string]any{"code": owner.backups[0]}, 200, challenge), "session_token")
	})
}

// midStep waits, when fewer than five seconds of the current authenticator
// period remain, for the next period, so a code drawn for a neighbouring
// period is still a neighbour when the server compares it.
func midStep(period time.Duration) time.Time {
	if left := period - time.Duration(time.Now().UnixNano())%period; left < 5*time.Second {
		time.Sleep(left)
	}
	return time.Now()
}

// A sign-in accepts a code from the period before or after the current
// one, refuses codes two periods away, and then refuses a code from a period
// earlier than the last one accepted.
func TestAuthenticatorStepWindow(t *testing.T) {
	withFactorDatabases(t, twofactor.Options{}, func(h *factorHarness) {
		t := h.t
		owner := h.enroll()
		challenge := h.challenge(h.first, owner)
		at := midStep(30 * time.Second)
		codeAt := func(offset time.Duration) map[string]any {
			code, err := totp.GenerateCode(owner.secret, at.Add(offset))
			if err != nil {
				t.Fatal(err)
			}
			return map[string]any{"code": code}
		}
		// Codes two periods away are refused.
		h.answer(h.second, "two-factor/verify-totp", codeAt(-60*time.Second), 401, "INVALID_CODE", challenge)
		h.answer(h.second, "two-factor/verify-totp", codeAt(60*time.Second), 401, "INVALID_CODE", challenge)
		h.cookie(h.request(h.second, "two-factor/verify-totp", codeAt(-30*time.Second), 200, challenge), "session_token")
		h.cookie(h.request(h.first, "two-factor/verify-totp", codeAt(30*time.Second), 200, h.challenge(h.second, owner)), "session_token")
		// A code from an earlier period than the last accepted one is refused.
		h.answer(h.second, "two-factor/verify-totp", codeAt(0), 401, "INVALID_CODE", h.challenge(h.first, owner))
	})
}
