package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/twofactor"
)

func TestDeliveredSecondFactor(t *testing.T) {
	var delivered twofactor.OTPMessage
	opts := twofactor.Options{OTP: twofactor.OTPOptions{Period: 2 * time.Minute, Digits: 8, AllowedAttempts: 2, Store: "hashed", Send: func(_ context.Context, m twofactor.OTPMessage) error { delivered = m; return nil }}}
	withFactorDatabases(t, opts, func(h *factorHarness) {
		t := h.t
		ctx := t.Context()
		email := strings.ToLower(rand.Text()) + "@example.test"
		const password = "factor-test-credential"
		reg, err := h.first.SignUpEmail(ctx, auth.SignUpInput{Email: email, Password: password, Name: "Owner"}, auth.RequestMeta{})
		if err != nil {
			t.Fatal(err)
		}
		source := h.first.SessionCookie(reg.Token, true)
		h.request(h.first, "two-factor/send-otp", map[string]any{}, 400, source)
		h.request(h.first, "two-factor/enable", map[string]string{"method": "otp", "password": "wrong"}, 400, source)
		enabled := h.request(h.first, "two-factor/enable", map[string]string{"method": "otp", "password": password}, 200, source)
		if !strings.Contains(enabled.Body.String(), `"method":"otp"`) {
			t.Fatal("delivery enrollment returned wrong method")
		}
		current := h.cookie(enabled, "session_token")
		start := func() *http.Cookie {
			t.Helper()
			w := h.request(h.first, "sign-in/email", map[string]string{"email": email, "password": password}, 200)
			var v struct {
				TwoFactorMethods  []string
				TwoFactorRedirect bool
				Token             string
			}
			if err = json.Unmarshal(w.Body.Bytes(), &v); err != nil {
				t.Fatal(err)
			}
			if !v.TwoFactorRedirect || len(v.TwoFactorMethods) != 1 || v.TwoFactorMethods[0] != "otp" || v.Token != "" {
				t.Fatal("password login bypassed the delivered factor gate", v)
			}
			return h.cookie(w, "two_factor")
		}
		challenge := start()
		send := func(a *auth.Auth, c *http.Cookie) string {
			t.Helper()
			w := h.request(a, "two-factor/send-otp", map[string]any{}, 200, c)
			if delivered.User.ID != reg.User.ID || len(delivered.Code) != 8 || strings.Trim(delivered.Code, "0123456789") != "" || strings.Contains(w.Body.String(), delivered.Code) {
				t.Fatal("factor delivery exposed proof or addressed another user")
			}
			return delivered.Code
		}
		code := send(h.first, challenge)
		var stored string
		var created, expires time.Time
		key := "2fa-otp-" + h.first.VerifySignedSessionToken(challenge.Value)
		if err = h.store.db.QueryRowContext(ctx, h.store.bind(`SELECT "value","createdAt","expiresAt" FROM "verification" WHERE "identifier"=?`), key).Scan(&stored, &created, &expires); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(code))
		// Generated delivery and creation times may lose database sub-millisecond precision.
		if stored != base64.RawURLEncoding.EncodeToString(sum[:])+":0" || expires.Sub(created) != 2*time.Minute {
			t.Fatal("stored delivered OTP or expiry differs from configuration")
		}
		isolated := start()
		h.request(h.second, "two-factor/verify-otp", map[string]string{"code": code}, 400, isolated)
		for range 2 {
			h.request(h.second, "two-factor/verify-otp", map[string]string{"code": "wrong"}, 401, challenge)
		}
		capped := h.request(h.second, "two-factor/verify-otp", map[string]string{"code": code}, 400, challenge)
		if !strings.Contains(capped.Body.String(), "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE") {
			t.Fatal("delivery-specific attempt limit failed")
		}
		code = send(h.second, challenge)
		if _, err = h.store.db.ExecContext(ctx, h.store.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "identifier"=?`), h.store.date(time.Now().Add(-time.Minute)), key); err != nil {
			t.Fatal(err)
		}
		if w := h.request(h.first, "two-factor/verify-otp", map[string]string{"code": code}, 400, challenge); !strings.Contains(w.Body.String(), "OTP_HAS_EXPIRED") {
			t.Fatal("expired delivered factor accepted")
		}
		code = send(h.first, challenge)
		var wg sync.WaitGroup
		results := make(chan *httptest.ResponseRecorder, 2)
		for _, a := range []*auth.Auth{h.first, h.second} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := httptest.NewRequest("POST", "https://factor.example/api/auth/two-factor/verify-otp", strings.NewReader(`{"code":"`+code+`","trustDevice":true}`))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", "https://factor.example")
				r.AddCookie(challenge)
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				results <- w
			}()
		}
		wg.Wait()
		close(results)
		successes := 0
		for w := range results {
			if w.Code == 200 {
				successes++
				h.cookie(w, "session_token")
				h.cookie(w, "trust_device")
			} else if w.Code != 401 {
				t.Fatal("unexpected concurrent verification", w.Code, w.Body)
			}
		}
		if successes != 1 {
			t.Fatalf("a delivered factor issued %d authenticated sessions", successes)
		}
		// Starting authenticator enrollment keeps the enrolled delivery channel usable.
		pending := h.request(h.first, "two-factor/enable", map[string]string{"password": password}, 200, current)
		challenge = start()
		code = send(h.second, challenge)
		h.request(h.first, "two-factor/verify-otp", map[string]string{"code": code}, 200, challenge)
		var setup struct{ TOTPURI string }
		if err = json.Unmarshal(pending.Body.Bytes(), &setup); err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(setup.TOTPURI)
		raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
		if err != nil {
			t.Fatal(err)
		}
		totpCode, err := h.first.GenerateTOTP(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		h.request(h.second, "two-factor/verify-totp", map[string]string{"code": totpCode}, 200, current)
		both := h.request(h.first, "sign-in/email", map[string]string{"email": email, "password": password}, 200)
		if !strings.Contains(both.Body.String(), `"twoFactorMethods":["totp","otp"]`) {
			t.Fatal("verified authenticator and delivered channel were not both offered")
		}
		challenge = h.cookie(both, "two_factor")
		code = send(h.first, challenge)
		if err = h.first.RequestPasswordReset(ctx, email, "/"); err != nil {
			t.Fatal(err)
		}
		if err = h.second.ResetPassword(ctx, h.recovery.Token, "changed-factor-credential"); err != nil {
			t.Fatal(err)
		}
		h.request(h.first, "two-factor/verify-otp", map[string]string{"code": code}, 401, challenge)
	})
}
func TestAuthenticatorAndBackupSettings(t *testing.T) {
	counter := 0
	base := twofactor.Options{
		TOTP: twofactor.TOTPOptions{Digits: 8, Period: 45 * time.Second}, SkipVerificationOnEnable: true,
		Backup:  twofactor.BackupOptions{Amount: 4, Length: 12, Store: "plain"},
		Lockout: twofactor.LockoutOptions{MaxFailedAttempts: 2, Duration: 2 * time.Minute},
	}
	withFactorDatabases(t, base, func(h *factorHarness) {
		t := h.t
		ctx := t.Context()
		email := strings.ToLower(rand.Text()) + "@example.test"
		const password = "test-configured-authenticator"
		reg, err := h.first.SignUpEmail(ctx, auth.SignUpInput{Email: email, Password: password}, auth.RequestMeta{})
		if err != nil {
			t.Fatal(err)
		}
		source := h.first.SessionCookie(reg.Token, true)
		setup := h.request(h.first, "two-factor/enable", map[string]string{"issuer": "Fixture", "password": password}, 200, source)
		current := h.cookie(setup, "session_token")
		var info struct {
			TOTPURI     string
			BackupCodes []string
		}
		if err = json.Unmarshal(setup.Body.Bytes(), &info); err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(info.TOTPURI)
		if err != nil {
			t.Fatal(err)
		}
		if u.Query().Get("digits") != "8" || u.Query().Get("period") != "45" || u.Query().Get("issuer") != "Fixture" {
			t.Fatal("custom authenticator parameters were omitted")
		}
		if len(info.BackupCodes) != 4 {
			t.Fatal("custom backup code amount or length was ignored")
		}
		for _, c := range info.BackupCodes {
			if len(c) != 13 || c[5] != '-' {
				t.Fatal("a custom-length backup code is not twelve characters split by a hyphen", c)
			}
		}
		view, err := h.second.ViewBackupCodes(ctx, reg.User.ID)
		if err != nil || len(view) != 4 || view[0] != info.BackupCodes[0] {
			t.Fatal("trusted backup code listing failed", err)
		}
		var column string
		listed, _ := json.Marshal(info.BackupCodes)
		if err = h.store.db.QueryRowContext(ctx, h.store.bind(`SELECT "backupCodes" FROM "twoFactor" WHERE "userId"=?`), reg.User.ID).Scan(&column); err != nil || column != string(listed) {
			t.Fatal("plain backup codes were not stored as the JSON list of issued codes", column, err)
		}
		raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
		if err != nil {
			t.Fatal(err)
		}
		code, err := h.first.GenerateTOTP(string(raw))
		if err != nil || len(code) != 8 {
			t.Fatal("native authenticator generation ignored settings", err)
		}
		login := func() *http.Cookie {
			w := h.request(h.first, "sign-in/email", map[string]string{"email": email, "password": password}, 200)
			return h.cookie(w, "two_factor")
		}
		ch := login()
		h.request(h.second, "two-factor/verify-totp", map[string]any{"code": code, "trustDevice": true}, 200, ch)
		ch = login()
		h.request(h.first, "two-factor/verify-backup-code", map[string]string{"code": "bad"}, 401, ch)
		h.request(h.second, "two-factor/verify-backup-code", map[string]string{"code": "bad"}, 401, ch)
		locked := h.request(h.first, "two-factor/verify-backup-code", map[string]string{"code": info.BackupCodes[0]}, 429, ch)
		if !strings.Contains(locked.Body.String(), "ACCOUNT_TEMPORARILY_LOCKED") {
			t.Fatal("configured account lockout did not cover backup codes")
		}
		var until time.Time
		if err = h.store.db.QueryRowContext(ctx, h.store.bind(`SELECT "lockedUntil" FROM "twoFactor" WHERE "userId"=?`), reg.User.ID).Scan(&until); err != nil || time.Until(until) < 110*time.Second || time.Until(until) > 121*time.Second {
			t.Fatal("custom lockout duration ignored", err)
		}
		if _, err = h.store.db.ExecContext(ctx, h.store.bind(`UPDATE "twoFactor" SET "lockedUntil"=? WHERE "userId"=?`), h.store.date(time.Now().Add(-time.Second)), reg.User.ID); err != nil {
			t.Fatal(err)
		}
		h.request(h.second, "two-factor/verify-backup-code", map[string]string{"code": info.BackupCodes[0]}, 200, ch)
		var failures int
		if err = h.store.db.QueryRowContext(ctx, h.store.bind(`SELECT "failedVerificationCount" FROM "twoFactor" WHERE "userId"=?`), reg.User.ID).Scan(&failures); err != nil || failures != 0 {
			t.Fatal("successful proof did not recover from lockout", err)
		}
		h.request(h.first, "two-factor/disable", map[string]string{"password": password}, 200, current)
		cfg := base
		cfg.SkipVerificationOnEnable = false
		cfg.AllowPasswordless = true
		cfg.Backup.Store = ""
		cfg.Backup.Generate = func(context.Context) ([]string, error) { counter++; return []string{"unique-code", "other-code"}, nil }
		cfg.Backup.Encrypt = func(_ context.Context, s string) (string, error) {
			return base64.StdEncoding.EncodeToString([]byte(s)), nil
		}
		cfg.Backup.Decrypt = func(_ context.Context, s string) (string, error) {
			raw, e := base64.StdEncoding.DecodeString(s)
			return string(raw), e
		}
		rate := false
		service, err := auth.New(auth.Options{Store: h.store, BaseURL: "https://factor.example", Secret: "synthetic-factor-secret-0001-0123456789", EmailAndPassword: true, RateLimit: &rate, Plugins: []auth.Plugin{twofactor.New(cfg)}})
		if err != nil {
			t.Fatal(err)
		}
		// A verified passwordless account has no credential row.
		id := rand.Text()
		now := time.Now().UTC().Truncate(time.Millisecond)
		if _, err = h.store.db.ExecContext(ctx, h.store.bind(`INSERT INTO "user" ("id","email","name","emailVerified","createdAt","updatedAt") VALUES (?,?,?,true,?,?)`), id, "passwordless-"+email, "Mailbox", h.store.date(now), h.store.date(now)); err != nil {
			t.Fatal(err)
		}
		session := auth.StoredSession{Session: auth.Session{ID: rand.Text(), Token: rand.Text(), UserID: id, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
		if err = h.store.CreateSession(ctx, session); err != nil {
			t.Fatal(err)
		}
		withoutPassword := service.SessionCookie(session.Token, true)
		enroll := h.request(service, "two-factor/enable", map[string]string{}, 200, withoutPassword)
		if !strings.Contains(enroll.Body.String(), "unique-code") || counter == 0 {
			t.Fatal("passwordless enrollment did not use custom backup generator")
		}
		items, err := service.ViewBackupCodes(ctx, id)
		if err != nil || len(items) != 2 || items[1] != "other-code" {
			t.Fatal("custom backup-code codec did not round trip", err)
		}
		var sealed string
		plainCodes, _ := json.Marshal([]string{"unique-code", "other-code"})
		if err = h.store.db.QueryRowContext(ctx, h.store.bind(`SELECT "backupCodes" FROM "twoFactor" WHERE "userId"=?`), id).Scan(&sealed); err != nil || sealed != base64.StdEncoding.EncodeToString(plainCodes) {
			t.Fatal("custom backup-code cipher was not used for storage", sealed, err)
		}
		off := false
		cfg.TOTP.AllowPasswordless = &off
		cfg.Backup.AllowPasswordless = &off
		cfg.TOTP.Disabled = true
		disabled, err := auth.New(auth.Options{Store: h.store, BaseURL: "https://factor.example", Secret: "synthetic-factor-secret-0001-0123456789", RateLimit: &off, Plugins: []auth.Plugin{twofactor.New(cfg)}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := disabled.GenerateTOTP("raw-secret"); err == nil {
			t.Fatal("disabled authenticator generated a code")
		}
		h.request(disabled, "two-factor/get-totp-uri", map[string]any{}, 400, withoutPassword)
		h.request(disabled, "two-factor/generate-backup-codes", map[string]any{}, 400, withoutPassword)
		passwordLogin, err := service.SignInEmail(ctx, auth.SignInInput{Email: email, Password: password}, auth.RequestMeta{})
		if err != nil {
			t.Fatal(err)
		}
		h.request(service, "two-factor/enable", map[string]string{}, 400, service.SessionCookie(passwordLogin.Token, true))
		h.request(service, "two-factor/view-backup-codes", map[string]string{"userId": id}, 404, withoutPassword)
		h.request(service, "two-factor/generate-totp", map[string]string{"secret": "unused"}, 404, withoutPassword)
	})
}

func TestFactorSenderFailureAndConcurrency(t *testing.T) {
	type pending struct {
		code   string
		finish chan error
	}
	messages := make(chan pending, 2)
	opts := twofactor.Options{OTP: twofactor.OTPOptions{Store: "encrypted", Send: func(_ context.Context, m twofactor.OTPMessage) error {
		p := pending{m.Code, make(chan error, 1)}
		messages <- p
		return <-p.finish
	}}}
	withFactorDatabases(t, opts, func(h *factorHarness) {
		t := h.t
		ctx := t.Context()
		u := h.enroll()
		challenge := func() *http.Cookie {
			w := h.request(h.first, "sign-in/email", map[string]string{"email": u.input.Email, "password": u.input.Password}, 200)
			return h.cookie(w, "two_factor")
		}
		a, b, c, d := challenge(), challenge(), challenge(), challenge()
		send := func(instance *auth.Auth, marker *http.Cookie) (pending, <-chan int) {
			statuses := make(chan int, 1)
			go func() {
				r := httptest.NewRequest("POST", "https://factor.example/api/auth/two-factor/send-otp", strings.NewReader("{}"))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", "https://factor.example")
				r.AddCookie(marker)
				w := httptest.NewRecorder()
				instance.ServeHTTP(w, r)
				statuses <- w.Code
			}()
			select {
			case m := <-messages:
				return m, statuses
			case status := <-statuses:
				t.Fatalf("sender returned %d before callback", status)
			case <-time.After(5 * time.Second):
				t.Fatal("factor sender did not run outside the transaction")
			}
			return pending{}, nil
		}
		// A code is stored before its sender runs, so it verifies while the
		// sender runs.
		running, done := send(h.first, c)
		h.request(h.second, "two-factor/verify-otp", map[string]string{"code": running.code}, 200, c)
		running.finish <- nil
		if status := <-done; status != 200 {
			t.Fatal("a send whose code was spent while it ran did not answer as sent", status)
		}
		// A failing sender changes neither the answer nor the stored code.
		failed, first := send(h.first, d)
		failed.finish <- errors.New("synthetic sender unavailable")
		if status := <-first; status != 200 {
			t.Fatal("a failing sender changed the send-otp answer", status)
		}
		// The code of the failed send still verifies.
		h.request(h.first, "two-factor/verify-otp", map[string]string{"code": failed.code}, 200, d)
		// An older send that fails late leaves the newer code alone.
		old, first := send(h.first, a)
		newer, last := send(h.second, a)
		newer.finish <- nil
		if <-last != 200 {
			t.Fatal("newer delivery did not publish")
		}
		old.finish <- errors.New("late delivery failure")
		if <-first != 200 {
			t.Fatal("a late sender failure changed the send-otp answer")
		}
		h.request(h.first, "two-factor/verify-otp", map[string]string{"code": newer.code}, 400, b)
		h.request(h.second, "two-factor/verify-otp", map[string]string{"code": newer.code}, 200, a)
		// A code requested in a signed-in session is scoped to that session.
		pendingSession, done := send(h.first, u.session)
		pendingSession.finish <- nil
		if <-done != 200 {
			t.Fatal("session delivery failed")
		}
		h.request(h.second, "two-factor/verify-otp", map[string]string{"code": pendingSession.code}, 400, b)
		if err := h.first.SignOut(ctx, http.Header{"Cookie": {u.session.String()}}); err != nil {
			t.Fatal(err)
		}
		h.request(h.second, "two-factor/verify-otp", map[string]string{"code": pendingSession.code}, 401, u.session)
	})
}

// A sender error is logged without the code while send-otp answers as sent
// and the code stays valid. With BackgroundTasks the code is stored before
// the response and sent by the queued task.
func TestDeliveredCodeSendsInBackground(t *testing.T) {
	var mu sync.Mutex
	var sent []twofactor.OTPMessage
	failNext := false
	opts := twofactor.Options{OTP: twofactor.OTPOptions{Send: func(_ context.Context, m twofactor.OTPMessage) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, m)
		if failNext {
			failNext = false
			return errors.New("synthetic delivery outage")
		}
		return nil
	}}}
	latest := func() (twofactor.OTPMessage, int) {
		mu.Lock()
		defer mu.Unlock()
		if len(sent) == 0 {
			return twofactor.OTPMessage{}, 0
		}
		return sent[len(sent)-1], len(sent)
	}
	logs := &lockedLog{}
	untimed := &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}
	withConfiguredFactorDatabases(t, opts, func(o *auth.Options) { o.Logger = slog.New(slog.NewTextHandler(logs, untimed)) }, func(h *factorHarness) {
		t := h.t
		ctx := t.Context()
		owner := h.enroll()
		mu.Lock()
		failNext = true
		mu.Unlock()
		challenge := h.challenge(h.first, owner)
		failures := logs.count("Failed to send two-factor OTP")
		if w := h.request(h.first, "two-factor/send-otp", map[string]any{}, 200, challenge); strings.TrimSpace(w.Body.String()) != `{"status":true}` {
			t.Fatal("a failed send did not answer status true", w.Body)
		}
		msg, _ := latest()
		if logs.count("Failed to send two-factor OTP") != failures+1 || logs.count(msg.Code) != 0 {
			t.Fatal("the failed delivery was not logged once without its code")
		}
		h.request(h.second, "two-factor/verify-otp", map[string]any{"code": msg.Code}, 200, challenge)

		var queue []func()
		off := false
		deferred, err := auth.New(auth.Options{Store: h.store, BaseURL: "https://factor.example", Secret: "synthetic-factor-secret-0001-0123456789", EmailAndPassword: true, RateLimit: &off, BackgroundTasks: func(task func()) { queue = append(queue, task) }, Plugins: []auth.Plugin{twofactor.New(opts)}})
		if err != nil {
			t.Fatal(err)
		}
		later := h.challenge(h.first, owner)
		_, before := latest()
		h.request(deferred, "two-factor/send-otp", map[string]any{}, 200, later)
		var stored int
		if err := h.store.db.QueryRowContext(ctx, h.store.bind(`SELECT count(*) FROM "verification" WHERE "identifier"=?`), "2fa-otp-"+h.first.VerifySignedSessionToken(later.Value)).Scan(&stored); err != nil || stored != 1 || len(queue) != 1 {
			t.Fatal("with a runner the code was not stored before its queued send", stored, len(queue), err)
		}
		if _, n := latest(); n != before {
			t.Fatal("with a runner the code was sent before the response")
		}
		for _, task := range queue {
			task()
		}
		queued, n := latest()
		if n != before+1 || queued.User.ID != owner.userID {
			t.Fatal("the queued send did not deliver the challenge's code")
		}
		h.request(h.second, "two-factor/verify-otp", map[string]any{"code": queued.Code}, 200, later)
	})
}
