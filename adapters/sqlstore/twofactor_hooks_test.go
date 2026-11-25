package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/twofactor"
	"github.com/pquerna/otp/totp"
)

// countingFactors counts two-factor store calls.
type countingFactors struct {
	*Store
	calls *atomic.Int32
}

func (c countingFactors) WithTwoFactor(ctx context.Context, sub auth.FactorSubject, decide func(auth.FactorState) (auth.FactorChange, error)) error {
	c.calls.Add(1)
	return c.Store.WithTwoFactor(ctx, sub, decide)
}

// Two-factor challenges, delivered codes and remembered browsers run the
// verification hooks on SQLite, PostgreSQL and MySQL, outside the store's
// transaction and with the stored row's ID. Each record's before hooks run
// before anything is judged or written, and its after hooks once the change
// committed, before the session's.
func TestVerificationHooksAroundTwoFactor(t *testing.T) {
	var mu sync.Mutex
	var events []string
	var records []auth.VerificationRecord
	var codes []string
	skip, fail := map[string]bool{}, map[string]bool{}
	sendFails := false
	var h *factorHarness
	var onEvent func(string) // runs once for the next matching event, outside the lock
	note := func(ctx context.Context, event string, rec *auth.VerificationRecord) error {
		if rec != nil && rec.UserID != "" && h != nil {
			// The hook reads the account through the store, which locks it:
			// a hook run inside the store's transaction would wait forever.
			read, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, err := h.first.ViewBackupCodes(read, rec.UserID)
			cancel()
			if errors.Is(err, context.DeadlineExceeded) {
				t.Error("the account was locked during", event)
			}
		}
		mu.Lock()
		events = append(events, event)
		if rec != nil {
			records = append(records, *rec)
		}
		run := onEvent
		if run != nil {
			onEvent = nil
		}
		skipped, failed := skip[event], fail[event]
		mu.Unlock()
		if run != nil {
			run(event)
		}
		if skipped {
			return auth.ErrSkipWrite
		}
		if failed {
			return errors.New("hook failed")
		}
		return nil
	}
	hooks := auth.DatabaseHooks{
		Verification: auth.ModelHooks[auth.VerificationRecord]{
			Create: auth.OperationHooks[auth.VerificationRecord]{
				Before: func(ctx context.Context, r *auth.VerificationRecord, _ *auth.HookContext) error {
					return note(ctx, "v-create-before:"+r.Identifier, r)
				},
				After: func(ctx context.Context, r auth.VerificationRecord, _ *auth.HookContext) error {
					return note(ctx, "v-create-after:"+r.Identifier, &r)
				},
			},
			Update: auth.OperationHooks[auth.VerificationRecord]{After: func(ctx context.Context, r auth.VerificationRecord, _ *auth.HookContext) error {
				return note(ctx, "v-update-after:"+r.Identifier, &r)
			}},
			Delete: auth.OperationHooks[auth.VerificationRecord]{
				Before: func(ctx context.Context, r *auth.VerificationRecord, _ *auth.HookContext) error {
					return note(ctx, "v-delete-before:"+r.Identifier, r)
				},
				After: func(ctx context.Context, r auth.VerificationRecord, _ *auth.HookContext) error {
					return note(ctx, "v-delete-after:"+r.Identifier, &r)
				},
			},
		},
		Session: auth.ModelHooks[auth.SessionRecord]{Create: auth.OperationHooks[auth.SessionRecord]{
			Before: func(ctx context.Context, _ *auth.SessionRecord, _ *auth.HookContext) error {
				return note(ctx, "session-before", nil)
			},
			After: func(ctx context.Context, _ auth.SessionRecord, _ *auth.HookContext) error {
				return note(ctx, "session-after", nil)
			},
		}},
	}
	send := func(_ context.Context, m auth.FactorOTPMessage) error {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, "send")
		codes = append(codes, m.Code)
		if sendFails {
			return errors.New("sms gateway down")
		}
		return nil
	}
	opts := twofactor.Options{Issuer: "Auth", OTP: auth.FactorOTPOptions{Send: send}}
	withConfiguredFactorDatabases(t, opts, func(o *auth.Options) { o.DatabaseHooks = hooks }, func(harness *factorHarness) {
		h = harness
		t := h.t
		ctx := t.Context()
		s := h.store
		drain := func() ([]string, []auth.VerificationRecord) {
			mu.Lock()
			defer mu.Unlock()
			e, r := events, records
			events, records = nil, nil
			return e, r
		}
		same := func(got []string, want ...string) {
			t.Helper()
			if len(got)+len(want) > 0 && !reflect.DeepEqual(got, want) {
				t.Fatalf("hooks ran as %q, want %q", got, want)
			}
		}
		set := func(m map[string]bool, event string, on bool) {
			mu.Lock()
			defer mu.Unlock()
			m[event] = on
		}
		lastCode := func() string {
			mu.Lock()
			defer mu.Unlock()
			return codes[len(codes)-1]
		}
		// enroll signs up an account with an authenticator and backup codes.
		enroll := func() (enrolledAccount, string) {
			t.Helper()
			in := auth.SignInInput{Email: strings.ToLower(rand.Text()) + "@example.test", Password: "private-fixture-credential"}
			reg, err := h.first.SignUpEmail(ctx, auth.SignUpInput{Email: in.Email, Password: in.Password, Name: "Mailbox"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			c := h.first.SessionCookie(reg.Token, true)
			enabled := h.request(h.first, "two-factor/enable", map[string]string{"password": in.Password}, 200, c)
			var body struct {
				TOTPURI     string
				BackupCodes []string
			}
			if err := json.Unmarshal(enabled.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(body.TOTPURI)
			if err != nil {
				t.Fatal(err)
			}
			secret := u.Query().Get("secret")
			code, err := totp.GenerateCode(secret, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			verified := h.request(h.second, "two-factor/verify-totp", map[string]string{"code": code}, 200, c)
			drain()
			return enrolledAccount{in, reg.User.ID, body.BackupCodes, h.cookie(verified, "session_token")}, secret
		}
		signIn := func(a *auth.Auth, u enrolledAccount, status int, cookies ...*http.Cookie) *httptest.ResponseRecorder {
			t.Helper()
			return h.request(a, "sign-in/email", map[string]string{"email": u.input.Email, "password": u.input.Password}, status, cookies...)
		}
		challengeOf := func(w *httptest.ResponseRecorder) (*http.Cookie, string) {
			t.Helper()
			c := h.cookie(w, "two_factor")
			return c, h.first.VerifySignedSessionToken(c.Value)
		}
		row := func(identifier string) (string, time.Time) {
			t.Helper()
			var id string
			var expires time.Time
			err := s.db.QueryRowContext(ctx, s.bind(`SELECT "id","expiresAt" FROM "verification" WHERE "identifier"=?`), identifier).Scan(&id, &expires)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				t.Fatal(err)
			}
			return id, expires
		}
		value := func(identifier string) string {
			t.Helper()
			var v string
			if err := s.db.QueryRowContext(ctx, s.bind(`SELECT "value" FROM "verification" WHERE "identifier"=?`), identifier).Scan(&v); err != nil {
				t.Fatal(identifier, err)
			}
			return v
		}
		count := func(where string, args ...any) int {
			t.Helper()
			var n int
			if err := s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "verification" WHERE `+where), args...).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		failures := func(uid string) int {
			t.Helper()
			var n int
			if err := s.db.QueryRowContext(ctx, s.bind(`SELECT "failedVerificationCount" FROM "twoFactor" WHERE "userId"=?`), uid).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		// saw checks every record since the last drain against the row stored
		// under identifier, and that none carried a secret.
		saw := func(recs []auth.VerificationRecord, kind, identifier, uid string, secrets ...string) {
			t.Helper()
			id, expires := row(identifier)
			if id == "" {
				t.Fatal("nothing is stored under", identifier)
			}
			if len(recs) == 0 {
				t.Fatal("no record hook ran")
			}
			for _, r := range recs {
				if r.ID != id || r.Identifier != kind || r.UserID != uid || !r.ExpiresAt.Equal(expires) || r.ExpiresAt.Location() != time.UTC {
					t.Fatalf("a hook saw %+v for the row %s expiring %v", r, id, expires)
				}
				for _, secret := range append(secrets, identifier) {
					if strings.Contains(fmt.Sprint(r), secret) {
						t.Fatal("a record carried a secret:", r)
					}
				}
			}
		}
		cleared := func(w *httptest.ResponseRecorder, name string) bool {
			for _, c := range w.Result().Cookies() {
				if strings.HasSuffix(c.Name, "."+name) && c.MaxAge < 0 {
					return true
				}
			}
			return false
		}

		u, secret := enroll()
		// A sign-in that asks for the second factor runs the challenge's create
		// hooks, and no session's.
		w := signIn(h.first, u, 200)
		cookie, key := challengeOf(w)
		got, recs := drain()
		same(got, "v-create-before:2fa", "v-create-after:2fa")
		saw(recs, "2fa", key, u.userID, cookie.Value)
		// A correct authenticator code with trustDevice spends the challenge
		// and stores a remembered browser, before the session's hooks.
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		w = h.request(h.second, "two-factor/verify-totp", map[string]any{"code": code, "trustDevice": true}, 200, cookie)
		got, recs = drain()
		same(got, "v-delete-before:2fa", "v-create-before:trust-device", "session-before", "v-delete-after:2fa", "v-create-after:trust-device", "session-after")
		trust := h.cookie(w, "trust_device")
		grant := strings.TrimPrefix(h.first.VerifySignedSessionToken(trust.Value), h.first.TrustedDeviceCookieName()+"|"+u.userID+"|")
		saw([]auth.VerificationRecord{recs[1], recs[3]}, "trust-device", grant, u.userID, trust.Value, code)

		// A remembered browser rotates its grant through the verification hooks.
		w = signIn(h.second, u, 200, trust)
		got, recs = drain()
		same(got, "v-delete-before:trust-device", "v-create-before:trust-device", "session-before", "v-delete-after:trust-device", "v-create-after:trust-device", "session-after")
		next := h.cookie(w, "trust_device")
		nextGrant := strings.TrimPrefix(h.first.VerifySignedSessionToken(next.Value), h.first.TrustedDeviceCookieName()+"|"+u.userID+"|")
		saw([]auth.VerificationRecord{recs[1], recs[3]}, "trust-device", nextGrant, u.userID, next.Value)
		if recs[0] != recs[2] || recs[0].ID == recs[1].ID || count(`"identifier"=?`, grant) != 0 {
			t.Fatal("the rotation spent", recs[0], recs[2])
		}
		// A declined spend or replacement keeps the grant and its cookie and
		// asks for the second factor.
		for _, declined := range []string{"v-delete-before:trust-device", "v-create-before:trust-device"} {
			set(skip, declined, true)
			w = signIn(h.first, u, 200, next)
			set(skip, declined, false)
			got, _ = drain()
			want := []string{"v-delete-before:trust-device"}
			if declined == "v-create-before:trust-device" {
				want = append(want, declined)
			}
			same(got, append(want, "v-create-before:2fa", "v-create-after:2fa")...)
			if !strings.Contains(w.Body.String(), "twoFactorRedirect") || cleared(w, "trust_device") || count(`"identifier"=?`, nextGrant) != 1 {
				t.Fatal("a declined remembered browser answered", w.Body.String())
			}
		}
		// A skipped session keeps the grant, and no after hook runs.
		set(skip, "session-before", true)
		signIn(h.first, u, 401, next)
		set(skip, "session-before", false)
		got, _ = drain()
		same(got, "v-delete-before:trust-device", "v-create-before:trust-device", "session-before")
		if count(`"identifier"=?`, nextGrant) != 1 {
			t.Fatal("a skipped session spent the grant")
		}
		// Sign-ins sharing a remembered browser spend it once.
		var wg sync.WaitGroup
		bodies := make(chan string, 4)
		for i := range 4 {
			wg.Go(func() {
				data, _ := json.Marshal(map[string]string{"email": u.input.Email, "password": u.input.Password})
				r := httptest.NewRequest("POST", "https://factor.example/api/auth/sign-in/email", strings.NewReader(string(data)))
				r.Header.Set("Origin", "https://factor.example")
				r.Header.Set("Content-Type", "application/json")
				r.AddCookie(next)
				rec := httptest.NewRecorder()
				[]*auth.Auth{h.first, h.second}[i%2].ServeHTTP(rec, r)
				bodies <- fmt.Sprint(rec.Code, " ", rec.Body.String())
			})
		}
		wg.Wait()
		close(bodies)
		sessions, redirects := 0, 0
		for b := range bodies {
			switch {
			case strings.HasPrefix(b, "200 ") && strings.Contains(b, "twoFactorRedirect"):
				redirects++
			case strings.HasPrefix(b, "200 "):
				sessions++
			default:
				t.Fatal("a sign-in sharing a remembered browser answered", b)
			}
		}
		tally := map[string]int{}
		got, _ = drain()
		for _, e := range got {
			tally[e]++
		}
		if sessions != 1 || redirects != 3 || tally["v-delete-after:trust-device"] != 1 || tally["v-create-after:trust-device"] != 1 || tally["v-create-after:2fa"] != 3 || tally["session-after"] != 1 {
			t.Fatal("four sign-ins sharing a remembered browser ran", sessions, redirects, tally)
		}

		// A declined challenge is answered but redeems nothing.
		before := count(`"value"=? AND "identifier" LIKE '2fa-%'`, u.userID)
		set(skip, "v-create-before:2fa", true)
		w = signIn(h.first, u, 200)
		set(skip, "v-create-before:2fa", false)
		cookie, _ = challengeOf(w)
		if !strings.Contains(w.Body.String(), "twoFactorRedirect") || count(`"value"=? AND "identifier" LIKE '2fa-%'`, u.userID) != before {
			t.Fatal("a declined challenge was stored")
		}
		got, _ = drain()
		same(got, "v-create-before:2fa")
		h.request(h.second, "two-factor/verify-backup-code", map[string]any{"code": u.backups[0]}, 401, cookie)
		got, _ = drain()
		same(got)

		// A declined proof is refused before the code is compared or counted.
		cookie, key = challengeOf(signIn(h.first, u, 200))
		drain()
		set(skip, "v-delete-before:2fa", true)
		w = h.request(h.second, "two-factor/verify-backup-code", map[string]any{"code": "wrong-code"}, 401, cookie)
		set(skip, "v-delete-before:2fa", false)
		if !strings.Contains(w.Body.String(), "INVALID_TWO_FACTOR_COOKIE") || value("2fa-attempts-"+key) != "0" || failures(u.userID) != 0 || cleared(w, "two_factor") {
			t.Fatal("a declined proof was judged:", w.Body.String())
		}
		got, _ = drain()
		same(got, "v-delete-before:2fa")
		// A counted wrong guess runs the update after hooks on the same record.
		h.request(h.second, "two-factor/verify-backup-code", map[string]any{"code": "wrong-code"}, 401, cookie)
		got, recs = drain()
		same(got, "v-delete-before:2fa", "v-update-after:2fa")
		saw(recs, "2fa", key, u.userID, cookie.Value)
		if value("2fa-attempts-"+key) != "1" || failures(u.userID) != 1 {
			t.Fatal("the wrong guess was not counted")
		}
		// A declined authenticator code is refused before it is compared or counted.
		stale, err := totp.GenerateCode(secret, time.Now().Add(-time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		set(skip, "v-delete-before:2fa", true)
		w = h.request(h.first, "two-factor/verify-totp", map[string]any{"code": stale}, 401, cookie)
		set(skip, "v-delete-before:2fa", false)
		if !strings.Contains(w.Body.String(), "INVALID_TWO_FACTOR_COOKIE") || value("2fa-attempts-"+key) != "1" || failures(u.userID) != 1 || cleared(w, "two_factor") {
			t.Fatal("a declined authenticator code was judged:", w.Body.String())
		}
		got, _ = drain()
		same(got, "v-delete-before:2fa")
		w = h.request(h.second, "two-factor/verify-totp", map[string]any{"code": stale}, 401, cookie)
		got, recs = drain()
		same(got, "v-delete-before:2fa", "v-update-after:2fa")
		saw(recs, "2fa", key, u.userID, cookie.Value, stale)
		if !strings.Contains(w.Body.String(), "INVALID_CODE") || value("2fa-attempts-"+key) != "2" || failures(u.userID) != 2 {
			t.Fatal("a wrong authenticator code was not counted:", w.Body.String())
		}
		// A declined trust grant signs in without remembering the browser.
		set(skip, "v-create-before:trust-device", true)
		grants := count(`"value"=? AND "identifier" LIKE 'trust-device-%'`, u.userID)
		w = h.request(h.first, "two-factor/verify-backup-code", map[string]any{"code": u.backups[0], "trustDevice": true}, 200, cookie)
		set(skip, "v-create-before:trust-device", false)
		got, _ = drain()
		same(got, "v-delete-before:2fa", "v-create-before:trust-device", "session-before", "v-delete-after:2fa", "session-after")
		for _, c := range w.Result().Cookies() {
			if strings.HasSuffix(c.Name, ".trust_device") {
				t.Fatal("a declined grant set", c)
			}
		}
		if count(`"value"=? AND "identifier" LIKE 'trust-device-%'`, u.userID) != grants {
			t.Fatal("a declined grant was stored")
		}
		// The fifth wrong guess spends the challenge with its delete hooks.
		cookie, key = challengeOf(signIn(h.first, u, 200))
		drain()
		for i := range 5 {
			w = h.request([]*auth.Auth{h.first, h.second}[i%2], "two-factor/verify-backup-code", map[string]any{"code": "wrong-code", "trustDevice": i == 0}, 401, cookie)
			got, _ = drain()
			switch i {
			case 0:
				same(got, "v-delete-before:2fa", "v-create-before:trust-device", "v-update-after:2fa")
			case 4:
				same(got, "v-delete-before:2fa", "v-delete-after:2fa")
			default:
				same(got, "v-delete-before:2fa", "v-update-after:2fa")
			}
		}
		if !cleared(w, "two_factor") || count(`"identifier"=?`, key) != 0 {
			t.Fatal("the fifth wrong guess kept the challenge")
		}
		// A backup code with disableSession spends the challenge without a session or a remembered browser.
		cookie, _ = challengeOf(signIn(h.second, u, 200))
		drain()
		h.request(h.first, "two-factor/verify-backup-code", map[string]any{"code": u.backups[1], "disableSession": true, "trustDevice": true}, 200, cookie)
		got, _ = drain()
		same(got, "v-delete-before:2fa", "v-delete-after:2fa")
		// An expired challenge is refused without hooks.
		cookie, key = challengeOf(signIn(h.second, u, 200))
		drain()
		if _, err := s.db.ExecContext(ctx, s.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "identifier"=?`), s.date(time.Now().Add(-time.Minute)), key); err != nil {
			t.Fatal(err)
		}
		h.request(h.first, "two-factor/verify-backup-code", map[string]any{"code": u.backups[2]}, 401, cookie)
		got, _ = drain()
		same(got)

		// A send runs the code's create before hooks before the code is drawn,
		// and its create after hooks once it is stored, before it is sent.
		cookie, key = challengeOf(signIn(h.first, u, 200))
		drain()
		h.request(h.second, "two-factor/send-otp", map[string]any{}, 200, cookie)
		got, recs = drain()
		same(got, "v-create-before:2fa-otp", "v-create-after:2fa-otp", "send")
		code = lastCode()
		saw(recs, "2fa-otp", "2fa-otp-"+key, u.userID, code, cookie.Value)
		// A declined delivered code answers as sent; nothing is stored or sent.
		set(skip, "v-create-before:2fa-otp", true)
		h.request(h.first, "two-factor/send-otp", map[string]any{}, 200, cookie)
		set(skip, "v-create-before:2fa-otp", false)
		got, _ = drain()
		same(got, "v-create-before:2fa-otp")
		if count(`"identifier" IN (?,?)`, "2fa-otp-"+key, "pending-2fa-otp-"+key) != 1 {
			t.Fatal("a declined code replaced the earlier one")
		}
		// Each counted wrong delivered code runs the update after hooks.
		h.request(h.first, "two-factor/verify-otp", map[string]any{"code": "000000x"}, 401, cookie)
		got, recs = drain()
		same(got, "v-delete-before:2fa-otp", "v-delete-before:2fa", "v-update-after:2fa-otp", "v-update-after:2fa")
		if recs[0] != recs[2] || recs[1] != recs[3] || recs[0].Identifier != "2fa-otp" || recs[1].Identifier != "2fa" {
			t.Fatal("the counted guess saw", recs)
		}
		// A declined code gate keeps the code and runs no challenge gate.
		set(skip, "v-delete-before:2fa-otp", true)
		w = h.request(h.second, "two-factor/verify-otp", map[string]any{"code": code}, 400, cookie)
		set(skip, "v-delete-before:2fa-otp", false)
		got, _ = drain()
		same(got, "v-delete-before:2fa-otp")
		if !strings.Contains(w.Body.String(), "OTP_HAS_EXPIRED") || value("2fa-attempts-"+key) != "1" || !strings.HasSuffix(value("2fa-otp-"+key), ":1") {
			t.Fatal("a declined code gate counted the guess:", w.Body.String())
		}
		// The earlier code still verifies, spending code and challenge.
		h.request(h.second, "two-factor/verify-otp", map[string]any{"code": code}, 200, cookie)
		got, _ = drain()
		same(got, "v-delete-before:2fa-otp", "v-delete-before:2fa", "session-before", "v-delete-after:2fa-otp", "v-delete-after:2fa", "session-after")

		// A code sent again while its hooks run is left alone.
		cookie, key = challengeOf(signIn(h.first, u, 200))
		h.request(h.first, "two-factor/send-otp", map[string]any{}, 200, cookie)
		drain()
		mu.Lock()
		onEvent = func(string) { h.request(h.second, "two-factor/send-otp", map[string]any{}, 200, cookie) }
		mu.Unlock()
		w = h.request(h.first, "two-factor/verify-otp", map[string]any{"code": lastCode()}, 400, cookie)
		got, _ = drain()
		same(got, "v-delete-before:2fa-otp", "v-create-before:2fa-otp", "v-create-after:2fa-otp", "send", "v-delete-before:2fa")
		if !strings.Contains(w.Body.String(), "OTP is unavailable") || !strings.HasSuffix(value("2fa-otp-"+key), ":0") || value("2fa-attempts-"+key) != "0" {
			t.Fatal("a code sent again was judged:", w.Body.String())
		}
		h.request(h.second, "two-factor/verify-otp", map[string]any{"code": lastCode()}, 200, cookie)
		drain()
		// A code that ran out is removed with its delete hooks.
		cookie, key = challengeOf(signIn(h.first, u, 200))
		h.request(h.first, "two-factor/send-otp", map[string]any{}, 200, cookie)
		drain()
		stored := value("2fa-otp-" + key)
		if _, err := s.db.ExecContext(ctx, s.bind(`UPDATE "verification" SET "value"=? WHERE "identifier"=?`), stored[:strings.LastIndexByte(stored, ':')]+":5", "2fa-otp-"+key); err != nil {
			t.Fatal(err)
		}
		w = h.request(h.second, "two-factor/verify-otp", map[string]any{"code": lastCode()}, 400, cookie)
		got, _ = drain()
		same(got, "v-delete-before:2fa-otp", "v-delete-before:2fa", "v-delete-after:2fa-otp")
		if !strings.Contains(w.Body.String(), "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE") {
			t.Fatal("a code that ran out answered", w.Body.String())
		}
		// A failed send removes its pending code without hooks.
		mu.Lock()
		sendFails = true
		mu.Unlock()
		w = httptest.NewRecorder()
		r := httptest.NewRequest("POST", "https://factor.example/api/auth/two-factor/send-otp", strings.NewReader("{}"))
		r.Header.Set("Origin", "https://factor.example")
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(cookie)
		h.first.ServeHTTP(w, r)
		mu.Lock()
		sendFails = false
		mu.Unlock()
		got, _ = drain()
		same(got, "v-create-before:2fa-otp", "v-create-after:2fa-otp", "send")
		if w.Code < 400 || count(`"identifier" IN (?,?)`, "2fa-otp-"+key, "pending-2fa-otp-"+key) != 0 {
			t.Fatal("a failed send answered", w.Code, "and kept its code")
		}

		// Signed-in codes name the account, and signed-in proofs of other
		// factors run no hooks.
		h.request(h.first, "two-factor/send-otp", map[string]any{}, 200, u.session)
		h.request(h.second, "two-factor/verify-otp", map[string]any{"code": lastCode()}, 200, u.session)
		got, recs = drain()
		same(got, "v-create-before:2fa-otp", "v-create-after:2fa-otp", "send", "v-delete-before:2fa-otp", "v-delete-after:2fa-otp")
		for _, r := range recs {
			if r.Identifier != "2fa-otp" || r.UserID != u.userID {
				t.Fatal("a signed-in code's hook saw", r)
			}
		}
		h.request(h.first, "two-factor/verify-backup-code", map[string]any{"code": u.backups[3]}, 200, u.session)
		got, _ = drain()
		same(got)

		// A failed create after hook is returned; the challenge stays and no
		// session is issued.
		challenges := count(`"value"=? AND "identifier" LIKE '2fa-%'`, u.userID)
		set(fail, "v-create-after:2fa", true)
		signIn(h.first, u, 500)
		set(fail, "v-create-after:2fa", false)
		got, _ = drain()
		same(got, "v-create-before:2fa", "v-create-after:2fa")
		if count(`"value"=? AND "identifier" LIKE '2fa-%'`, u.userID) != challenges+1 {
			t.Fatal("a failed create after hook removed the challenge")
		}

		// Concurrent proofs at one challenge count each wrong guess once and spend it once.
		v, _ := enroll()
		for _, correct := range []bool{false, true} {
			cookie, _ = challengeOf(signIn(h.first, v, 200))
			drain()
			guess := "wrong-code"
			if correct {
				guess = v.backups[0]
			}
			statuses := make(chan int, 6)
			for i := range 6 {
				wg.Go(func() {
					data, _ := json.Marshal(map[string]any{"code": guess})
					r := httptest.NewRequest("POST", "https://factor.example/api/auth/two-factor/verify-backup-code", strings.NewReader(string(data)))
					r.Header.Set("Origin", "https://factor.example")
					r.Header.Set("Content-Type", "application/json")
					r.AddCookie(cookie)
					rec := httptest.NewRecorder()
					[]*auth.Auth{h.first, h.second}[i%2].ServeHTTP(rec, r)
					statuses <- rec.Code
				})
			}
			wg.Wait()
			close(statuses)
			signedIn := 0
			for status := range statuses {
				if status == 200 {
					signedIn++
				} else if status != 401 && status != 429 {
					t.Fatal("a concurrent proof answered", status)
				}
			}
			tally := map[string]int{}
			got, _ = drain()
			for _, e := range got {
				tally[e]++
			}
			if correct && (signedIn != 1 || tally["v-delete-after:2fa"] != 1 || tally["v-update-after:2fa"] != 0 || tally["session-after"] != 1) {
				t.Fatal("six concurrent correct proofs ran", signedIn, tally)
			}
			if !correct && (signedIn != 0 || tally["v-update-after:2fa"] != 4 || tally["v-delete-after:2fa"] != 1) {
				t.Fatal("six concurrent wrong proofs ran", tally)
			}
		}

		// Disabling the factor removes challenges and grants without hooks.
		signIn(h.first, u, 200)
		drain()
		h.request(h.second, "two-factor/disable", map[string]string{"password": u.input.Password}, 200, u.session)
		got, _ = drain()
		for _, e := range got {
			if strings.HasPrefix(e, "v-") {
				t.Fatal("disabling the factor ran", got)
			}
		}
		if count(`"value"=? AND ("identifier" LIKE '2fa-%' OR "identifier" LIKE 'trust-device-%')`, u.userID) != 0 {
			t.Fatal("disabling the factor kept its records")
		}

		// An account without a second factor makes one store call; an enrolled
		// one makes a second after its challenge's before hooks.
		var calls atomic.Int32
		off := false
		counted, err := auth.New(auth.Options{EmailAndPassword: true, Secret: "synthetic-factor-secret-0001-0123456789", BaseURL: "https://factor.example",
			Store: countingFactors{s, &calls}, Plugins: []auth.Plugin{twofactor.New(opts)}, RateLimit: &off,
			DatabaseHooks: auth.DatabaseHooks{Verification: auth.ModelHooks[auth.VerificationRecord]{Create: hooks.Verification.Create}}})
		if err != nil {
			t.Fatal(err)
		}
		signIn(counted, u, 200)
		if calls.Swap(0) != 1 {
			t.Fatal("a sign-in without a second factor made more than one store call")
		}
		signIn(counted, v, 200)
		if n := calls.Load(); n != 2 {
			t.Fatal("a sign-in with a second factor made", n, "store calls")
		}
		drain()
	})
}
