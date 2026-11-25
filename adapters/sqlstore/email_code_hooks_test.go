package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// Email code verification hooks run on SQLite, PostgreSQL and MySQL,
// outside the store's transaction and with the stored row's ID. Around a
// planned sign-in the code's delete before hooks run once, before the dry
// run and the user and session before hooks, and its after hooks before
// theirs; a wrong guess is counted once. A skipped user keeps the code, a
// code that expires while its hooks run is removed with its after hooks, and
// a code another runtime stores again is refused uncounted.
func TestVerificationHooksAroundEmailCodes(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			open := func() *Store {
				t.Helper()
				s, err := Open(ctx, dialect, dsn)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				return s
			}
			store, other := open(), open()
			var mu sync.Mutex
			var events, mail []string
			var records []auth.VerificationRecord
			fail := map[string]error{}
			during := map[string]func(context.Context){}
			// probe is the mailbox a guess locks; its hooks read it through the
			// store, which takes the same lock, so they must run outside the
			// store's transaction. Concurrent guesses clear it.
			var probe *auth.EmailOTPRequest
			note := func(ctx context.Context, event string, rec *auth.VerificationRecord) error {
				mu.Lock()
				events = append(events, event)
				if rec != nil {
					records = append(records, *rec)
				}
				fn, err, mailbox := during[event], fail[event], probe
				mu.Unlock()
				if rec != nil && mailbox != nil && !strings.HasPrefix(event, "v-create") {
					read, cancel := context.WithTimeout(ctx, 5*time.Second)
					defer cancel()
					req := *mailbox
					req.Now = time.Now()
					if _, err := store.ReadEmailOTP(read, req); err != nil {
						t.Error("the mailbox was locked during", event, err)
					}
				}
				if fn != nil {
					fn(ctx)
				}
				return err
			}
			setFail := func(event string, err error) {
				mu.Lock()
				defer mu.Unlock()
				fail[event] = err
			}
			setDuring := func(event string, fn func(context.Context)) {
				mu.Lock()
				defer mu.Unlock()
				during[event] = fn
			}
			setProbe := func(email string, purpose auth.EmailOTPPurpose) {
				mu.Lock()
				defer mu.Unlock()
				probe = nil
				if email != "" {
					probe = &auth.EmailOTPRequest{Email: email, Purpose: purpose}
				}
			}
			drain := func() []string {
				mu.Lock()
				defer mu.Unlock()
				out := events
				events = nil
				return out
			}
			last := func() auth.VerificationRecord {
				mu.Lock()
				defer mu.Unlock()
				return records[len(records)-1]
			}
			same := func(got []string, want ...string) {
				t.Helper()
				if len(got)+len(want) > 0 && !reflect.DeepEqual(got, want) {
					t.Fatalf("hooks ran as %q, want %q", got, want)
				}
			}
			hooks := auth.DatabaseHooks{
				Verification: auth.ModelHooks[auth.VerificationRecord]{
					Create: auth.OperationHooks[auth.VerificationRecord]{After: func(ctx context.Context, r auth.VerificationRecord, _ *auth.HookContext) error {
						return note(ctx, "v-create-after:"+r.Identifier, &r)
					}},
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
				User: auth.ModelHooks[auth.UserRecord]{Create: auth.OperationHooks[auth.UserRecord]{
					Before: func(ctx context.Context, _ *auth.UserRecord, _ *auth.HookContext) error {
						return note(ctx, "user-before", nil)
					},
					After: func(ctx context.Context, _ auth.UserRecord, _ *auth.HookContext) error {
						return note(ctx, "user-after", nil)
					},
				}},
				Session: auth.ModelHooks[auth.SessionRecord]{Create: auth.OperationHooks[auth.SessionRecord]{
					Before: func(ctx context.Context, _ *auth.SessionRecord, _ *auth.HookContext) error {
						return note(ctx, "session-before", nil)
					},
					After: func(ctx context.Context, _ auth.SessionRecord, _ *auth.HookContext) error {
						return note(ctx, "session-after", nil)
					},
				}},
			}
			instance := func(s *Store, edit func(*auth.Options, *auth.EmailOTPOptions)) *auth.Auth {
				t.Helper()
				o := auth.EmailOTPOptions{Send: func(_ context.Context, m auth.EmailOTPMessage) error {
					mu.Lock()
					defer mu.Unlock()
					mail = append(mail, m.OTP)
					return nil
				}}
				off := false
				opts := auth.Options{Store: s, BaseURL: "https://auth.example", Secret: strings.Repeat("s", 40), RateLimit: &off, EmailAndPassword: true, DatabaseHooks: hooks}
				if edit != nil {
					edit(&opts, &o)
				}
				codes, err := auth.NewEmailOTP(o)
				if err != nil {
					t.Fatal(err)
				}
				opts.Plugins = []auth.Plugin{codes}
				a, err := auth.New(opts)
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			a, b := instance(store, nil), instance(other, nil)
			serve := func(a *auth.Auth, path, body, cookie string) *httptest.ResponseRecorder {
				r := httptest.NewRequest("POST", "https://auth.example/api/auth"+path, strings.NewReader(body))
				r.Header.Set("Origin", "https://auth.example")
				r.Header.Set("Content-Type", "application/json")
				if cookie != "" {
					r.Header.Set("Cookie", cookie)
				}
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				return w
			}
			call := func(a *auth.Auth, path, body, cookie string, status int, want string) *httptest.ResponseRecorder {
				t.Helper()
				w := serve(a, path, body, cookie)
				if w.Code != status || !strings.Contains(w.Body.String(), want) {
					t.Fatalf("%s answered %d %s, want %d with %q", path, w.Code, w.Body.String(), status, want)
				}
				return w
			}
			send := func(a *auth.Auth, email string) string {
				t.Helper()
				call(a, "/email-otp/send-verification-otp", `{"email":"`+email+`","type":"sign-in"}`, "", 200, "")
				mu.Lock()
				defer mu.Unlock()
				return mail[len(mail)-1]
			}
			signIn := func(a *auth.Auth, email, code string, status int, want string) {
				t.Helper()
				setProbe(email, auth.OTPSignIn)
				call(a, "/sign-in/email-otp", `{"email":"`+email+`","otp":"`+code+`"}`, "", status, want)
			}
			tally := func() map[string]int {
				n := map[string]int{}
				for _, e := range drain() {
					n[e]++
				}
				return n
			}
			row := func(email string) (id, value string) {
				t.Helper()
				err := store.db.QueryRowContext(ctx, store.bind(`SELECT "id","value" FROM "verification" WHERE "identifier"=? ORDER BY "createdAt" DESC LIMIT 1`), "sign-in-otp-"+email).Scan(&id, &value)
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					t.Fatal(err)
				}
				return id, value
			}

			// The record names the stored row, and a planned wrong guess is counted once.
			code := send(a, "new@codes.example")
			same(drain(), "v-create-after:sign-in-otp")
			created := last()
			if id, value := row("new@codes.example"); created.ID != id || !strings.HasSuffix(value, ":0") {
				t.Fatal("the hook saw ID", created.ID, "for the row", id, value)
			}
			signIn(a, "new@codes.example", "nope", 400, "INVALID_OTP")
			same(drain(), "v-delete-before:sign-in-otp", "v-update-after:sign-in-otp")
			if _, value := row("new@codes.example"); !strings.HasSuffix(value, ":1") {
				t.Fatal("the planned wrong guess was counted as", value)
			}
			// The code's hooks wrap the planned sign-in's.
			signIn(a, "new@codes.example", code, 200, "")
			same(drain(), "v-delete-before:sign-in-otp", "user-before", "session-before", "v-delete-after:sign-in-otp", "user-after", "session-after")
			if spent := last(); spent != created {
				t.Fatal("the spend's record was", spent, created)
			}

			// A skipped user keeps the code, and the retry signs in.
			code = send(a, "skipped@codes.example")
			drain()
			setFail("user-before", auth.ErrSkipWrite)
			signIn(a, "skipped@codes.example", code, 500, "FAILED_TO_CREATE_USER")
			same(drain(), "v-delete-before:sign-in-otp", "user-before")
			setFail("user-before", nil)
			signIn(a, "skipped@codes.example", code, 200, "")
			drain()

			// A code that expires while its hooks run is removed with its after hooks.
			code = send(a, "late@codes.example")
			drain()
			setDuring("v-delete-before:sign-in-otp", func(ctx context.Context) {
				if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "identifier"=?`), store.date(time.Now().Add(-time.Minute)), "sign-in-otp-late@codes.example"); err != nil {
					t.Error(err)
				}
			})
			signIn(a, "late@codes.example", code, 400, "OTP_EXPIRED")
			setDuring("v-delete-before:sign-in-otp", nil)
			same(drain(), "v-delete-before:sign-in-otp", "v-delete-after:sign-in-otp")

			// A code another runtime stores again while its hooks run is refused uncounted.
			code = send(a, "again@codes.example")
			drain()
			var once sync.Once
			setDuring("v-delete-before:sign-in-otp", func(ctx context.Context) {
				once.Do(func() {
					now := time.Now().Add(time.Second)
					if _, err := store.db.ExecContext(ctx, store.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`),
						"again-row", "sign-in-otp-again@codes.example", code+":0", store.date(now.Add(time.Minute)), store.date(now), store.date(now)); err != nil {
						t.Error(err)
					}
				})
			})
			signIn(a, "again@codes.example", code, 400, "INVALID_OTP")
			setDuring("v-delete-before:sign-in-otp", nil)
			same(drain(), "v-delete-before:sign-in-otp")
			if id, value := row("again@codes.example"); id != "again-row" || value != code+":0" {
				t.Fatal("the code stored again was touched:", id, value)
			}
			signIn(a, "again@codes.example", code, 200, "")
			drain()

			// Concurrent guesses at one email code count each wrong guess once and spend it once.
			code = send(a, "race@codes.example")
			drain()
			setProbe("", "")
			var wg sync.WaitGroup
			for i := range 6 {
				wg.Go(func() {
					serve([]*auth.Auth{a, b}[i%2], "/sign-in/email-otp", `{"email":"race@codes.example","otp":"nope"}`, "")
				})
			}
			wg.Wait()
			if n := tally(); n["v-update-after:sign-in-otp"] != 3 || n["v-delete-after:sign-in-otp"] != 1 {
				t.Fatal("six concurrent wrong guesses ran", n)
			}
			code = send(a, "race@codes.example")
			drain()
			ok := make(chan int, 6)
			for i := range 6 {
				wg.Go(func() {
					ok <- serve([]*auth.Auth{a, b}[i%2], "/sign-in/email-otp", `{"email":"race@codes.example","otp":"`+code+`"}`, "").Code
				})
			}
			wg.Wait()
			close(ok)
			signedIn := 0
			for status := range ok {
				if status == 200 {
					signedIn++
				}
			}
			if n := tally(); signedIn != 1 || n["v-delete-after:sign-in-otp"] != 1 {
				t.Fatal("six concurrent sign-ins succeeded", signedIn, "times with", n)
			}

			// The reset's after hooks run before the reset callback.
			resets := instance(store, func(o *auth.Options, _ *auth.EmailOTPOptions) {
				o.OnPasswordReset = func(ctx context.Context, _ auth.User, _ *http.Request) error {
					return note(ctx, "on-password-reset", nil)
				}
			})
			call(resets, "/sign-up/email", `{"email":"reset@codes.example","password":"correct horse battery","name":"Ada"}`, "", 200, "")
			call(resets, "/email-otp/request-password-reset", `{"email":"reset@codes.example"}`, "", 200, "")
			mu.Lock()
			code = mail[len(mail)-1]
			mu.Unlock()
			drain()
			setProbe("reset@codes.example", auth.OTPResetPassword)
			call(resets, "/email-otp/reset-password", `{"email":"reset@codes.example","otp":"`+code+`","password":"second horse battery"}`, "", 200, "")
			same(drain(), "v-delete-before:forget-password-otp", "v-delete-after:forget-password-otp", "on-password-reset")

			// An observed change whose after hook fails discards the spend and keeps the address.
			observed := instance(store, func(o *auth.Options, e *auth.EmailOTPOptions) {
				o.BeforeEmailVerification = func(ctx context.Context, _ auth.User, _ *http.Request) error {
					return note(ctx, "before-email-verification", nil)
				}
				e.ChangeEmail.Enabled = true
			})
			w := call(observed, "/sign-up/email", `{"email":"move@codes.example","password":"correct horse battery","name":"Ada"}`, "", 200, "")
			var cookie string
			for _, c := range w.Result().Cookies() {
				if strings.HasSuffix(c.Name, "session_token") {
					cookie = c.Name + "=" + c.Value
				}
			}
			call(observed, "/email-otp/request-email-change", `{"newEmail":"moved@codes.example"}`, cookie, 200, "")
			mu.Lock()
			code = mail[len(mail)-1]
			mu.Unlock()
			drain()
			setProbe("", "")
			setFail("v-delete-after:change-email-otp", errors.New("late"))
			call(observed, "/email-otp/change-email", `{"newEmail":"moved@codes.example","otp":"`+code+`"}`, cookie, 500, "")
			setFail("v-delete-after:change-email-otp", nil)
			same(drain(), "v-delete-before:change-email-otp", "v-delete-after:change-email-otp")
			if _, err := store.FindAccountUser(ctx, "move@codes.example"); err != nil {
				t.Fatal("a failed observed change moved the address:", err)
			}
		})
	}
}
