package sqlstore

import (
	"context"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// Phone code verification hooks run on SQLite, PostgreSQL and MySQL,
// outside the store's transaction and with the stored row's ID. Around a
// planned sign-up the code's delete before hooks run first and its after
// hooks before the user's and session's; a wrong guess is counted once, and
// concurrent verifications of one code run one delete after hook.
func TestVerificationHooksAroundPhoneCodes(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			opened, other := phoneStores(t, dialect)
			store := opened.(*Store)
			var mu sync.Mutex
			var events []string
			var sms []string
			var created auth.VerificationRecord
			// probe is the number a guess locks; its hooks read it through the
			// store, which takes the same lock, so they must run outside the
			// store's transaction. Concurrent guesses clear it.
			probe := ""
			note := func(ctx context.Context, event string, rec *auth.VerificationRecord) error {
				mu.Lock()
				events = append(events, event)
				if rec != nil && strings.HasPrefix(event, "v-create") {
					created = *rec
				}
				number := probe
				mu.Unlock()
				if rec != nil && number != "" && !strings.HasPrefix(event, "v-create") {
					read, cancel := context.WithTimeout(ctx, 5*time.Second)
					defer cancel()
					purpose := auth.PhoneVerify
					if rec.Identifier == "phone-number-reset" {
						purpose = auth.PhonePasswordReset
					}
					if _, err := store.ReadPhoneOTP(read, number, purpose); err != nil {
						t.Error("the number was locked during", event, err)
					}
				}
				return nil
			}
			drain := func() []string {
				mu.Lock()
				defer mu.Unlock()
				out := events
				events = nil
				return out
			}
			same := func(got []string, want ...string) {
				t.Helper()
				if len(got)+len(want) > 0 && !reflect.DeepEqual(got, want) {
					t.Fatalf("hooks ran as %q, want %q", got, want)
				}
			}
			setProbe := func(number string) {
				mu.Lock()
				defer mu.Unlock()
				probe = number
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
			instance := func(s auth.Store) *auth.Auth {
				t.Helper()
				capture := func(_ context.Context, m auth.PhoneOTPMessage) error {
					mu.Lock()
					defer mu.Unlock()
					sms = append(sms, m.Code)
					return nil
				}
				phone, err := auth.NewPhoneNumber(auth.PhoneNumberOptions{SendOTP: capture, SendPasswordResetOTP: capture,
					SignUpOnVerification: &auth.PhoneSignUpOptions{GetTempEmail: func(n string) string { return strings.TrimPrefix(n, "+") + "@phone.example" }}})
				if err != nil {
					t.Fatal(err)
				}
				off := false
				a, err := auth.New(auth.Options{Store: s, BaseURL: "https://auth.example", Secret: strings.Repeat("s", 40), RateLimit: &off, EmailAndPassword: true,
					RevokeSessionsOnPasswordReset: true, Plugins: []auth.Plugin{phone}, DatabaseHooks: hooks})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			a, b := instance(opened), instance(other)
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
			call := func(path, body, cookie string, status int, want string) *httptest.ResponseRecorder {
				t.Helper()
				w := serve(a, path, body, cookie)
				if w.Code != status || !strings.Contains(w.Body.String(), want) {
					t.Fatalf("%s answered %d %s, want %d with %q", path, w.Code, w.Body.String(), status, want)
				}
				return w
			}
			lastSMS := func() string {
				mu.Lock()
				defer mu.Unlock()
				return sms[len(sms)-1]
			}
			send := func(number string) string {
				t.Helper()
				call("/phone-number/send-otp", `{"phoneNumber":"`+number+`"}`, "", 200, "")
				return lastSMS()
			}
			verify := func(number, code, extra, cookie string, status int, want string) {
				t.Helper()
				setProbe(number)
				call("/phone-number/verify", `{"phoneNumber":"`+number+`","code":"`+code+`"`+extra+`}`, cookie, status, want)
			}
			rowValue := func(identifier string) (id, value string) {
				t.Helper()
				if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "id","value" FROM "verification" WHERE "identifier"=?`), identifier).Scan(&id, &value); err != nil {
					t.Fatal(err)
				}
				return id, value
			}

			// The record names the stored row, and a planned wrong guess is counted once.
			code := send("+15552000001")
			same(drain(), "v-create-after:phone-number-otp")
			if id, value := rowValue("phone-number-otp-+15552000001"); created.ID != id || !strings.HasSuffix(value, ":0") {
				t.Fatal("the hook saw ID", created.ID, "for the row", id, value)
			}
			sent := created
			verify("+15552000001", "nope", "", "", 400, "INVALID_OTP")
			same(drain(), "v-delete-before:phone-number-otp", "v-update-after:phone-number-otp")
			if _, value := rowValue("phone-number-otp-+15552000001"); !strings.HasSuffix(value, ":1") {
				t.Fatal("the wrong guess was counted as", value)
			}
			// A planned sign-up: the code's hooks wrap the user's and session's.
			verify("+15552000001", code, "", "", 200, `"status":true`)
			same(drain(), "v-delete-before:phone-number-otp", "user-before", "session-before", "v-delete-after:phone-number-otp", "user-after", "session-after")
			if created != sent {
				t.Fatal("the guess saw a record that was created", created, sent)
			}

			// Concurrent verifications of one phone code run one delete after hook.
			code = send("+15552000002")
			drain()
			setProbe("")
			var wg sync.WaitGroup
			statuses := make(chan int, 6)
			for i := range 6 {
				wg.Go(func() {
					statuses <- serve([]*auth.Auth{a, b}[i%2], "/phone-number/verify", `{"phoneNumber":"+15552000002","code":"`+code+`"}`, "").Code
				})
			}
			wg.Wait()
			close(statuses)
			signedUp := 0
			for status := range statuses {
				if status == 200 {
					signedUp++
				}
			}
			spends := 0
			for _, e := range drain() {
				if e == "v-delete-after:phone-number-otp" {
					spends++
				}
			}
			if signedUp != 1 || spends != 1 {
				t.Fatal("six concurrent verifications signed up", signedUp, "times with", spends, "spends")
			}

			// A reset's hooks run after the revocation it commits.
			w := call("/sign-up/email", `{"email":"ada@phone.example","password":"correct horse battery","name":"Ada"}`, "", 200, "")
			var cookie string
			for _, c := range w.Result().Cookies() {
				if strings.HasSuffix(c.Name, "session_token") {
					cookie = c.Name + "=" + c.Value
				}
			}
			code = send("+15552000003")
			drain()
			verify("+15552000003", code, `,"updatePhoneNumber":true`, cookie, 200, `"status":true`)
			same(drain(), "v-delete-before:phone-number-otp", "v-delete-after:phone-number-otp")
			ada, err := store.FindAccountUser(ctx, "ada@phone.example")
			if err != nil {
				t.Fatal(err)
			}
			call("/phone-number/request-password-reset", `{"phoneNumber":"+15552000003"}`, "", 200, "")
			code = lastSMS()
			drain()
			setProbe("+15552000003")
			call("/phone-number/reset-password", `{"phoneNumber":"+15552000003","otp":"`+code+`","newPassword":"second horse battery"}`, "", 200, "")
			same(drain(), "v-delete-before:phone-number-reset", "v-delete-after:phone-number-reset")
			if sessions, err := store.ListSessions(ctx, ada.ID); err != nil || len(sessions) != 0 {
				t.Fatal("the reset kept sessions", sessions, err)
			}
		})
	}
}
