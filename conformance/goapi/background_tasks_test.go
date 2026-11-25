package goapi_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/schema"
)

// taskQueue is a BackgroundTasks runner the test drains itself.
type taskQueue struct {
	mu    sync.Mutex
	tasks []func()
}

func (q *taskQueue) Go(task func()) { q.mu.Lock(); q.tasks = append(q.tasks, task); q.mu.Unlock() }
func (q *taskQueue) drain() int {
	q.mu.Lock()
	tasks := q.tasks
	q.tasks = nil
	q.mu.Unlock()
	for _, task := range tasks {
		task()
	}
	return len(tasks)
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *lockedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buf.String() }

// With BackgroundTasks, sign-up mail and the existing-user observer run after
// the response with a context the finished request no longer cancels, and
// plugins hand their own work to the same runner.
func TestBackgroundTasksRunAfterTheResponse(t *testing.T) {
	for _, withRunner := range []bool{true, false} {
		name := "runner"
		if !withRunner {
			name = "inline"
		}
		t.Run(name, func(t *testing.T) {
			store, err := sqlite.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			var mu sync.Mutex
			var events []string
			record := func(event string) { mu.Lock(); events = append(events, event); mu.Unlock() }
			seen := func() string { mu.Lock(); defer mu.Unlock(); return strings.Join(events, ",") }
			live := func(ctx context.Context, r *http.Request) string {
				if ctx.Err() != nil || r == nil || r.Context().Err() != nil || r.Header.Get("X-Request-Id") != "req-1" {
					return "cancelled"
				}
				return "live"
			}
			queue := &taskQueue{}
			logs := &lockedBuffer{}
			detached := make(chan string, 1)
			server := httptest.NewUnstartedServer(nil)
			base := "http://" + server.Listener.Addr().String()
			opts := auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: base, EmailAndPassword: true, RateLimit: new(bool),
				RequireEmailVerification: true, Logger: slog.New(slog.NewJSONHandler(logs, nil)),
				SendVerificationEmail: func(ctx context.Context, m auth.MailLink) error {
					record("verification:" + live(ctx, m.Request))
					return nil
				},
				OnExistingUserSignUp: func(ctx context.Context, _ auth.User, r *http.Request) error {
					record("existing:" + live(ctx, r))
					return nil
				},
				Plugins: []auth.Plugin{{ID: "deferred", Endpoints: []auth.Endpoint{{Method: "GET", Path: "/deferred", Handler: func(c auth.EndpointContext) (any, error) {
					ctx := c.Request.Context()
					// Copy the request before the work leaves the request.
					meta := c.RequestMetadata()
					c.Auth.RunInBackground(ctx, func(ctx context.Context) {
						detached <- "background:" + live(ctx, meta.WithContext(ctx))
					})
					c.Auth.RunInBackgroundOrAwait(ctx, func(context.Context) error {
						record("awaited")
						return errors.New("private task detail")
					})
					if withRunner {
						// Inline, a panic propagates as without the helper.
						c.Auth.RunInBackgroundOrAwait(ctx, func(context.Context) error { panic("private panic detail") })
					}
					return map[string]bool{"ok": true}, nil
				}}}}},
			}
			if withRunner {
				opts.BackgroundTasks = queue.Go
			}
			node, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			server.Config.Handler = node
			server.Start()
			defer server.Close()
			send := func(method, path, body string) {
				t.Helper()
				r, _ := http.NewRequest(method, base+"/api/auth"+path, strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-Request-Id", "req-1")
				res, err := http.DefaultClient.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				data, _ := io.ReadAll(res.Body)
				res.Body.Close()
				if res.StatusCode != 200 {
					t.Fatalf("%s %s answered %d %s", method, path, res.StatusCode, data)
				}
			}
			expect := func(queued int, before, after string) {
				t.Helper()
				if got := seen(); got != before {
					t.Fatalf("before the queue ran: %q, want %q", got, before)
				}
				if got := queue.drain(); got != queued {
					t.Fatalf("%d tasks queued, want %d", got, queued)
				}
				if got := seen(); got != after {
					t.Fatalf("after the queue ran: %q, want %q", got, after)
				}
			}
			signUp := `{"name":"Person","email":"person@example.org","password":"a background test password"}`
			send("POST", "/sign-up/email", signUp)
			send("POST", "/sign-up/email", signUp)
			if withRunner {
				expect(2, "", "verification:live,existing:live")
			} else {
				expect(0, "verification:live,existing:live", "verification:live,existing:live")
			}
			send("GET", "/deferred", "")
			if withRunner {
				expect(3, "verification:live,existing:live", "verification:live,existing:live,awaited")
			} else {
				expect(0, "verification:live,existing:live,awaited", "verification:live,existing:live,awaited")
			}
			select {
			case got := <-detached:
				if got != "background:live" {
					t.Fatal("RunInBackground ran with", got)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("RunInBackground never ran")
			}
			// Failures and handed-off panics are logged without their details.
			out, failures := logs.String(), 1
			if withRunner {
				failures = 2
			}
			if strings.Count(out, "Background task failed") != failures || strings.Contains(out, "private") {
				t.Fatalf("task failures were logged as %s", out)
			}
		})
	}
}

// A runner that panics loses the task, which is logged, and the request
// still succeeds.
func TestBackgroundTasksRunnerPanic(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	logs := &lockedBuffer{}
	sent := false
	node, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example", EmailAndPassword: true, RateLimit: new(bool),
		RequireEmailVerification: true, Logger: slog.New(slog.NewJSONHandler(logs, nil)),
		SendVerificationEmail: func(context.Context, auth.MailLink) error { sent = true; return nil },
		BackgroundTasks:       func(func()) { panic("runner unavailable") }})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://auth.example/api/auth/sign-up/email", strings.NewReader(`{"name":"Person","email":"person@example.org","password":"a background test password"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	node.ServeHTTP(w, r)
	if w.Code != 200 || sent || !strings.Contains(logs.String(), "Could not start background task") {
		t.Fatal(w.Code, sent, logs.String())
	}
}

// Work started from inside a task goes to the runner too, so the host can
// wait for it, and the task's writes reach database hooks as direct calls,
// not as the finished endpoint call.
func TestBackgroundTasksNestedWorkAndHooks(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	queue := &taskQueue{}
	var mu sync.Mutex
	var seen []string
	record := func(event string) { mu.Lock(); seen = append(seen, event); mu.Unlock() }
	node, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example", EmailAndPassword: true, RateLimit: new(bool),
		BackgroundTasks: queue.Go,
		DatabaseHooks: auth.DatabaseHooks{User: auth.ModelHooks[auth.UserRecord]{Update: auth.OperationHooks[auth.UserRecord]{
			After: func(_ context.Context, _ auth.UserRecord, c *auth.HookContext) error {
				if c == nil {
					record("hook:direct")
				} else {
					record("hook:" + c.Path)
				}
				return nil
			},
		}}},
		Plugins: []auth.Plugin{{ID: "rename", Endpoints: []auth.Endpoint{{Method: "POST", Path: "/rename-later", Handler: func(c auth.EndpointContext) (any, error) {
			headers := c.Request.Header.Clone()
			c.Auth.RunInBackgroundOrAwait(c.Request.Context(), func(ctx context.Context) error {
				name := "Renamed"
				if err := c.Auth.UpdateUser(ctx, headers, auth.ProfileUpdate{Name: &name}); err != nil {
					return err
				}
				c.Auth.RunInBackground(ctx, func(context.Context) { record("nested") })
				return nil
			})
			return map[string]bool{"ok": true}, nil
		}}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://auth.example/api/auth/sign-up/email", strings.NewReader(`{"name":"Person","email":"person@example.org","password":"a background test password"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	node.ServeHTTP(w, r)
	cookie, _, _ := strings.Cut(w.Header().Get("Set-Cookie"), ";")
	if w.Code != 200 || cookie == "" {
		t.Fatal("sign-up", w.Code, w.Body.String())
	}
	r = httptest.NewRequest("POST", "https://auth.example/api/auth/rename-later", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://auth.example")
	r.Header.Set("Cookie", cookie)
	w = httptest.NewRecorder()
	node.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if queue.drain() != 1 || queue.drain() != 1 || queue.drain() != 0 {
		t.Fatal("the nested work did not go to the runner")
	}
	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(seen, ","); got != "hook:direct,nested" {
		t.Fatalf("the task's work was seen as %q", got)
	}
}

// Over HTTP a failed delivery is logged and the response is the one a
// successful send gives, as in the reference, so it reveals nothing about
// the address. A direct Go call still returns the sender's error.
func TestDeliveryFailuresAreLoggedOverHTTP(t *testing.T) {
	failure := errors.New("private mail credentials")
	failing := func(context.Context, auth.MailLink) error { return failure }
	store, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"phone-number"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	emailOTP, err := auth.NewEmailOTP(auth.EmailOTPOptions{Send: func(context.Context, auth.EmailOTPMessage) error { return failure }})
	if err != nil {
		t.Fatal(err)
	}
	phone, err := auth.NewPhoneNumber(auth.PhoneNumberOptions{SendOTP: func(context.Context, auth.PhoneOTPMessage) error { return failure }})
	if err != nil {
		t.Fatal(err)
	}
	logs := &lockedBuffer{}
	queue := &taskQueue{}
	opts := auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example", EmailAndPassword: true, RateLimit: new(bool),
		RequireEmailVerification: true, SendVerificationOnSignIn: true, DeleteUserEnabled: true, ChangeEmailEnabled: true,
		SendVerificationEmail: failing, SendResetPassword: failing, SendDeleteAccountVerification: failing,
		Logger: slog.New(slog.NewJSONHandler(logs, nil)), Plugins: []auth.Plugin{emailOTP, phone}}
	node, err := auth.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	call := func(node http.Handler, path, body, cookie string) (int, string) {
		t.Helper()
		r := httptest.NewRequest("POST", "https://auth.example/api/auth"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://auth.example")
		if cookie != "" {
			r.Header.Set("Cookie", cookie)
		}
		w := httptest.NewRecorder()
		node.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	ctx := t.Context()
	const email, password = "person@example.org", "a background test password"
	if _, err := node.SignUpEmail(ctx, auth.SignUpInput{Name: "Person", Email: email, Password: password}, auth.RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path, body string
		status     int
		code, log  string
	}{
		{"/request-password-reset", `{"email":"` + email + `"}`, 200, "", "Could not deliver password reset email"},
		{"/sign-in/email", `{"email":"` + email + `","password":"` + password + `"}`, 403, "EMAIL_NOT_VERIFIED", "Could not deliver sign-in verification email"},
		{"/email-otp/send-verification-otp", `{"email":"` + email + `","type":"email-verification"}`, 200, "", "Could not deliver email OTP"},
		{"/forget-password/email-otp", `{"email":"` + email + `"}`, 200, "", "Could not deliver email OTP"},
	} {
		status, body := call(node, tc.path, tc.body, "")
		if status != tc.status || !strings.Contains(body, tc.code) || !strings.Contains(logs.String(), tc.log) {
			t.Fatalf("%s answered %d %s; logs %s", tc.path, status, body, logs.String())
		}
	}
	// /send-verification-email still waits for its sender and reports it.
	if status, _ := call(node, "/send-verification-email", `{"email":"`+email+`"}`, ""); status != 500 {
		t.Fatal("a failed /send-verification-email answered", status)
	}
	// Direct calls return the sender's error.
	if err := node.RequestPasswordReset(ctx, email, ""); !errors.Is(err, failure) {
		t.Fatal("a direct reset request returned", err)
	}
	if _, err := node.SignInEmail(ctx, auth.SignInInput{Email: email, Password: password}, auth.RequestMeta{}); !errors.Is(err, failure) {
		t.Fatal("a direct sign-in returned", err)
	}
	if err := node.SendEmailOTP(ctx, email, auth.OTPVerifyEmail); !errors.Is(err, failure) {
		t.Fatal("a direct email OTP send returned", err)
	}
	if strings.Contains(logs.String(), "private") || strings.Contains(logs.String(), email) {
		t.Fatal("a delivery failure leaked into the logs:", logs.String())
	}

	// Account deletion and email change answer as if their mail went out.
	sessionOpts := opts
	sessionOpts.RequireEmailVerification, sessionOpts.Plugins = false, nil
	sessions, err := auth.New(sessionOpts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://auth.example/api/auth/sign-in/email", strings.NewReader(`{"email":"`+email+`","password":"`+password+`"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	sessions.ServeHTTP(w, r)
	cookie, _, _ := strings.Cut(w.Header().Get("Set-Cookie"), ";")
	if w.Code != 200 || cookie == "" {
		t.Fatal("sign-in", w.Code, w.Body.String())
	}
	for path, wantLog := range map[string]string{"/delete-user": "Could not deliver account deletion email", "/change-email": "Could not deliver email change verification"} {
		body := `{}`
		if path == "/change-email" {
			body = `{"newEmail":"renamed@example.org"}`
		}
		if status, response := call(sessions, path, body, cookie); status != 200 || !strings.Contains(logs.String(), wantLog) {
			t.Fatalf("%s answered %d %s", path, status, response)
		}
	}

	// Phone /send-otp reports its failure without a runner and hands the
	// send off with one.
	const number = "+15555550100"
	if status, _ := call(node, "/phone-number/send-otp", `{"phoneNumber":"`+number+`"}`, ""); status != 500 {
		t.Fatal("a failed /send-otp without a runner answered", status)
	}
	opts.BackgroundTasks = queue.Go
	deferred, err := auth.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if status, body := call(deferred, "/phone-number/send-otp", `{"phoneNumber":"`+number+`"}`, ""); status != 200 || queue.drain() != 1 {
		t.Fatal("/send-otp with a runner answered", status, body)
	}
	// With a runner a reset for a registered address is queued, and an
	// unknown address queues nothing.
	if status, _ := call(deferred, "/request-password-reset", `{"email":"`+email+`"}`, ""); status != 200 || queue.drain() != 1 {
		t.Fatal("a reset request was not handed off")
	}
	if status, _ := call(deferred, "/request-password-reset", `{"email":"nobody@example.org"}`, ""); status != 200 || queue.drain() != 0 {
		t.Fatal("an unknown address was handled differently")
	}
	// The sign-in verification mail, an email code, the deletion mail and
	// the email change mail are each handed off once, with the usual answer.
	for _, tc := range []struct {
		path, body string
		status     int
	}{
		{"/sign-in/email", `{"email":"` + email + `","password":"` + password + `"}`, 403},
		{"/email-otp/send-verification-otp", `{"email":"` + email + `","type":"email-verification"}`, 200},
	} {
		if status, body := call(deferred, tc.path, tc.body, ""); status != tc.status || queue.drain() != 1 {
			t.Fatalf("%s with a runner answered %d %s", tc.path, status, body)
		}
	}
	sessionOpts.BackgroundTasks = queue.Go
	deferredSessions, err := auth.New(sessionOpts)
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{"/delete-user": `{}`, "/change-email": `{"newEmail":"moved@example.org"}`} {
		if status, response := call(deferredSessions, path, body, cookie); status != 200 || queue.drain() != 1 {
			t.Fatalf("%s with a runner answered %d %s", path, status, response)
		}
	}
}

// Every email-change delivery, the verify-email confirmation step, the
// email-change code and a code sent in place of the verification email log
// a failed send over HTTP and answer as if it went out.
func TestEmailChangeDeliveryFailuresAreLogged(t *testing.T) {
	failure := errors.New("private mail credentials")
	var mu sync.Mutex
	var links []string
	capture := func(_ context.Context, m auth.MailLink) error {
		mu.Lock()
		links = append(links, m.URL)
		mu.Unlock()
		return failure
	}
	lastLink := func() string { mu.Lock(); defer mu.Unlock(); return links[len(links)-1] }
	newNode := func(t *testing.T, opts auth.Options) (*sqlite.Store, *auth.Auth, *lockedBuffer) {
		t.Helper()
		store, err := sqlite.Open(":memory:")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		logs := &lockedBuffer{}
		opts.Store, opts.Secret, opts.BaseURL, opts.EmailAndPassword, opts.RateLimit = store, strings.Repeat("s", 32), "https://auth.example", true, new(bool)
		opts.ChangeEmailEnabled, opts.SendVerificationEmail, opts.Logger = true, capture, slog.New(slog.NewJSONHandler(logs, nil))
		node, err := auth.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		return store, node, logs
	}
	call := func(node http.Handler, method, target, body, cookie string) (int, string) {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://auth.example")
		r.Header.Set("Cookie", cookie)
		w := httptest.NewRecorder()
		node.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	signUp := func(t *testing.T, node http.Handler, email string) string {
		t.Helper()
		r := httptest.NewRequest("POST", "https://auth.example/api/auth/sign-up/email", strings.NewReader(`{"name":"Person","email":"`+email+`","password":"a background test password"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		node.ServeHTTP(w, r)
		cookie, _, _ := strings.Cut(w.Header().Get("Set-Cookie"), ";")
		if w.Code != 200 || cookie == "" {
			t.Fatal("sign-up", w.Code, w.Body.String())
		}
		return cookie
	}
	expect := func(t *testing.T, logs *lockedBuffer, status int, body string, want int, log string) {
		t.Helper()
		if status != want || !strings.Contains(logs.String(), log) || strings.Contains(logs.String(), "private") {
			t.Fatalf("answered %d %s; logs %s", status, body, logs.String())
		}
	}

	t.Run("confirmation", func(t *testing.T) {
		store, node, logs := newNode(t, auth.Options{SendChangeEmailConfirmation: capture})
		cookie := signUp(t, node, "verified@example.org")
		user, err := store.FindAccountUser(t.Context(), "verified@example.org")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.VerifyAccountEmail(t.Context(), user.ID, user.Email, time.Now()); err != nil {
			t.Fatal(err)
		}
		status, body := call(node, "POST", "https://auth.example/api/auth/change-email", `{"newEmail":"new@example.org"}`, cookie)
		expect(t, logs, status, body, 200, "Could not deliver email change confirmation")
		// The confirmation link's own step sends the new inbox's link and
		// still redirects to the callback without an error.
		r := httptest.NewRequest("GET", lastLink(), nil)
		r.Header.Set("Cookie", cookie)
		w := httptest.NewRecorder()
		node.ServeHTTP(w, r)
		if location := w.Header().Get("Location"); w.Code != 302 || strings.Contains(location, "error") {
			t.Fatal("the confirmation step answered", w.Code, location, w.Body.String())
		}
		expect(t, logs, 302, "", 302, "Could not deliver email change verification")
	})
	t.Run("immediate", func(t *testing.T) {
		_, node, logs := newNode(t, auth.Options{UpdateEmailWithoutVerification: true})
		cookie := signUp(t, node, "unverified@example.org")
		status, body := call(node, "POST", "https://auth.example/api/auth/change-email", `{"newEmail":"moved@example.org"}`, cookie)
		expect(t, logs, status, body, 200, "Could not deliver verification email for a changed address")
	})
	t.Run("email OTP", func(t *testing.T) {
		emailOTP, err := auth.NewEmailOTP(auth.EmailOTPOptions{OverrideDefaultEmailVerification: true, ChangeEmail: auth.EmailOTPChangeOptions{Enabled: true},
			Send: func(context.Context, auth.EmailOTPMessage) error { return failure }})
		if err != nil {
			t.Fatal(err)
		}
		_, node, logs := newNode(t, auth.Options{Plugins: []auth.Plugin{emailOTP}})
		cookie := signUp(t, node, "otp@example.org")
		status, body := call(node, "POST", "https://auth.example/api/auth/email-otp/request-email-change", `{"newEmail":"next@example.org"}`, cookie)
		expect(t, logs, status, body, 200, "Could not deliver email OTP")
		// A code sent in place of the verification email follows the email
		// OTP rule.
		status, body = call(node, "POST", "https://auth.example/api/auth/send-verification-email", `{"email":"otp@example.org"}`, "")
		if status != 200 || strings.Count(logs.String(), "Could not deliver email OTP") < 2 {
			t.Fatalf("an overridden verification email answered %d %s; logs %s", status, body, logs.String())
		}
	})
}
