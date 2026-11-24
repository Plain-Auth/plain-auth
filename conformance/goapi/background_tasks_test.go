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
