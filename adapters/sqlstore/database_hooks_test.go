package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/schema"
)

// Run user and session create hooks, and session update and delete hooks,
// that use the Auth and the store on three engines without holding a write
// transaction; fire once for concurrent sign-ups of one email; and apply to
// anonymous sign-in and the admin bootstrap.
func TestDatabaseCreateHooksOnSQL(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			store, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), []string{"admin", "anonymous"}, schema.Options{})
			must(err)
			t.Cleanup(func() { store.Close() })
			anonymous, err := auth.NewAnonymous(auth.AnonymousOptions{})
			must(err)
			admin, err := auth.NewAdmin(auth.AdminOptions{})
			must(err)
			var created atomic.Int32
			var mu sync.Mutex
			var events []string
			record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
			var self *auth.Auth
			off := false
			self, err = auth.New(auth.Options{
				BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
				Plugins: []auth.Plugin{anonymous},
				DatabaseHooks: auth.DatabaseHooks{
					User: auth.ModelHooks[auth.UserRecord]{Create: auth.OperationHooks[auth.UserRecord]{
						Before: func(ctx context.Context, u *auth.UserRecord, c *auth.HookContext) error {
							// Reading through the store inside a hook must not wait on a write transaction.
							if _, err := store.FindAccountUser(ctx, u.Email); err != nil && !errors.Is(err, auth.ErrNotFound) {
								return err
							}
							if c != nil {
								if _, err := self.GetSession(ctx, c.Request.Header); err != nil {
									return err
								}
							}
							u.Name = strings.ToUpper(u.Name)
							return nil
						},
						After: func(ctx context.Context, u auth.UserRecord, _ *auth.HookContext) error {
							created.Add(1)
							stored, err := store.FindAccountUser(ctx, u.Email)
							if err != nil {
								return err
							}
							record("user:" + stored.Name)
							return nil
						},
					}},
					Session: auth.ModelHooks[auth.SessionRecord]{Create: auth.OperationHooks[auth.SessionRecord]{
						After: func(ctx context.Context, s auth.SessionRecord, _ *auth.HookContext) error {
							// The new session is already readable from another connection.
							if _, _, err := store.Session(ctx, s.Token); err != nil {
								return err
							}
							record("session")
							return nil
						},
					}},
				},
			})
			must(err)
			post := func(target, body string) *httptest.ResponseRecorder {
				r := httptest.NewRequest("POST", "https://auth.example/api/auth"+target, strings.NewReader(body))
				r.Header = http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
				w := httptest.NewRecorder()
				self.ServeHTTP(w, r)
				return w
			}

			// Hooks that use the store finish well within the deadline on every engine.
			if w := post("/sign-up/email", `{"email":"ada@example.com","password":"correct horse battery","name":"Ada"}`); w.Code != 200 {
				t.Fatal("sign-up failed", w.Code, w.Body)
			}
			if w := post("/sign-in/anonymous", `{}`); w.Code != 200 {
				t.Fatal("anonymous sign-in failed", w.Code, w.Body)
			}
			mu.Lock()
			got := strings.Join(events, ",")
			events = nil
			mu.Unlock()
			if got != "user:ADA,session,user:ANONYMOUS,session" {
				t.Fatal("unexpected hooks", got)
			}

			// Concurrent sign-ups of one new email store one user and fire one after hook.
			created.Store(0)
			var wg sync.WaitGroup
			for i := range 6 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					post("/sign-up/email", fmt.Sprintf(`{"email":"grace@example.com","password":"correct horse battery","name":"Grace %d"}`, i))
				}()
			}
			wg.Wait()
			if n := created.Load(); n != 1 {
				t.Fatalf("concurrent sign-ups fired %d user after hooks", n)
			}

			// Session update and delete hooks may also read through the store on every engine.
			every := time.Duration(0)
			var changes []string
			note := func(e string) { mu.Lock(); changes = append(changes, e); mu.Unlock() }
			sessions, err := auth.New(auth.Options{
				BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off, SessionUpdateAge: &every,
				DatabaseHooks: auth.DatabaseHooks{Session: auth.ModelHooks[auth.SessionRecord]{
					Update: auth.OperationHooks[auth.SessionRecord]{After: func(ctx context.Context, s auth.SessionRecord, _ *auth.HookContext) error {
						stored, _, err := store.Session(ctx, s.Token)
						if err != nil {
							return err
						}
						note("refreshed:" + fmt.Sprint(stored.ExpiresAt.Equal(s.ExpiresAt)))
						return nil
					}},
					Delete: auth.OperationHooks[auth.SessionRecord]{
						Before: func(ctx context.Context, s *auth.SessionRecord, _ *auth.HookContext) error {
							_, err := store.ListSessions(ctx, s.UserID)
							return err
						},
						After: func(ctx context.Context, s auth.SessionRecord, _ *auth.HookContext) error {
							_, _, err := store.Session(ctx, s.Token)
							note("deleted:" + fmt.Sprint(errors.Is(err, auth.ErrNotFound)))
							return nil
						},
					},
				}},
			})
			must(err)
			signIn := func() http.Header {
				r := httptest.NewRequest("POST", "https://auth.example/api/auth/sign-in/email", strings.NewReader(`{"email":"ada@example.com","password":"correct horse battery"}`))
				r.Header = http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
				w := httptest.NewRecorder()
				sessions.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatal("sign-in failed", w.Code, w.Body)
				}
				h := http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
				for _, c := range w.Result().Cookies() {
					h.Add("Cookie", c.Name+"="+c.Value)
				}
				return h
			}
			send := func(h http.Header, method, target string) int {
				r := httptest.NewRequest(method, "https://auth.example/api/auth"+target, strings.NewReader(`{}`))
				r.Header = h.Clone()
				w := httptest.NewRecorder()
				sessions.ServeHTTP(w, r)
				return w.Code
			}
			browser := signIn()
			signIn()
			if send(browser, "GET", "/get-session") != 200 || send(browser, "POST", "/revoke-other-sessions") != 200 || send(browser, "POST", "/sign-out") != 200 {
				t.Fatal("a session request failed")
			}
			mu.Lock()
			got = strings.Join(changes, ",")
			mu.Unlock()
			if !strings.HasPrefix(got, "refreshed:true,deleted:true") || !strings.HasSuffix(got, "deleted:true") || strings.Contains(got, "false") {
				t.Fatal("unexpected session hooks", got)
			}

			// The admin bootstrap creates its user through the hooks.
			bootstrap, err := auth.New(auth.Options{
				BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true,
				Plugins: []auth.Plugin{admin},
				DatabaseHooks: auth.DatabaseHooks{User: auth.ModelHooks[auth.UserRecord]{Create: auth.OperationHooks[auth.UserRecord]{
					Before: func(_ context.Context, u *auth.UserRecord, c *auth.HookContext) error {
						if c != nil {
							return errors.New("a Go call received an endpoint context")
						}
						u.Name = "Root Admin"
						return nil
					},
				}}},
			})
			if err == nil || !strings.Contains(err.Error(), "admin") {
				t.Fatal("user create hooks were accepted with the admin plugin", err)
			}
			bootstrap, err = auth.New(auth.Options{
				BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true,
				DatabaseHooks: auth.DatabaseHooks{User: auth.ModelHooks[auth.UserRecord]{Create: auth.OperationHooks[auth.UserRecord]{
					Before: func(_ context.Context, u *auth.UserRecord, c *auth.HookContext) error {
						if c != nil {
							return errors.New("a Go call received an endpoint context")
						}
						u.Name = "Root Admin"
						return nil
					},
				}}},
			})
			must(err)
			root, err := bootstrap.BootstrapAdmin(ctx, "Root", "root@example.com", "a long administrator password")
			must(err)
			stored, err := store.FindAccountUser(ctx, "root@example.com")
			must(err)
			if root.Name != "Root Admin" || stored.Name != "Root Admin" {
				t.Fatal("the bootstrap ignored the user hook", root.Name, stored.Name)
			}
		})
	}
}
