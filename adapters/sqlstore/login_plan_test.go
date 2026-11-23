package sqlstore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/schema"
)

// Plan a magic-link sign-in on three engines: the dry run stores nothing,
// the approved run stores the hooks' edits, a skip leaves the link usable,
// and a user stored while the hooks run is signed in instead.
func TestLoginPlanOnSQL(t *testing.T) {
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
			store, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), nil, schema.Options{})
			must(err)
			t.Cleanup(func() { store.Close() })
			var token string
			magic, err := auth.NewMagicLink(auth.MagicLinkOptions{Send: func(_ context.Context, m auth.MagicLinkMessage) error { token = m.Token; return nil }})
			must(err)
			var before func(*auth.UserRecord) error
			users := 0
			off := false
			host, err := auth.New(auth.Options{
				BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), RateLimit: &off, Plugins: []auth.Plugin{magic},
				DatabaseHooks: auth.DatabaseHooks{User: auth.ModelHooks[auth.UserRecord]{Create: auth.OperationHooks[auth.UserRecord]{
					Before: func(ctx context.Context, u *auth.UserRecord, _ *auth.HookContext) error {
						// The dry run has rolled back, so the user is not stored yet.
						if _, err := store.FindAccountUser(ctx, u.Email); err == nil {
							t.Error("a dry run stored its user")
						}
						u.Name = "Planned"
						if before != nil {
							return before(u)
						}
						return nil
					},
					After: func(context.Context, auth.UserRecord, *auth.HookContext) error { users++; return nil },
				}}},
			})
			must(err)
			signIn := func(email string) string {
				t.Helper()
				r := httptest.NewRequest("POST", "https://auth.example/api/auth/sign-in/magic-link", strings.NewReader(`{"email":"`+email+`","callbackURL":"/done","errorCallbackURL":"/failed"}`))
				r.Header = http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
				w := httptest.NewRecorder()
				host.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatal("magic link request failed", w.Code, w.Body)
				}
				return token
			}
			verify := func(link string) string {
				t.Helper()
				w := httptest.NewRecorder()
				host.ServeHTTP(w, httptest.NewRequest("GET", "https://auth.example/api/auth/magic-link/verify?token="+url.QueryEscape(link)+"&callbackURL=/done&errorCallbackURL=/failed", nil))
				return w.Header().Get("Location")
			}

			// The approved run stores the hook's edit once.
			verify(signIn("ada@example.com"))
			stored, err := store.FindAccountUser(ctx, "ada@example.com")
			must(err)
			if stored.Name != "Planned" || users != 1 {
				t.Fatal("the planned user was not stored", stored.Name, users)
			}

			// A skip stores nothing and leaves the link usable.
			before = func(*auth.UserRecord) error { return auth.ErrSkipWrite }
			link := signIn("grace@example.com")
			if got := verify(link); !strings.Contains(got, "error=failed_to_create_user") {
				t.Fatal("a skipped user did not fail the sign-in", got)
			}
			before = nil
			if got := verify(link); !strings.HasSuffix(got, "/done") {
				t.Fatal("a skipped sign-in consumed its link", got)
			}

			// A user stored while the hooks run is signed in instead of created again.
			before = func(u *auth.UserRecord) error {
				now := time.Now().UTC().Truncate(time.Millisecond)
				return store.CreateUser(ctx, auth.User{ID: "racer", Name: "Racer", Email: u.Email, EmailVerified: true, CreatedAt: now, UpdatedAt: now}, "", nil)
			}
			if got := verify(signIn("race@example.com")); !strings.HasSuffix(got, "/done") {
				t.Fatal("the raced sign-in failed", got)
			}
			before = nil
			sessions, err := store.ListSessions(ctx, "racer")
			must(err)
			if len(sessions) != 1 || users != 2 {
				t.Fatal("the raced sign-in did not sign in the stored user", len(sessions), users)
			}
		})
	}
}
