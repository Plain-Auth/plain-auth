package sqlstore

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/plugins/lastlogin"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestPersistedLastLoginMethod(t *testing.T) {
	type loginStore interface {
		auth.Store
		lastlogin.Store
	}
	for _, kind := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(kind, func(t *testing.T) {
			ctx := t.Context()
			var store loginStore
			if kind == "memory" {
				store = memory.New()
			} else {
				ddl, err := schema.Generate(kind, []string{"last-login-method"})
				if err != nil {
					t.Fatal(err)
				}
				db, err := OpenWithSchema(ctx, kind, organizationTestDSN(t, kind), ddl)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				store = db
			}
			const origin = "https://example.test"
			plugin := lastlogin.New(lastlogin.Options{Database: store, Allow: func(*http.Request, string) bool { return false }, Resolve: func(r *http.Request) string {
				if strings.HasSuffix(r.URL.Path, "/sign-in/email") {
					return "password"
				}
				return ""
			}})
			opts := auth.Options{BaseURL: origin, Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, Plugins: []auth.Plugin{plugin}}
			a, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			sign := func(path string) *http.Cookie {
				r := httptest.NewRequest("POST", origin+"/api/auth/"+path, strings.NewReader(`{"name":"Test","email":"mail@example.test","password":"fixture-password"}`))
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatal(w.Code, w.Body)
				}
				var session *http.Cookie
				for _, c := range w.Result().Cookies() {
					if strings.Contains(c.Name, "last_used_login_method") {
						t.Fatal("consent-gated cookie was emitted")
					}
					if strings.HasSuffix(c.Name, ".session_token") {
						session = c
					}
				}
				if session == nil {
					t.Fatal("missing session")
				}
				return session
			}
			read := func(a *auth.Auth, c *http.Cookie) auth.User {
				r := httptest.NewRequest("GET", origin+"/api/auth/get-session", nil)
				r.AddCookie(c)
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var row auth.SessionResult
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &row) != nil {
					t.Fatal("session read", w.Code, w.Body)
				}
				return row.User
			}
			first := sign("sign-up/email")
			user := read(a, first)
			if user.LastLoginMethod == nil || *user.LastLoginMethod != "email" {
				t.Fatal("missing persisted sign-up method")
			}
			second := sign("sign-in/email")
			again := read(a, first)
			if again.LastLoginMethod == nil || *again.LastLoginMethod != "password" {
				t.Fatal("second session did not update account method")
			}
			if err := store.DeleteSession(ctx, a.VerifySignedSessionToken(second.Value)); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveSessionLoginMethod(ctx, a.VerifySignedSessionToken(second.Value), "stale", time.Now()); err != nil {
				t.Fatal(err)
			}
			if method, err := store.UserLoginMethod(ctx, user.ID); err != nil || method != "password" {
				t.Fatal("revoked session changed the recorded method", err)
			}
			opts.Plugins = nil
			bare, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			if read(bare, first).LastLoginMethod != nil {
				t.Fatal("disabled plugin exposed login method")
			}
		})
	}
}
