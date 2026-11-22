package sqlstore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/Stonewrit/stonewrit-auth"
	jwtplugin "github.com/Stonewrit/stonewrit-auth/plugins/jwt"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

func TestCompactSessionSQLPrivilegeBoundaries(t *testing.T) {
	checkCachePrivilegeBoundaries(t, auth.SessionCacheCompact, false)
}

func TestJOSESessionSQLPrivilegeBoundaries(t *testing.T) {
	for _, strategy := range []auth.SessionCookieCacheStrategy{auth.SessionCacheJWT, auth.SessionCacheJWE} {
		t.Run(string(strategy), func(t *testing.T) { checkCachePrivilegeBoundaries(t, strategy, false) })
	}
}

func TestSessionVersionSQLPrivilegeBoundaries(t *testing.T) {
	for _, strategy := range []auth.SessionCookieCacheStrategy{auth.SessionCacheCompact, auth.SessionCacheJWT, auth.SessionCacheJWE} {
		t.Run(string(strategy), func(t *testing.T) { checkCachePrivilegeBoundaries(t, strategy, true) })
	}
}

func checkCachePrivilegeBoundaries(t *testing.T, strategy auth.SessionCookieCacheStrategy, dynamicVersion bool) {
	t.Helper()
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			open := func(profiles ...string) *Store {
				ddl, err := schema.Generate(dialect, profiles)
				must(err)
				store, err := OpenWithSchema(ctx, dialect, dsn, ddl)
				must(err)
				t.Cleanup(func() { store.Close() })
				return store
			}
			cold := open("jwt")
			const origin = "https://cache.example.test"
			opts := auth.Options{Store: cold, BaseURL: origin, Secret: strings.Repeat("s", 32), EmailAndPassword: true, SessionCookieCache: &auth.SessionCookieCacheOptions{Strategy: strategy}}
			calls := 0
			if dynamicVersion {
				opts.SessionCookieCache.VersionFor = func(_ context.Context, session auth.Session, user auth.User) (string, error) {
					calls++
					if calls > 2 {
						t.Fatal("protected live session verification invoked a cache version callback")
					}
					return session.ID + "/" + user.ID, nil
				}
			}
			plain, err := auth.New(opts)
			must(err)
			jwt, err := jwtplugin.New(jwtplugin.Options{})
			must(err)
			opts.Store = open("jwt")
			opts.Plugins = []auth.Plugin{jwt}
			withJWT, err := auth.New(opts)
			must(err)
			route := func(server *auth.Auth, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
				method := "GET"
				if body != "" {
					method = "POST"
				}
				r := httptest.NewRequest(method, origin+"/api/auth/"+path, strings.NewReader(body))
				if body != "" {
					r.Header.Set("Content-Type", "application/json")
					r.Header.Set("Origin", origin)
				}
				for _, c := range cookies {
					r.AddCookie(c)
				}
				w := httptest.NewRecorder()
				server.ServeHTTP(w, r)
				return w
			}
			signup := route(plain, "sign-up/email", `{"name":"Before","email":"owner@example.test","password":"fixture-password"}`)
			if signup.Code != 200 {
				t.Fatal(signup.Code, signup.Body)
			}
			cookies := signup.Result().Cookies()
			read := func(server *auth.Auth) (*auth.SessionResult, *httptest.ResponseRecorder) {
				w := route(server, "get-session", "", cookies...)
				var result *auth.SessionResult
				must(json.Unmarshal(w.Body.Bytes(), &result))
				if w.Code != 200 {
					t.Fatal(w.Code)
				}
				return result, w
			}
			write := func(store *Store, query string, args ...any) {
				_, err := store.db.ExecContext(ctx, store.bind(query), args...)
				must(err)
			}
			write(cold, `UPDATE "user" SET "name"=? WHERE "email"=?`, "Live", "owner@example.test")
			old, _ := read(plain)
			if old == nil || old.User.Name != "Before" {
				t.Fatal("browser view did not use its bounded snapshot")
			}
			if dynamicVersion && calls != 2 {
				t.Fatal("expected one version lookup on issuance and one bound snapshot lookup", calls)
			}
			var request http.Request
			request.Header = make(http.Header)
			for _, c := range cookies {
				request.AddCookie(c)
			}
			live, err := plain.GetSession(ctx, request.Header)
			must(err)
			if live == nil || live.User.Name != "Live" {
				t.Fatal("direct authorization received a snapshot")
			}
			fresh, w := read(withJWT)
			if fresh == nil || fresh.User.Name != "Live" || strings.Count(w.Header().Get("Set-Auth-Jwt"), ".") != 2 {
				t.Fatal("JWT issuance did not use live identity")
			}
			admin := open("admin", "jwt")
			write(admin, `UPDATE "user" SET "banned"=? WHERE "id"=?`, true, old.User.ID)
			for _, server := range []*auth.Auth{plain, withJWT} {
				gone, w := read(server)
				if gone != nil || w.Header().Get("Set-Auth-Jwt") != "" {
					t.Fatal("live administrative migration failed to suppress stale identity")
				}
				if protected := route(server, "list-sessions", "", cookies...); protected.Code != 401 {
					t.Fatal("protected endpoint accepted a banned account", protected.Code)
				}
			}
		})
	}
}
