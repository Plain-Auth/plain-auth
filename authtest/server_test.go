package authtest_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
	"github.com/Plain-Auth/plain-auth/adapters/sqlstore"
	"github.com/Plain-Auth/plain-auth/authtest"
)

func TestFixtureUserLifecycle(t *testing.T) {
	for _, engine := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(engine, func(t *testing.T) {
			ctx := t.Context()
			var store auth.Store
			if engine == "memory" {
				store = memory.New()
			} else {
				dsn := filepath.Join(t.TempDir(), "auth.sqlite")
				if engine != "sqlite" {
					name := "AUTH_TEST_" + strings.ToUpper(engine) + "_DSN"
					dsn = os.Getenv(name)
					if dsn == "" {
						t.Skipf("set %s", name)
					}
				}
				sql, err := sqlstore.Open(ctx, engine, dsn)
				if err != nil {
					t.Fatal(err)
				}
				defer sql.Close()
				store = sql
			}
			opts := auth.Options{BaseURL: "https://app.example.test", BasePath: "/identity", Store: store, Secret: strings.Repeat("x", 40), CookiePrefix: "myapp", SessionTTL: 22 * time.Hour}
			h, err := authtest.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			peer, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			u := authtest.NewUser()
			u.Email = strings.ToUpper(u.Email)
			saved, err := h.SaveUser(ctx, u)
			if err != nil || saved.ID != u.ID || saved.Name != u.Name || saved.Email != strings.ToLower(u.Email) || !saved.EmailVerified {
				t.Fatal("saved fixture", saved, err)
			}
			defer func() {
				if err := h.DeleteUser(ctx, u.ID); err != nil {
					t.Error(err)
				}
			}()
			if _, err = h.SaveUser(ctx, u); !errors.Is(err, auth.ErrEmailTaken) {
				t.Fatal("duplicate fixture", err)
			}
			if rows, err := store.ListSessions(ctx, u.ID); err != nil || len(rows) != 0 {
				t.Fatal("save created a session", err)
			}
			accounts, err := store.(auth.LinkedAccountStore).ListUserAccounts(ctx, u.ID)
			if err != nil || len(accounts) != 0 {
				t.Fatal("fixture acquired a credential", accounts, err)
			}
			if _, err = h.Login(ctx, "absent-"+u.ID); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("missing owner got a session", err)
			}
			signed, err := h.Login(ctx, u.ID)
			if err != nil {
				t.Fatal(err)
			}
			cookie := signed.Cookies[0]
			if signed.Token == "" || signed.Token != signed.Session.Token || cookie.Value == signed.Token || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "app.example.test" || !strings.Contains(cookie.Name, "myapp.") {
				t.Fatal("wrong fixture cookie attributes")
			}
			if signed.Session.ExpiresAt.Sub(signed.Session.CreatedAt) != 22*time.Hour || signed.Session.UserID != saved.ID || signed.User.ID != saved.ID {
				t.Fatal("fixture session did not use host policy")
			}
			check := func(h http.Header, want bool) {
				t.Helper()
				result, e := peer.GetSession(ctx, h)
				if e != nil {
					t.Fatal(e)
				}
				if (result != nil) != want || (result != nil && result.User.ID != saved.ID) {
					t.Fatal("session ownership or validity changed")
				}
			}
			check(signed.Headers, true)
			request := httptest.NewRequest("GET", "https://app.example.test/identity/get-session", nil)
			request.AddCookie(cookie)
			w := httptest.NewRecorder()
			peer.ServeHTTP(w, request)
			if w.Code != 200 || !strings.Contains(w.Body.String(), saved.ID) {
				t.Fatal("browser cookie failed on peer", w.Code)
			}
			headers, err := h.GetAuthHeaders(ctx, u.ID)
			if err != nil {
				t.Fatal(err)
			}
			check(headers, true)
			if headers.Get("Cookie") == signed.Headers.Get("Cookie") {
				t.Fatal("header helper reused a different login")
			}
			if _, err := h.GetCookies(ctx, u.ID, "example.test:9000"); err == nil {
				t.Fatal("malformed cookie domain accepted")
			}
			forBrowser, err := h.GetCookies(ctx, u.ID, ".example.test")
			if err != nil || len(forBrowser) != 1 || forBrowser[0].Domain != ".example.test" {
				t.Fatal("cookie override", err)
			}
			cookieRequest := httptest.NewRequest("GET", "https://app.example.test", nil)
			cookieRequest.AddCookie(forBrowser[0])
			check(cookieRequest.Header, true)
			if rows, err := store.ListSessions(ctx, u.ID); err != nil || len(rows) != 3 {
				t.Fatal("unexpected sessions from fixture requests", len(rows), err)
			}
			if err := h.DeleteUser(ctx, u.ID); err != nil {
				t.Fatal(err)
			}
			check(signed.Headers, false)
			check(headers, false)
			check(cookieRequest.Header, false)
			if _, err := h.Login(ctx, u.ID); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("deleted fixture signed in", err)
			}
		})
	}
}

type canceledSessionRead struct {
	*memory.Store
	cancel context.CancelFunc
}

func (s canceledSessionRead) Session(ctx context.Context, token string) (auth.StoredSession, auth.User, error) {
	s.cancel()
	return auth.StoredSession{}, auth.User{}, ctx.Err()
}

func TestFixtureLoginCleansUpOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	store := canceledSessionRead{memory.New(), cancel}
	h, err := authtest.New(auth.Options{BaseURL: "https://app.example.test", Secret: strings.Repeat("a", 40), Store: store})
	if err != nil {
		t.Fatal(err)
	}
	user, err := h.SaveUser(t.Context(), authtest.NewUser())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Login(ctx, user.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("failed lookup did not preserve cancellation", err)
	}
	rows, err := store.ListSessions(t.Context(), user.ID)
	if err != nil || len(rows) != 0 {
		t.Fatal("failed fixture login left a session", err)
	}
}
