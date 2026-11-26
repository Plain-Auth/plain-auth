package authtest_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/authtest"
	"github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
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

// A fixture server from New or NewWithOrganizations serves exactly the routes
// of the same options passed to plainauth.New.
func TestFixtureServerAddsNoRoutes(t *testing.T) {
	ctx := t.Context()
	opts := auth.Options{BaseURL: "https://app.example.test", Secret: strings.Repeat("r", 40), Store: memory.New(), EmailAndPassword: true}
	fixtures, err := authtest.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := auth.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fixtures.Auth.DescribeHTTP().Routes, plain.DescribeHTTP().Routes) {
		t.Fatal("authtest.New changed the HTTP routes")
	}
	ddl, err := schema.Generate("sqlite", []string{"organization"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlstore.OpenWithSchema(ctx, "sqlite", filepath.Join(t.TempDir(), "org.sqlite"), ddl)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	orgOpts := opts
	orgOpts.Store = store
	withOrgs, err := authtest.NewWithOrganizations(orgOpts, organization.Options{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := organization.NewService(organization.Options{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	orgOpts.Plugins = []auth.Plugin{service.Plugin()}
	direct, err := auth.New(orgOpts)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(withOrgs.Auth.DescribeHTTP().Routes, direct.DescribeHTTP().Routes) {
		t.Fatal("NewWithOrganizations added routes beyond the organization plugin")
	}
}

// On a server from New, the organization helpers return ErrOrganizationSetup.
func TestOrganizationHelpersNeedSetup(t *testing.T) {
	ctx := t.Context()
	server, err := authtest.New(auth.Options{BaseURL: "https://app.example.test", Secret: strings.Repeat("r", 40), Store: memory.New()})
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"SaveOrganization": func() error { _, err := server.SaveOrganization(ctx, authtest.NewOrganization("")); return err },
		"AddMember": func() error {
			_, err := server.AddMember(ctx, organization.AddMemberRequest{UserID: "user-1", OrganizationID: "org-1"})
			return err
		},
		"DeleteOrganization": func() error { return server.DeleteOrganization(ctx, "org-1") },
	} {
		if err := call(); !errors.Is(err, authtest.ErrOrganizationSetup) {
			t.Fatal("organization helper ran without NewWithOrganizations", name, err)
		}
	}
}
