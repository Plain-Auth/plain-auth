package multisession_test

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	authn "github.com/nabuhadba/go-better-auth"
	"github.com/nabuhadba/go-better-auth/adapters/memory"
	"github.com/nabuhadba/go-better-auth/client"
	"github.com/nabuhadba/go-better-auth/plugins/multisession"
)

type fixture struct {
	auth   *authn.Auth
	server *httptest.Server
	store  *memory.Store
	url    *url.URL
}

func newFixture(t *testing.T, maximum *int) fixture {
	t.Helper()
	p, err := multisession.New(multisession.Options{MaximumSessions: maximum})
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(nil)
	t.Cleanup(s.Close)
	base := "https://" + s.Listener.Addr().String()
	store := memory.New()
	limit := false
	a, err := authn.New(authn.Options{BaseURL: base, CookiePrefix: "switch", Store: store, Plugins: []authn.Plugin{p}, EmailAndPassword: true, RateLimit: &limit, Secret: "a-test-session-switching-key-0123456789"})
	if err != nil {
		t.Fatal(err)
	}
	s.Config.Handler = a
	s.StartTLS()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{a, s, store, u}
}

func (f fixture) device(t *testing.T) (*client.Client, http.CookieJar) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(f.url.String(), &http.Client{Transport: f.server.Client().Transport, Jar: jar})
	if err != nil {
		t.Fatal(err)
	}
	return c, jar
}

func register(t *testing.T, c *client.Client, email string, persistent bool) string {
	t.Helper()
	out, err := c.SignUpEmail(t.Context(), client.SignUpRequest{Name: email, Email: email, Password: "sample-password-for-tests", RememberMe: &persistent})
	if err != nil || out.Token == nil {
		t.Fatalf("register: %v", err)
	}
	return *out.Token
}

func assertActive(t *testing.T, c *client.Client, expected string) {
	t.Helper()
	out, err := c.GetSession(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if expected == "" {
		if out != nil {
			t.Fatal("session still active")
		}
		return
	}
	if out == nil || out.Session.Token != expected {
		t.Fatal("unexpected active session")
	}
}

func expectDenied(t *testing.T, err error, code string) {
	t.Helper()
	var api *authn.APIError
	if !errors.As(err, &api) || api.Status != 401 || api.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

func TestDeviceAccountSwitching(t *testing.T) {
	limit := 2
	f := newFixture(t, &limit)
	first, jar := f.device(t)
	other, _ := f.device(t)
	ctx := t.Context()
	if out, err := first.ListDeviceSessions(ctx); err != nil || len(out) != 0 {
		t.Fatal("anonymous list", err)
	}
	alice := register(t, first, "alice@example.test", false)
	bob := register(t, first, "bob@example.test", true)
	carol := register(t, first, "carol@example.test", true)
	assertActive(t, first, carol)
	entries, err := first.ListDeviceSessions(ctx)
	if err != nil || len(entries) != 2 || entries[0].Session.Token != alice || entries[1].Session.Token != bob {
		t.Fatal("remembered accounts at capacity", err)
	}
	_, err = first.SetActiveSession(ctx, carol)
	expectDenied(t, err, "INVALID_SESSION_TOKEN")
	_, err = other.SetActiveSession(ctx, alice)
	expectDenied(t, err, "INVALID_SESSION_TOKEN")
	if err := other.RevokeDeviceSession(ctx, alice); err == nil {
		t.Fatal("unauthorized revoke")
	}
	// Holding an active session for Bob on an independent browser does not authorize access to Alice's login.
	remote, err := other.SignInEmail(ctx, client.SignInRequest{Email: "bob@example.test", Password: "sample-password-for-tests"})
	if err != nil || remote.Token == nil {
		t.Fatal("remote login", err)
	}
	expectDenied(t, other.RevokeDeviceSession(ctx, alice), "INVALID_SESSION_TOKEN")
	if _, err := first.SetActiveSession(ctx, alice); err != nil {
		t.Fatal(err)
	}
	assertActive(t, first, alice)
	const activeName = "__Secure-switch.session_token"
	readPreference := func() bool {
		for _, c := range jar.Cookies(f.url) {
			if c.Name == "__Secure-switch.dont_remember" {
				return true
			}
		}
		return false
	}
	if !readPreference() {
		t.Fatal("browser-only choice lost on switch")
	}
	if _, err := first.SetActiveSession(ctx, bob); err != nil {
		t.Fatal(err)
	}
	if readPreference() {
		t.Fatal("persistent account kept the browser-only marker")
	}
	// Reauthenticate Alice. Only the remembered Alice session on this browser is replaced.
	newAlice, err := first.SignInEmail(ctx, client.SignInRequest{Email: "alice@example.test", Password: "sample-password-for-tests"})
	if err != nil || newAlice.Token == nil || *newAlice.Token == alice {
		t.Fatal("replacement login", err)
	}
	if _, _, err := f.store.Session(ctx, alice); !errors.Is(err, authn.ErrNotFound) {
		t.Fatal("previous login survived replacement")
	}
	assertActive(t, other, *remote.Token)
	jar.SetCookies(f.url, []*http.Cookie{{Name: activeName, Path: "/", MaxAge: -1}})
	if sessions, err := first.ListDeviceSessions(ctx); err != nil || len(sessions) != 2 {
		t.Fatal("list without active cookie", err)
	}
	expectDenied(t, first.RevokeDeviceSession(ctx, bob), "UNAUTHORIZED")
	if _, err := first.SetActiveSession(ctx, *newAlice.Token); err != nil {
		t.Fatal(err)
	}
	if err := first.RevokeDeviceSession(ctx, *newAlice.Token); err != nil {
		t.Fatal(err)
	}
	assertActive(t, first, bob)
	if err := first.RevokeDeviceSession(ctx, bob); err != nil {
		t.Fatal(err)
	}
	assertActive(t, first, "")
	assertActive(t, other, *remote.Token)
}

func TestDeviceCookieScopeExpiryAndSignOut(t *testing.T) {
	f := newFixture(t, nil)
	device, jar := f.device(t)
	other, _ := f.device(t)
	ctx := t.Context()
	alice := register(t, device, "first@example.test", true)
	bob := register(t, device, "second@example.test", true)
	foreign := register(t, other, "foreign@example.test", true)
	const prefix = "__Secure-switch.session_token_multi-"
	var valid *http.Cookie
	for _, c := range jar.Cookies(f.url) {
		if c.Name == prefix+strings.ToLower(alice) {
			valid = c
		}
	}
	if valid == nil {
		t.Fatal("missing namespaced device cookie")
	}
	// Requests may carry unrelated cookies from another application at the same origin.
	jar.SetCookies(f.url, []*http.Cookie{
		{Name: prefix + strings.ToLower(foreign), Value: valid.Value, Path: "/"},
		{Name: "__Secure-other.session_token_multi-" + strings.ToLower(foreign), Value: f.auth.SessionCookie(foreign, true).Value, Path: "/"},
	})
	_, err := device.SetActiveSession(ctx, foreign)
	expectDenied(t, err, "INVALID_SESSION_TOKEN")
	expectDenied(t, device.RevokeDeviceSession(ctx, foreign), "INVALID_SESSION_TOKEN")
	row, _, err := f.store.Session(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.DeleteSession(ctx, alice); err != nil {
		t.Fatal(err)
	}
	row.ExpiresAt = time.Now().Add(-time.Hour)
	if err := f.store.CreateSession(ctx, row); err != nil {
		t.Fatal(err)
	}
	_, err = device.SetActiveSession(ctx, alice)
	expectDenied(t, err, "INVALID_SESSION_TOKEN")
	rows, err := device.ListDeviceSessions(ctx)
	if err != nil || len(rows) != 1 || rows[0].Session.Token != bob {
		t.Fatal("expired/foreign cookies listed", err)
	}
	carol := register(t, device, "third@example.test", true)
	if err := device.SignOut(ctx); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{bob, carol} {
		if _, _, err := f.store.Session(ctx, token); !errors.Is(err, authn.ErrNotFound) {
			t.Fatal("signed-out login remains")
		}
	}
	results, err := device.ListDeviceSessions(ctx)
	if err != nil || len(results) != 0 {
		t.Fatal("signed-out device still lists entries", err)
	}
	assertActive(t, other, foreign)
}

func TestDeviceCookieAttributesAndMaximum(t *testing.T) {
	limit := 0
	f := newFixture(t, &limit)
	c, _ := f.device(t)
	token := register(t, c, "zero@example.test", true)
	assertActive(t, c, token)
	if rows, err := c.ListDeviceSessions(t.Context()); err != nil || len(rows) != 0 {
		t.Fatal("zero maximum still remembers accounts")
	}
	limit = -1
	if _, err := multisession.New(multisession.Options{MaximumSessions: &limit}); err == nil {
		t.Fatal("negative maximum accepted")
	}
	f = newFixture(t, nil)
	for i := range 2 {
		remember := []string{"true", "false"}[i]
		body := `{"name":"Fixture","email":"` + remember + `@example.test","password":"sample-password-for-tests","rememberMe":` + remember + `}`
		r := httptest.NewRequest("POST", f.url.String()+"/api/auth/sign-up/email", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", f.url.String())
		w := httptest.NewRecorder()
		f.auth.ServeHTTP(w, r)
		found := false
		for _, cookie := range w.Result().Cookies() {
			if !strings.HasPrefix(cookie.Name, "__Secure-switch.session_token_multi-") {
				continue
			}
			found = true
			if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || (cookie.MaxAge > 0) != (i == 0) {
				t.Fatal("device cookie attributes differ from login")
			}
		}
		if !found {
			t.Fatal("missing device cookie", w.Code)
		}
	}
}

func TestDefaultFiveRememberedAccounts(t *testing.T) {
	f := newFixture(t, nil)
	c, _ := f.device(t)
	var overLimit string
	for i := range 6 {
		overLimit = register(t, c, string(rune('a'+i))+"@example.test", true)
	}
	rows, err := c.ListDeviceSessions(t.Context())
	if err != nil || len(rows) != 5 {
		t.Fatal("default limit should be five remembered accounts", err)
	}
	assertActive(t, c, overLimit)
}

func TestDeviceConcurrentCookieReconciliation(t *testing.T) {
	limit := 1
	f := newFixture(t, &limit)
	first, firstJar := f.device(t)
	second, secondJar := f.device(t)
	register(t, first, "firsttab@example.test", true)
	register(t, second, "secondtab@example.test", true)
	// Two tabs can send the same, initially empty request jar before either
	// response arrives. Apply their independent Set-Cookie results to one jar.
	c, merged := f.device(t)
	merged.SetCookies(f.url, firstJar.Cookies(f.url))
	merged.SetCookies(f.url, secondJar.Cookies(f.url))
	rows, err := c.ListDeviceSessions(t.Context())
	if err != nil || len(rows) != 1 {
		t.Fatal("concurrent logins exceeded the displayed maximum", err)
	}
	count := 0
	for _, cookie := range merged.Cookies(f.url) {
		if strings.Contains(cookie.Name, "_multi-") {
			count++
		}
	}
	if count != 1 {
		t.Fatal("extra account cookie survived list reconciliation")
	}
}
