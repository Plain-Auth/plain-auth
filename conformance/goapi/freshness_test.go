package goapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/plugins/twofactor"
	"github.com/Plain-Org/plain-auth/schema"
)

// Refuse sensitive account changes from a session older than FreshAge, and
// let a negative FreshAge turn the check off.
func TestSessionFreshness(t *testing.T) {
	store := memory.New()
	newAuth := func(fresh time.Duration) *authn.Auth {
		t.Helper()
		off := false
		a, err := authn.New(authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off, DeleteUserEnabled: true, FreshAge: fresh})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	strict, relaxed := newAuth(0), newAuth(-1)
	account, err := strict.SignUpEmail(t.Context(), authn.SignUpInput{Email: "ada@example.com", Password: "correct horse battery", Name: "Ada"}, authn.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	created := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Millisecond)
	stale := authn.StoredSession{Session: authn.Session{ID: "stale", Token: "stale-token", UserID: account.User.ID, CreatedAt: created, UpdatedAt: created, ExpiresAt: time.Now().Add(time.Hour)}}
	if err := store.CreateSession(t.Context(), stale); err != nil {
		t.Fatal(err)
	}
	call := func(a *authn.Auth, path, body string) (int, string) {
		r := httptest.NewRequest("POST", "https://auth.example/api/auth"+path, strings.NewReader(body))
		r.Header = http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
		r.AddCookie(a.SessionCookie("stale-token", false))
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		code, _ := out["code"].(string)
		return w.Code, code
	}

	// The default one-day window refuses a two-day-old session.
	if status, code := call(strict, "/unlink-account", `{"accountId":"missing"}`); status != 403 || code != "SESSION_NOT_FRESH" {
		t.Fatal("a stale session unlinked an account", status, code)
	}
	if status, code := call(strict, "/delete-user", `{}`); status != 400 || code != "SESSION_EXPIRED" {
		t.Fatal("a stale session deleted the user", status, code)
	}
	// A negative FreshAge skips the check, so the request reaches its own validation.
	if status, code := call(relaxed, "/unlink-account", `{"accountId":"missing"}`); status != 400 || code != "FAILED_TO_UNLINK_LAST_ACCOUNT" {
		t.Fatal("the freshness check was not turned off", status, code)
	}
}

// Name the application in authenticator apps unless the two-factor plugin sets its own issuer.
func TestAppNameIsTheAuthenticatorIssuer(t *testing.T) {
	for _, tc := range []struct{ app, issuer, want string }{{"Acme", "", "Acme"}, {"", "", "Auth"}, {"Acme", "Acme Security", "Acme Security"}} {
		store, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"two-factor"}, schema.Options{})
		if err != nil {
			t.Fatal(err)
		}
		off := false
		a, err := authn.New(authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off, AppName: tc.app,
			Plugins: []authn.Plugin{twofactor.New(twofactor.Options{Issuer: tc.issuer})}})
		if err != nil {
			t.Fatal(err)
		}
		// Plugins read the application name from the instance.
		if name := a.AppName(); name != tc.app && !(tc.app == "" && name == "Auth") {
			t.Fatal("unexpected application name", name)
		}
		account, err := a.SignUpEmail(t.Context(), authn.SignUpInput{Email: "ada@example.com", Password: "correct horse battery", Name: "Ada"}, authn.RequestMeta{})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "https://auth.example/api/auth/two-factor/enable", strings.NewReader(`{"password":"correct horse battery"}`))
		r.Header = http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
		r.AddCookie(a.SessionCookie(account.Token, false))
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		var setup struct{ TOTPURI string }
		_ = json.Unmarshal(w.Body.Bytes(), &setup)
		u, err := url.Parse(setup.TOTPURI)
		if err != nil || u.Query().Get("issuer") != tc.want {
			t.Fatal("unexpected authenticator issuer", tc, setup.TOTPURI, w.Body)
		}
		store.Close()
	}
}
