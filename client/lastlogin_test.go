package client_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/lastlogin"
)

func TestLoginMethodPreferenceJar(t *testing.T) {
	for _, name := range []string{"", "staff.preference"} {
		server := httptest.NewUnstartedServer(nil)
		origin := "https://" + server.Listener.Addr().String()
		const method = "email + SSO / équipe"
		instance, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("s", 32), EmailAndPassword: true, Store: memory.New(), Plugins: []auth.Plugin{lastlogin.New(lastlogin.Options{CookieName: name, Resolve: func(*http.Request) string { return method }})}})
		if err != nil {
			t.Fatal(err)
		}
		server.Config.Handler = instance
		server.StartTLS()
		t.Cleanup(server.Close)
		browser, err := client.New(origin, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		if browser.LastLoginMethod(name) != "" {
			t.Fatal("new client has preference")
		}
		var out auth.AuthResult
		if err := browser.Do(t.Context(), "POST", "/sign-up/email", map[string]string{"name": "User", "email": "user@example.test", "password": "fixture-password"}, &out); err != nil {
			t.Fatal(err)
		}
		if browser.LastLoginMethod(name) != method {
			t.Fatal("client could not read preference")
		}
		browser.ClearLastLoginMethod(name)
		if browser.LastLoginMethod(name) != "" {
			t.Fatal("client retained cleared preference")
		}
		var active auth.SessionResult
		if err := browser.Do(t.Context(), "GET", "/get-session", nil, &active); err != nil || active.User.ID != out.User.ID {
			t.Fatal("clearing preference affected session", err)
		}
	}
}
