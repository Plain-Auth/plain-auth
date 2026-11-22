package client_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
	"github.com/Plain-Auth/plain-auth/client"
	"github.com/Plain-Auth/plain-auth/plugins/bearer"
)

func TestSignedBearerClient(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	instance, err := plainauth.New(plainauth.Options{BaseURL: origin, Store: memory.New(), Secret: strings.Repeat("x", 32),
		EmailAndPassword: true, Plugins: []plainauth.Plugin{bearer.New(bearer.Options{RequireSignature: true})}})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" && r.Header.Get("Cookie") != "" {
			t.Error("bearer request attached a cookie")
		}
		if r.URL.Path == "/private/profile" {
			session, err := instance.GetSession(r.Context(), r.Header)
			if err != nil {
				http.Error(w, "session lookup failed", http.StatusInternalServerError)
				return
			}
			if session == nil {
				http.Error(w, "sign in first", http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, session.User.ID)
			return
		}
		instance.ServeHTTP(w, r)
	})
	server.StartTLS()
	t.Cleanup(server.Close)
	browser, err := client.New(origin, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	register := func(email string) (string, string) {
		t.Helper()
		var result client.EmailResult
		h, err := browser.DoWithHeaders(t.Context(), "POST", "/sign-up/email", client.SignUpRequest{
			Email: email, Password: "fixture-password", Name: "User",
		}, &result)
		if err != nil || h.Get("Set-Auth-Token") == "" || result.User.ID == "" {
			t.Fatal("registration did not issue a signed credential", err)
		}
		return result.User.ID, h.Get("Set-Auth-Token")
	}
	alice, token := register("alice@example.test")
	bob, _ := register("bob@example.test")
	device, err := browser.WithBearerToken(token)
	if err != nil {
		t.Fatal(err)
	}
	get := func(c *client.Client) string {
		t.Helper()
		s, err := c.GetSession(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if s == nil {
			return ""
		}
		return s.User.ID
	}
	if get(device) != alice || get(browser) != bob {
		t.Fatal("bearer and cookie identities were mixed")
	}
	// A separate application endpoint can use the same signed credential.
	privateProfile := func(wantStatus int, wantID string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, origin+"/private/profile", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil || res.StatusCode != wantStatus || (wantID != "" && string(body) != wantID) {
			t.Fatalf("application bearer route returned %d, want %d with expected account", res.StatusCode, wantStatus)
		}
	}
	privateProfile(http.StatusOK, alice)
	if err := device.SignOut(t.Context()); err != nil {
		t.Fatal(err)
	}
	if get(device) != "" || get(browser) != bob {
		t.Fatal("revoked bearer reused a browser identity")
	}
	privateProfile(http.StatusUnauthorized, "")
	for _, invalid := range []string{"", "a b", "x\r\ny", "a,b"} {
		if _, err := browser.WithBearerToken(invalid); err == nil {
			t.Fatal("accepted malformed bearer")
		}
	}
}
