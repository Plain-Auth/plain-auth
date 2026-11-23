package authtest_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/authtest"
)

func TestBrowserCookieFixture(t *testing.T) {
	ctx := t.Context()
	store := memory.New()
	server, err := authtest.New(auth.Options{Store: store, BaseURL: "https://auth.example.test",
		Secret: strings.Repeat("s", 40), SessionTTL: 20 * time.Minute, CookiePrefix: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := server.SaveUser(ctx, authtest.NewUser())
	if err != nil {
		t.Fatal(err)
	}
	login, err := server.Login(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := login.BrowserCookies("app.example.test:443"); err == nil {
		t.Fatal("port accepted as a cookie domain")
	}
	cookies, err := login.BrowserCookies(".example.test")
	if err != nil || len(cookies) != 1 {
		t.Fatal("browser export failed", err)
	}
	cookie := cookies[0]
	if cookie.Name != "__Secure-fixture.session_token" || cookie.Value != login.Cookies[0].Value || cookie.Value == login.Token ||
		cookie.Domain != ".example.test" || cookie.Path != "/" || !cookie.HTTPOnly || !cookie.Secure || cookie.SameSite != "Lax" {
		t.Fatal("browser export changed signed cookie attributes")
	}
	if cookie.Expires == nil || *cookie.Expires != login.Session.ExpiresAt.Unix() {
		t.Fatal("browser export changed the original deadline")
	}
	if login.Cookies[0].Domain != "auth.example.test" {
		t.Fatal("browser override mutated the issuing cookie")
	}
	records, err := store.ListSessions(ctx, user.ID)
	if err != nil || len(records) != 1 {
		t.Fatal("export changed the number of sessions", err)
	}
	for _, scenario := range []struct {
		mode http.SameSite
		want string
	}{{http.SameSiteNoneMode, "None"}, {http.SameSiteStrictMode, "Strict"}, {http.SameSiteDefaultMode, "Lax"}} {
		temporary := *login.Cookies[0]
		temporary.MaxAge, temporary.SameSite = 0, scenario.mode
		copy := *login
		copy.Cookies = []*http.Cookie{&temporary}
		view, err := copy.BrowserCookies("")
		if err != nil || view[0].SameSite != scenario.want || view[0].Expires != nil {
			t.Fatal("wrong browser session-cookie policy", scenario.want, err)
		}
		wire, err := json.Marshal(view[0])
		var fields map[string]any
		if err != nil || json.Unmarshal(wire, &fields) != nil || len(fields) != 7 || fields["httpOnly"] != true || fields["sameSite"] != scenario.want {
			t.Fatal("wrong browser cookie JSON keys")
		}
	}
}
