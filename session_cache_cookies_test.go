package plainauth

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestDisabledCacheScopeCleanup(t *testing.T) {
	cleanConfigEnv(t)
	a, err := New(Options{Store: &refreshFixture{}, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example.com",
		CookiePrefix: "tenant", CrossSubDomainCookies: &CrossSubDomainCookiesOptions{Domain: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/api/auth/get-session", nil)
	name := a.prefixedCookieName("session_data") + ".0"
	for _, item := range []string{name, name, "authn.session_data.0", name + "01"} {
		r.AddCookie(&http.Cookie{Name: item, Value: "old"})
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "null" {
		t.Fatal("cache cookie authenticated an anonymous request")
	}
	var scopes []string
	for _, c := range w.Result().Cookies() {
		if c.Name != name || c.Value != "" || !c.Secure || !c.HttpOnly || c.Path != "/" || c.MaxAge >= 0 {
			t.Fatal("unexpected expiration", c.Name)
		}
		scopes = append(scopes, c.Domain)
	}
	if !reflect.DeepEqual(scopes, []string{"", "example.com"}) {
		t.Fatal("cache was not cleared once on each cookie scope", scopes)
	}
}
