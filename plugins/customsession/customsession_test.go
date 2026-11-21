package customsession_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/FineStack/frost-auth"
	"github.com/FineStack/frost-auth/adapters/memory"
	"github.com/FineStack/frost-auth/plugins/customsession"
)

func TestProjectedSessionHTTP(t *testing.T) {
	for _, deferred := range []bool{false, true} {
		calls := 0
		plugin, err := customsession.New(func(c auth.EndpointContext, s auth.SessionResult) (any, error) {
			calls++
			if c.Request.Header.Get("X-Fail") != "" {
				return nil, errors.New("unavailable private backend")
			}
			c.ResponseHeader.Set("X-Session-View", "active")
			return map[string]string{"viewer": s.User.Email, "id": s.User.ID}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		immediate := time.Duration(0)
		a, err := auth.New(auth.Options{BaseURL: "http://localhost", Secret: strings.Repeat("s", 32), Store: memory.New(),
			EmailAndPassword: true, SessionUpdateAge: &immediate, DeferSessionRefresh: deferred, Plugins: []auth.Plugin{plugin}})
		if err != nil {
			t.Fatal(err)
		}
		user, err := a.SignUpEmail(context.Background(), auth.SignUpInput{Name: "Viewer", Email: "viewer@example.test", Password: "example-password"}, auth.RequestMeta{})
		if err != nil {
			t.Fatal(err)
		}
		request := func(cookie, fails bool) *httptest.ResponseRecorder {
			r := httptest.NewRequest("GET", "http://localhost/api/auth/get-session", nil)
			if cookie {
				r.AddCookie(a.SessionCookie(user.Token, true))
			}
			if fails {
				r.Header.Set("X-Fail", "yes")
			}
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			return w
		}
		if w := request(false, false); strings.TrimSpace(w.Body.String()) != "null" || calls != 0 {
			t.Fatal("anonymous projection", w.Body)
		}
		w := request(true, false)
		var view map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil || w.Code != 200 || view["id"] != user.User.ID || view["viewer"] != "viewer@example.test" || len(view) != 2 || w.Header().Get("X-Session-View") != "active" {
			t.Fatal("projection", w.Code, w.Body)
		}
		if !deferred && len(w.Result().Cookies()) == 0 {
			t.Fatal("refresh cookies lost")
		}
		if w = request(true, true); w.Code != 500 || strings.Contains(w.Body.String(), "private backend") {
			t.Fatal("failed projection", w.Code, w.Body)
		}
		h := http.Header{}
		h.Set("Cookie", a.SessionCookie(user.Token, true).String())
		if verified, err := a.GetSession(t.Context(), h); err != nil || verified == nil || verified.User.ID != user.User.ID || calls != 2 {
			t.Fatal("authoritative read", err)
		}
	}
}
