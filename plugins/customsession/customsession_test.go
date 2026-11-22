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

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
	"github.com/Plain-Auth/plain-auth/plugins/customsession"
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

func TestProjectionRegistrationAndResponseCommit(t *testing.T) {
	if _, err := customsession.New(nil); err == nil {
		t.Fatal("nil projection accepted")
	}
	const baseURL = "https://portal.example"
	opts := func(plugins ...auth.Plugin) auth.Options {
		return auth.Options{BaseURL: baseURL, Secret: strings.Repeat("s", 32), Store: memory.New(), EmailAndPassword: true, Plugins: plugins}
	}
	if _, err := auth.New(opts(auth.Plugin{ID: "missing-view", ProjectDeviceSessions: true})); err == nil {
		t.Fatal("registered device projection without a callback")
	}
	build := func(t *testing.T, label string) (*auth.Auth, []*http.Cookie) {
		t.Helper()
		fn := func(c auth.EndpointContext, session auth.SessionResult) (any, error) {
			c.ResponseHeader.Set("X-Projected", label)
			c.ResponseHeader.Set("Cache-Control", "public")
			c.ResponseHeader.Set("Pragma", "cache")
			c.ResponseHeader.Add("Set-Cookie", "view_marker="+label+"; Path=/; Secure; Partitioned")
			if c.Request.Header.Get("X-Invalid-JSON") != "" {
				return make(chan int), nil
			}
			return map[string]string{"instance": label, "user": session.User.ID}, nil
		}
		plugin, err := customsession.NewWithOptions(fn, customsession.Options{ProjectDeviceSessions: true})
		if err != nil {
			t.Fatal(err)
		}
		duplicate := plugin
		duplicate.ID = "another-projection"
		if _, err = auth.New(opts(plugin, duplicate)); err == nil {
			t.Fatal("multiple projection callbacks registered on the same endpoint")
		}
		multi, err := auth.NewMultiSession(auth.MultiSessionOptions{})
		if err != nil {
			t.Fatal(err)
		}
		settings := opts(multi, plugin)
		due := time.Duration(0)
		settings.SessionUpdateAge = &due
		host, err := auth.New(settings)
		if err != nil {
			t.Fatal(err)
		}
		input, err := json.Marshal(map[string]string{"name": label, "email": label + "@example.test", "password": "valid-fixture-password"})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", baseURL+"/api/auth/sign-up/email", strings.NewReader(string(input)))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		host.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal("fixture signup", w.Code)
		}
		return host, w.Result().Cookies()
	}
	for _, label := range []string{"one", "two"} {
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			host, cookies := build(t, label)
			transport := func(path string, invalid bool) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodGet, baseURL+"/api/auth/"+path, nil)
				for _, cookie := range cookies {
					r.AddCookie(cookie)
				}
				if invalid {
					r.Header.Set("X-Invalid-JSON", "yes")
				}
				w := httptest.NewRecorder()
				host.ServeHTTP(w, r)
				return w
			}
			w := transport("get-session", false)
			var out map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out["instance"] != label || w.Header().Get("X-Projected") != label || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
				t.Fatal("projection headers escaped their instance", w.Code)
			}
			for _, path := range []string{"get-session", "multi-session/list-device-sessions"} {
				w := transport(path, true)
				if w.Code != 500 || w.Header().Get("X-Projected") != "" || len(w.Result().Cookies()) != 0 || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("unencodable projection committed headers or cookies", path, w.Code)
				}
			}
		})
	}
}

func TestPlainAndProjectedSessionMethodMatrix(t *testing.T) {
	for _, projection := range []bool{false, true} {
		for _, deferred := range []bool{false, true} {
			count := 0
			options := auth.Options{BaseURL: "http://session.example", Store: memory.New(), Secret: strings.Repeat("s", 32), EmailAndPassword: true, DeferSessionRefresh: deferred}
			if projection {
				p, err := customsession.New(func(_ auth.EndpointContext, s auth.SessionResult) (any, error) { count++; return s, nil })
				if err != nil {
					t.Fatal(err)
				}
				options.Plugins = []auth.Plugin{p}
			}
			host, err := auth.New(options)
			if err != nil {
				t.Fatal(err)
			}
			account, err := host.SignUpEmail(t.Context(), auth.SignUpInput{Name: "Account", Email: "account@example.test", Password: "fixture-password"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			query := func(method string, authenticated bool) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, options.BaseURL+"/api/auth/get-session", nil)
				r.Header.Set("Origin", options.BaseURL)
				credential := host.SessionCookie(account.Token, true)
				if authenticated {
					r.AddCookie(credential)
				}
				prefix := strings.TrimSuffix(credential.Name, "session_token") + "session_data."
				for _, suffix := range []string{"0", "01", "invalid"} {
					r.AddCookie(&http.Cookie{Name: prefix + suffix, Value: "stale"})
				}
				w := httptest.NewRecorder()
				host.ServeHTTP(w, r)
				return w
			}
			for _, authenticated := range []bool{false, true} {
				w := query("GET", authenticated)
				var expired []string
				for _, c := range w.Result().Cookies() {
					if strings.Contains(c.Name, "session_data") && c.MaxAge < 0 {
						expired = append(expired, c.Name)
					}
				}
				if len(expired) != 1 || !strings.HasSuffix(expired[0], "session_data.0") || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
					t.Fatal("cache cleanup and policy", projection, deferred, authenticated, expired, w.Header())
				}
			}
			w := query("GET", true)
			var payload auth.SessionResult
			if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil || w.Code != 200 || (payload.NeedsRefresh != nil) != deferred || payload.NeedsRefresh != nil && *payload.NeedsRefresh {
				t.Fatal("GET shape differs from refresh mode", projection, deferred)
			}
			status := 405
			if projection {
				status = 404
			} else if deferred {
				status = 200
			}
			if got := query("POST", true).Code; got != status {
				t.Fatal("deferred POST dispatch", projection, deferred, got, status)
			}
			advertised := false
			for _, route := range host.DescribeHTTP().Routes {
				if route.Method == "POST" && route.Path == "/get-session" {
					advertised = true
				}
			}
			if advertised != (deferred && !projection) || projection && count != 2 {
				t.Fatal("session route metadata or projection invocation", projection, deferred, advertised, count)
			}
		}
	}
}
