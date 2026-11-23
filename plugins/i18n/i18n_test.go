package i18n_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/i18n"
)

func host(t *testing.T, base string, opts i18n.Options, extra ...auth.Plugin) *auth.Auth {
	t.Helper()
	p, err := i18n.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	testRoutes := auth.Plugin{ID: "errors", Endpoints: []auth.Endpoint{{Method: "GET", Path: "/example", Handler: func(c auth.EndpointContext) (any, error) {
		q := c.Request.URL.Query()
		if q.Has("authenticate") {
			if _, err := c.Auth.GetSession(c.Request.Context(), c.Request.Header); err != nil {
				return nil, err
			}
		}
		return nil, &auth.APIError{Status: 418, Code: q.Get("code"), Message: "Original"}
	}}}}
	off := false
	a, err := auth.New(auth.Options{Store: memory.New(), BaseURL: base, Secret: strings.Repeat("s", 32), RateLimit: &off, EmailAndPassword: true, Plugins: append([]auth.Plugin{p, testRoutes}, extra...)})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func response(t *testing.T, a *auth.Auth, route string, headers http.Header) (int, map[string]string) {
	t.Helper()
	r := httptest.NewRequest("GET", "http://localhost/api/auth"+route, nil)
	for k, v := range headers {
		r.Header[k] = v
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return w.Code, body
}

func TestFallbackAndOriginalMessage(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		opts                  i18n.Options
		header, code, message string
		localized             bool
	}{
		{"default English", i18n.Options{Translations: map[string]i18n.Dictionary{"en": {"E": "English"}}}, "", "E", "English", true},
		{"absent default", i18n.Options{Translations: map[string]i18n.Dictionary{"fr": {"E": "French"}}}, "", "E", "Original", false},
		{"unavailable explicit default", i18n.Options{Translations: map[string]i18n.Dictionary{"en": {"E": "English"}}, DefaultLocale: "missing"}, "", "E", "Original", false},
		{"no second dictionary fallback", i18n.Options{Translations: map[string]i18n.Dictionary{"en": {"E": "English"}, "fr": {}}}, "fr", "E", "Original", false},
		{"empty code", i18n.Options{Translations: map[string]i18n.Dictionary{"en": {"": "unnamed"}}}, "", "", "Original", false},
		{"empty translation", i18n.Options{Translations: map[string]i18n.Dictionary{"en": {"E": ""}}}, "", "E", "Original", false},
		{"empty detection", i18n.Options{Translations: map[string]i18n.Dictionary{"xx": {"E": "Custom"}, "de": {"E": "German"}}, DefaultLocale: "xx", Detection: []i18n.Strategy{}}, "de", "E", "Custom", true},
		{"same message", i18n.Options{Translations: map[string]i18n.Dictionary{"en": {"E": "Original"}}}, "", "E", "Original", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := host(t, "http://localhost", tc.opts)
			status, out := response(t, a, "/example?code="+tc.code, http.Header{"Accept-Language": {tc.header}})
			code, hasCode := out["code"]
			source, translated := out["originalMessage"]
			if status != 418 || code != tc.code || hasCode != (tc.code != "") || out["message"] != tc.message || translated != tc.localized || (translated && source != "Original") {
				t.Fatalf("error response lost its fallback or wire shape: %#v", out)
			}
		})
	}
	if _, err := i18n.New(i18n.Options{}); err == nil {
		t.Fatal("empty dictionaries accepted")
	}
}

func TestAuthenticatedLocaleWithoutRepeatedVerification(t *testing.T) {
	var verifications, reads atomic.Int32
	credentials := auth.Plugin{ID: "credential", CredentialSessions: &auth.CredentialSessionResolver{
		Matches: func(h http.Header) bool { return h.Get("X-Fixture-Key") != "" }, Resolve: func(_ context.Context, h http.Header, _ auth.RequestMeta, _ time.Duration) (*auth.CredentialSession, error) {
			verifications.Add(1)
			if h.Get("X-Fixture-Key") != "valid" {
				return nil, &auth.APIError{Status: 401, Code: "E", Message: "Rejected"}
			}
			return &auth.CredentialSession{Identity: auth.SessionResult{User: auth.User{ID: "principal"}, Session: auth.Session{UserID: "principal"}}}, nil
		},
	}}
	opts := i18n.Options{Translations: map[string]i18n.Dictionary{"xx": {"E": "Trusted profile"}}, Detection: []i18n.Strategy{i18n.Session}, ReadUserLocale: func(_ context.Context, u auth.User, field string) string {
		reads.Add(1)
		if u.ID == "principal" && field == "locale" {
			return "xx"
		}
		return ""
	}}
	a := host(t, "http://localhost", opts, credentials)
	for _, v := range []string{"valid", "invalid", ""} {
		status, out := response(t, a, "/example?code=E&authenticate", http.Header{"X-Fixture-Key": {v}})
		localized := out["message"] == "Trusted profile"
		if localized != (v == "valid") || (v == "invalid" && status != 401) {
			t.Fatal("locale used an unverified principal", v, out)
		}
	}
	if verifications.Load() != 2 || reads.Load() != 1 {
		t.Fatal("translation repeated credential verification or profile access", verifications.Load(), reads.Load())
	}
}

func TestIndependentDictionaries(t *testing.T) {
	all := i18n.Builtins()
	other := i18n.Builtins()
	all["en"]["INVALID_PASSWORD"] = "changed"
	if other["en"]["INVALID_PASSWORD"] == "changed" {
		t.Fatal("built-in dictionaries share mutable state")
	}
	detection := []i18n.Strategy{i18n.Header}
	opts := i18n.Options{Detection: detection, Translations: map[string]i18n.Dictionary{"xx": {"E": "first"}}}
	first := host(t, "http://localhost", opts)
	opts.Translations["xx"]["E"] = "second"
	second := host(t, "http://localhost", opts)
	opts.Translations["xx"]["E"] = "modified"
	detection[0] = i18n.Cookie
	var group sync.WaitGroup
	for i := 0; i < 12; i++ {
		group.Go(func() {
			for _, v := range []struct {
				a    *auth.Auth
				want string
			}{{first, "first"}, {second, "second"}} {
				_, out := response(t, v.a, "/example?code=E", http.Header{"Accept-Language": {"xx"}})
				if out["message"] != v.want {
					t.Errorf("independent installations shared locale state: %v", out)
				}
			}
		})
	}
	group.Wait()
}

func TestNativeLocalizedError(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	base := "http://" + server.Listener.Addr().String()
	opts := i18n.Options{Translations: map[string]i18n.Dictionary{"en": {"E": "Localized"}}}
	server.Config.Handler = host(t, base, opts)
	server.Start()
	defer server.Close()
	c, err := client.New(base, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	err = c.Do(t.Context(), "GET", "/example?code=E", nil, nil)
	var api *auth.APIError
	var localized *auth.LocalizedError
	if !errors.As(err, &api) || !errors.As(err, &localized) || api.Status != 418 || api.Code != "E" || api.Message != "Localized" || localized.OriginalMessage != "Original" {
		t.Fatal("native client lost translated or original error", err)
	}
	err = c.Do(t.Context(), "GET", "/example", nil, nil)
	if !errors.As(err, &api) || errors.As(err, &localized) || api.Code != "" || api.Message != "Original" {
		t.Fatal("uncoded native error changed", err)
	}
}

func TestCallbackWithoutRequest(t *testing.T) {
	plugin, err := i18n.New(i18n.Options{
		Translations: map[string]i18n.Dictionary{"fr": {"E": "Traduit"}},
		Detection:    []i18n.Strategy{i18n.Header, i18n.Cookie, i18n.Session, i18n.Callback},
		GetLocale: func(c auth.ErrorContext) string {
			if c.Request != nil || c.User != nil {
				t.Fatal("callback received unexpected request data")
			}
			return "fr"
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := plugin.TranslateError(auth.ErrorContext{}, auth.APIError{Code: "E"}); got != "Traduit" {
		t.Fatal("callback could not select a locale without an HTTP request")
	}
}

func TestBundledMessages(t *testing.T) {
	dicts := i18n.Builtins()
	plugin, err := i18n.New(i18n.Options{Translations: dicts})
	if err != nil {
		t.Fatal(err)
	}
	if len(dicts) != 22 {
		t.Fatalf("unexpected bundled locale count %d", len(dicts))
	}
	for language, dictionary := range dicts {
		req := httptest.NewRequest("GET", "http://localhost", nil)
		req.Header.Set("Accept-Language", language)
		for code, want := range dictionary {
			if got := plugin.TranslateError(auth.ErrorContext{Request: req}, auth.APIError{Code: code}); got != want || got == "" {
				t.Fatalf("bundled message unavailable for %s/%s", language, code)
			}
		}
	}
}

func TestOAuthAndRateLimitErrors(t *testing.T) {
	p, err := i18n.New(i18n.Options{Translations: map[string]i18n.Dictionary{"en": {"PROVIDER_NOT_FOUND": "No such provider", "": "Unexpected change"}}})
	if err != nil {
		t.Fatal(err)
	}
	on := true
	a, err := auth.New(auth.Options{Store: memory.New(), Secret: strings.Repeat("s", 32), BaseURL: "http://localhost", Plugins: []auth.Plugin{p}, RateLimit: &on, RateLimitRules: map[string]*auth.RateLimitRule{"/sign-in/social": {Max: 1, Window: time.Minute}}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("POST", "http://localhost/api/auth/sign-in/social", strings.NewReader(`{"provider":"missing"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if w.Code != 404 || body["message"] != "No such provider" || body["originalMessage"] != "Provider not found" {
				t.Fatal("OAuth error did not use the translation hook", body)
			}
		} else if w.Code != 429 || len(body) != 1 || body["message"] != "Too many requests. Please try again later." || w.Header().Get("X-Retry-After") == "" {
			t.Fatal("uncoded rate limit response changed", body)
		}
	}
}
