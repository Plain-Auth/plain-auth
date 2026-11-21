package fineauth_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	authn "github.com/FineStack/finestack-auth"
	"github.com/FineStack/finestack-auth/adapters/sqlite"
)

func newHTTPAuth(t *testing.T, opts authn.Options) *authn.Auth {
	t.Helper()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	opts.Store = store
	opts.Secret = "local-test-cookie-signing-secret-at-least-32"
	opts.EmailAndPassword = true
	auth, err := authn.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func serve(t *testing.T, auth http.Handler, method, path, body string, headers http.Header, wantStatus int) *http.Response {
	t.Helper()
	r := httptest.NewRequest(method, "https://auth.example"+path, strings.NewReader(body))
	r.Header = headers.Clone()
	w := httptest.NewRecorder()
	auth.ServeHTTP(w, r)
	response := w.Result()
	t.Cleanup(func() { _ = response.Body.Close() })
	if response.StatusCode != wantStatus {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("%s %s returned %d, want %d: %s", method, path, response.StatusCode, wantStatus, data)
	}
	return response
}

func TestCoreHTTPContracts(t *testing.T) {
	off := false
	auth := newHTTPAuth(t, authn.Options{
		BaseURL: "https://auth.example", BasePath: "/identity", RateLimit: &off,
		TrustedOrigins: []string{"https://app.example"},
	})
	request := func(method, path, body string, headers http.Header, status int) *http.Response {
		t.Helper()
		return serve(t, auth, method, "/identity/"+path, body, headers, status)
	}
	serve(t, auth, "GET", "/api/auth/ok", "", nil, 404)
	request("GET", "ok", "", nil, 200)
	request("POST", "ok", "", nil, 404)
	request("GET", "ok/", "", nil, 404)
	request("GET", "list-sessions", "", nil, 401)
	session := request("GET", "get-session", "", nil, 200)
	data, _ := io.ReadAll(session.Body)
	if strings.TrimSpace(string(data)) != "null" || session.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected empty session %q, headers %v", data, session.Header)
	}
	request("POST", "get-session", "", nil, 405)
	form := url.Values{"name": {"An Example"}, "email": {"person@example.test"}, "password": {"this is a test password"}}
	formHeaders := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Origin": {"https://app.example"}}
	signup := request("POST", "sign-up/email", form.Encode(), formHeaders, 200)
	first := signup.Cookies()[0]
	if !first.Secure || !first.HttpOnly || first.SameSite != http.SameSiteLaxMode || first.Path != "/" || first.MaxAge <= 0 {
		t.Fatalf("unexpected cookie attributes: %s", first)
	}
	h := http.Header{"Content-Type": {"application/json"}, "Origin": {"https://app.example"}}
	signin := request("POST", "sign-in/email", `{"email":"person@example.test","password":"this is a test password","rememberMe":false,"callbackURL":"/home?tab=open"}`, h, 200)
	if signin.Header.Get("Location") != "/home?tab=open" {
		t.Fatal("missing sign-in callback")
	}
	cookies := signin.Cookies()
	if len(cookies) != 2 || cookies[0].MaxAge != 0 || !strings.HasSuffix(cookies[1].Name, ".dont_remember") {
		t.Fatalf("unexpected rememberMe=false cookies: %v", cookies)
	}
	var result struct {
		Token    string
		Redirect bool
		URL      string
	}
	if err := json.NewDecoder(signin.Body).Decode(&result); err != nil || !result.Redirect || result.Token == "" || result.URL != "/home?tab=open" {
		t.Fatalf("unexpected sign-in result: %+v, %v", result, err)
	}
	h.Set("Cookie", cookies[0].Name+"="+cookies[0].Value)
	list := request("GET", "list-sessions", "", h, 200)
	var sessions []authn.Session
	if err := json.NewDecoder(list.Body).Decode(&sessions); err != nil || len(sessions) != 2 {
		t.Fatalf("expected two active sessions: %+v, %v", sessions, err)
	}
	request("POST", "revoke-other-sessions", "", h, 200)
	old := http.Header{"Cookie": {first.Name + "=" + first.Value}}
	request("GET", "list-sessions", "", old, 401)
	revoked := request("POST", "revoke-session", `{"token":"`+result.Token+`"}`, h, 200)
	if len(revoked.Cookies()) < 3 || revoked.Cookies()[0].MaxAge >= 0 {
		t.Fatalf("expected deletion cookies: %v", revoked.Cookies())
	}
	request("GET", "list-sessions", "", h, 401)
}

func TestBrowserRequestValidation(t *testing.T) {
	off := false
	auth := newHTTPAuth(t, authn.Options{BaseURL: "https://auth.example", RateLimit: &off})
	for _, tc := range []struct {
		name, path, body string
		headers          http.Header
		status           int
		code             string
	}{
		{"cross-origin login", "sign-in/email", "{}", http.Header{"Origin": {"https://other.example"}}, 403, "INVALID_ORIGIN"},
		{"cross-site form navigation", "sign-up/email", "{}", http.Header{"Sec-Fetch-Site": {"cross-site"}, "Sec-Fetch-Mode": {"navigate"}}, 403, "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED"},
		{"cookie without origin", "sign-out", "{}", http.Header{"Cookie": {"theme=light"}}, 403, "MISSING_OR_NULL_ORIGIN"},
		{"external callback", "sign-in/email", `{"callbackURL":"https://other.example"}`, nil, 403, "INVALID_CALLBACK_URL"},
		{"ambiguous callback", "sign-in/email", `{"callbackURL":"//other.example"}`, nil, 403, "INVALID_CALLBACK_URL"},
		{"external query callback", "sign-out?callbackURL=https://other.example", "{}", nil, 403, "INVALID_CALLBACK_URL"},
		{"malformed JSON", "sign-in/email", "{", nil, 400, "BAD_REQUEST"},
		{"malformed schema", "sign-in/email", `{"email":[],"password":"test"}`, nil, 400, "VALIDATION_ERROR"},
		{"unsupported media type", "sign-in/email", "credentials", http.Header{"Content-Type": {"text/plain"}}, 415, "UNSUPPORTED_MEDIA_TYPE"},
		{"form boolean", "sign-in/email", "email=a&password=b&rememberMe=false", http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, 400, "VALIDATION_ERROR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.headers == nil {
				tc.headers = make(http.Header)
			}
			if tc.headers.Get("Content-Type") == "" {
				tc.headers.Set("Content-Type", "application/json")
			}
			res := serve(t, auth, "POST", "/api/auth/"+tc.path, tc.body, tc.headers, tc.status)
			var body struct{ Code string }
			if err := json.NewDecoder(res.Body).Decode(&body); err != nil || body.Code != tc.code {
				t.Fatalf("got error %q, want %q: %v", body.Code, tc.code, err)
			}
		})
	}
}

func TestCredentialHTTPRateLimit(t *testing.T) {
	on := true
	auth := newHTTPAuth(t, authn.Options{BaseURL: "https://auth.example", RateLimit: &on})
	for i := 0; i < 3; i++ {
		serve(t, auth, "POST", "/api/auth/sign-in/email", "{}", http.Header{"Content-Type": {"application/json"}}, 400)
	}
	h := http.Header{"Content-Type": {"application/json"}, "X-Forwarded-For": {"203.0.113.10"}}
	res := serve(t, auth, "POST", "/api/auth/sign-in/email", "{}", h, 429)
	if res.Header.Get("X-Retry-After") == "" {
		t.Fatal("missing retry duration")
	}
	serve(t, auth, "POST", "/api/auth/sign-up/email", "{}", h, 400)
}
