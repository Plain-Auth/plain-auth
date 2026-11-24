package goapi_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

// Read the client address from an ordered list of proxy headers, and warn
// once when rate limiting cannot find one.
func TestClientAddressHeaders(t *testing.T) {
	var logs bytes.Buffer
	on := true
	auth, err := authn.New(authn.Options{
		BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &on,
		Logger:         slog.New(slog.NewTextHandler(&logs, nil)),
		RateLimitRules: map[string]*authn.RateLimitRule{"/sign-in/email": {Max: 1, Window: time.Minute}},
		ClientIP: authn.ClientIPOptions{
			TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			Headers:        []string{"CF-Connecting-IP", "X-Forwarded-For"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	signUp := func(i int, peer string, headers map[string]string) string {
		body := fmt.Sprintf(`{"email":"user%d@example.com","password":"correct horse battery","name":"User"}`, i)
		r := httptest.NewRequest("POST", "https://auth.example/api/auth/sign-up/email", strings.NewReader(body))
		r.RemoteAddr = peer
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://auth.example")
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		read := httptest.NewRequest("GET", "https://auth.example/api/auth/get-session", nil)
		for _, c := range w.Result().Cookies() {
			read.AddCookie(c)
		}
		got := httptest.NewRecorder()
		auth.ServeHTTP(got, read)
		var session struct {
			Session struct {
				IPAddress *string `json:"ipAddress"`
			} `json:"session"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &session); err != nil {
			t.Fatal(err, got.Body)
		}
		if session.Session.IPAddress == nil {
			return ""
		}
		return *session.Session.IPAddress
	}
	for i, tc := range []struct {
		name, peer string
		headers    map[string]string
		want       string
	}{
		{"the first listed header wins", "10.0.0.2:443", map[string]string{"CF-Connecting-IP": "203.0.113.7", "X-Forwarded-For": "198.51.100.1"}, "203.0.113.7"},
		{"a missing header falls through to the next", "10.0.0.2:443", map[string]string{"X-Forwarded-For": "198.51.100.1, 10.0.0.9"}, "198.51.100.1"},
		{"a malformed header falls through to the next", "10.0.0.2:443", map[string]string{"CF-Connecting-IP": "unknown", "X-Forwarded-For": "198.51.100.1"}, "198.51.100.1"},
		{"an untrusted peer's headers are ignored", "192.0.2.50:443", map[string]string{"CF-Connecting-IP": "203.0.113.7"}, "192.0.2.50"},
		{"no listed header gives the proxy address", "10.0.0.2:443", nil, "10.0.0.2"},
		{"only malformed headers give no address", "10.0.0.2:443", map[string]string{"CF-Connecting-IP": "unknown"}, ""},
		{"the warning is logged once", "10.0.0.2:443", map[string]string{"X-Forwarded-For": "unknown"}, ""},
	} {
		if got := signUp(i, tc.peer, tc.headers); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
	// Requests without an address share one counter per route.
	signIn := func(header string) int {
		r := httptest.NewRequest("POST", "https://auth.example/api/auth/sign-in/email", strings.NewReader(`{"email":"user0@example.com","password":"wrong password"}`))
		r.RemoteAddr = "10.0.0.2:443"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://auth.example")
		r.Header.Set("X-Forwarded-For", header)
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
		return w.Code
	}
	for _, tc := range []struct {
		header string
		want   int
	}{{"198.51.100.1", 401}, {"198.51.100.2", 401}, {"unknown", 401}, {"also unknown", 429}} {
		if got := signIn(tc.header); got != tc.want {
			t.Errorf("sign-in via %q: got %d, want %d", tc.header, got, tc.want)
		}
	}
	if n := strings.Count(logs.String(), "could not determine a client IP"); n != 1 {
		t.Fatalf("logged the missing address warning %d times: %s", n, logs.String())
	}
}
