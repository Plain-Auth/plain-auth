package goapi_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"github.com/Plain-Org/plain-auth/internal/kvtest"
	"github.com/Plain-Org/plain-auth/plugins/bearer"
)

// With SecondaryStorage and no RateLimitStorage, replicas count requests in
// the storage: one key per client and route, opened with the rule's window
// as its TTL, so two replicas share each limit. A refused request waits the
// whole window, a sign-out naming a counter as its token leaves the counter
// alone, a storage error stops the request, and an explicit
// RateLimitStorage keeps the counters elsewhere.
func TestRateLimitsInSecondaryStorage(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	storage := kvtest.New()
	on := true
	replica := func(limits authn.RateLimitStorage) *authn.Auth {
		auth, err := authn.New(authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true,
			RateLimit: &on, RateLimitStorage: limits, SecondaryStorage: storage, StoreSessionInDatabase: true, Plugins: []authn.Plugin{bearer.New(bearer.Options{})}})
		if err != nil {
			t.Fatal(err)
		}
		return auth
	}
	send := func(auth *authn.Auth, path, body string, header http.Header) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://auth.example/api/auth"+path, strings.NewReader(body))
		r.Header = header
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "[2001:db8:1:2::10]:1234"
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
		return w
	}
	signIn := func(auth *authn.Auth) *httptest.ResponseRecorder {
		return send(auth, "/sign-in/email", `{"email":"ada@example.com","password":"wrong password here"}`, http.Header{"Origin": {"https://auth.example"}})
	}
	const counter = "2001:db8:1:2::/64|/sign-in/email"
	a, b := replica(nil), replica(nil)
	start := time.Now()
	for _, auth := range []*authn.Auth{a, b, a} {
		if w := signIn(auth); w.Code == 429 {
			t.Fatal("a request within the shared limit was refused")
		}
	}
	w := signIn(b)
	if w.Code != 429 || w.Header().Get("X-Retry-After") != "10" {
		t.Fatal("the fourth request across replicas was not refused for the window:", w.Code, w.Header())
	}
	value, ttl, ok := storage.Lookup(counter)
	if !ok || value != "4" || ttl > 10*time.Second || ttl < 10*time.Second-time.Since(start) {
		t.Fatalf("the shared counter held %q with TTL %v (present %v)", value, ttl, ok)
	}
	// Session copies have their own namespace, so a sign-out whose bearer
	// token names the counter deletes nothing else.
	send(a, "/sign-out", `{}`, http.Header{"Authorization": {"Bearer " + counter}})
	if value, _, _ := storage.Lookup(counter); value != "4" {
		t.Fatal("a sign-out with a made-up token removed the rate-limit counter:", value)
	}
	if w := signIn(a); w.Code != 429 {
		t.Fatal("the limit reopened after a sign-out with a made-up token:", w.Code)
	}
	storage.Fail("incr", errors.New("storage is down"))
	if w := signIn(a); w.Code < 500 {
		t.Fatal("a storage error did not stop the request", w.Code)
	}
	storage.Fail("incr", nil)

	// An explicit RateLimitStorage wins, and in-process counters stay out of
	// the storage.
	storage.Clear()
	local := replica(authn.NewMemoryRateLimitStorage())
	for range 3 {
		if w := signIn(local); w.Code == 429 {
			t.Fatal("the local counters refused a request within the limit")
		}
	}
	w = signIn(local)
	if retry, _ := strconv.Atoi(w.Header().Get("X-Retry-After")); w.Code != 429 || retry < 1 || retry > 10 {
		t.Fatal("the local counters did not refuse the fourth request:", w.Code, w.Header())
	}
	for _, key := range storage.Keys() {
		if strings.Contains(key, "|") {
			t.Fatal("an explicit RateLimitStorage still counted in the storage:", key)
		}
	}
}
