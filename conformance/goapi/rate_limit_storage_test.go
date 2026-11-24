package goapi_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

// countingLimiter is a host RateLimitStorage that admits a fixed number of
// requests per key and can fail.
type countingLimiter struct {
	mu    sync.Mutex
	seen  map[string]int
	calls []string
	fail  bool
}

func (c *countingLimiter) ConsumeRateLimit(_ context.Context, key string, maximum int, window time.Duration, _ time.Time) (time.Duration, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return 0, errors.New("limiter unavailable")
	}
	c.calls = append(c.calls, key)
	c.seen[key]++
	if c.seen[key] > maximum {
		return window, nil
	}
	return 0, nil
}

// A custom RateLimitStorage decides every limited request: it receives the
// client and route key and the rule, its delay becomes a 429 with
// X-Retry-After, and its error stops the request.
func TestCustomRateLimitStorage(t *testing.T) {
	limiter := &countingLimiter{seen: map[string]int{}}
	on := true
	auth, err := authn.New(authn.Options{BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32), EmailAndPassword: true,
		RateLimit: &on, RateLimitStorage: limiter})
	if err != nil {
		t.Fatal(err)
	}
	signIn := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://auth.example/api/auth/sign-in/email", strings.NewReader(`{"email":"ada@example.com","password":"wrong password here"}`))
		r.Header = http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
		r.RemoteAddr = "192.0.2.10:1234"
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
		return w
	}
	for range 3 {
		if w := signIn(); w.Code == 429 {
			t.Fatal("the storage refused a request within the limit")
		}
	}
	w := signIn()
	if w.Code != 429 || w.Header().Get("X-Retry-After") != "10" {
		t.Fatal("the storage's delay was not a 429 with X-Retry-After", w.Code, w.Header())
	}
	if limiter.calls[0] != "192.0.2.10|/sign-in/email" {
		t.Fatal("unexpected storage key", limiter.calls[0])
	}
	limiter.fail = true
	if w := signIn(); w.Code < 500 {
		t.Fatal("a storage error did not stop the request", w.Code)
	}
}
