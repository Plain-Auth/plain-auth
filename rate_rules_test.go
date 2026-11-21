package fineauth

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHostRateLimitRules(t *testing.T) {
	on := true
	exact := &RateLimitRule{Max: 2, Window: 1500 * time.Millisecond}
	rules := map[string]*RateLimitRule{"/sign-in/*": nil, "/sign-in/email": exact}
	opts := Options{BaseURL: "http://example.test", Store: &refreshFixture{}, Secret: strings.Repeat("x", 32),
		RateLimit: &on, RateLimitDefault: &RateLimitRule{Max: 1, Window: time.Second}, RateLimitRules: rules}
	a, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	exact.Max = 100
	delete(rules, "/sign-in/*")
	post := httptest.NewRequest("POST", "/api/auth/sign-in/email", nil)
	for i := range 3 {
		w := httptest.NewRecorder()
		blocked := a.rejectRateLimited(w, post, "/sign-in/email")
		if blocked != (i == 2) || (blocked && (w.Code != 429 || w.Header().Get("X-Retry-After") != "2")) {
			t.Fatal(i, blocked, w.Code)
		}
	}
	if a.ruleForRoute("POST", "/sign-in/social") != nil {
		t.Fatal("wildcard exemption ignored")
	}
	if def := a.ruleForRoute("GET", "/ok"); def.Max != 1 {
		t.Fatal("default ignored")
	}
	for _, pattern := range []string{"", "/a//b", "relative", "/a*", "/a/*/b", "/a?b"} {
		opts.RateLimitRules = map[string]*RateLimitRule{pattern: nil}
		if _, err := New(opts); err == nil {
			t.Fatal("invalid route", pattern)
		}
	}
}
