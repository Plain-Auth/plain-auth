package plainauth

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// A host function chooses the limit per request from the route's plugin,
// built-in or default rule; a panic or an invalid result keeps that rule.
func TestRateLimitRuleFuncs(t *testing.T) {
	on := true
	var seen RateLimitRule
	opts := Options{BaseURL: "http://example.test", Store: &refreshFixture{}, Secret: strings.Repeat("x", 32), RateLimit: &on,
		RateLimitRuleFuncs: map[string]RateLimitRuleFunc{"/sign-in/*": func(r *http.Request, current RateLimitRule) *RateLimitRule {
			seen = current
			switch r.Header.Get("X-Plan") {
			case "pro":
				return &RateLimitRule{Max: 5, Window: time.Second}
			case "internal":
				return nil
			case "broken":
				return &RateLimitRule{Max: 0, Window: time.Second}
			case "panic":
				panic("plan lookup failed")
			}
			return &current
		}}}
	a, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	a.opts.Logger = slog.New(slog.DiscardHandler)
	allowed := func(plan string, n int) int {
		count := 0
		// Each plan counts from its own client address.
		for range n {
			r := httptest.NewRequest("POST", "/api/auth/sign-in/email", nil)
			r.RemoteAddr = "192.0.2." + strconv.Itoa(len(plan)+1) + ":1"
			r.Header.Set("X-Plan", plan)
			if !a.rejectRateLimited(httptest.NewRecorder(), r, "/sign-in/email") {
				count++
			}
		}
		return count
	}
	if got := allowed("", 5); got != 3 || seen != (RateLimitRule{Max: 3, Window: 10 * time.Second}) {
		t.Fatal("the function did not get the built-in sign-in rule", got, seen)
	}
	if got := allowed("pro", 7); got != 5 {
		t.Fatal("a raised limit was not applied", got)
	}
	if got := allowed("internal", 10); got != 10 {
		t.Fatal("an exempt request was limited", got)
	}
	if got := allowed("broken", 5); got != 3 {
		t.Fatal("an invalid rule did not keep the built-in one", got)
	}
	if got := allowed("panic", 5); got != 3 {
		t.Fatal("a panicking function did not keep the built-in one", got)
	}
	opts.RateLimitRules = map[string]*RateLimitRule{"/sign-in/*": {Max: 1, Window: time.Second}}
	if _, err := New(opts); err == nil {
		t.Fatal("a route with both a rule and a function was accepted")
	}
	// The closest entry wins: a function for an exact route replaces a
	// broader host rule and receives the built-in rule, not the host's.
	opts.RateLimitRules = map[string]*RateLimitRule{"/sign-in/*": {Max: 1, Window: time.Minute}}
	opts.RateLimitRuleFuncs = map[string]RateLimitRuleFunc{"/sign-in/email": func(_ *http.Request, current RateLimitRule) *RateLimitRule {
		seen = current
		return &current
	}}
	if a, err = New(opts); err != nil {
		t.Fatal(err)
	}
	a.opts.Logger = slog.New(slog.DiscardHandler)
	if got := allowed("closest", 5); got != 3 || seen != (RateLimitRule{Max: 3, Window: 10 * time.Second}) {
		t.Fatal("the exact function did not replace the broader host rule", got, seen)
	}
}

// The built-in rules limit sign-in and two-factor routes to 3 per 10 seconds.
func TestBuiltInRateLimitRules(t *testing.T) {
	on := true
	a, err := New(Options{BaseURL: "http://example.test", Store: &refreshFixture{}, Secret: strings.Repeat("x", 32), RateLimit: &on})
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"/sign-in/email", "/two-factor/verify-totp"} {
		if rule := a.ruleForRoute("POST", route); rule == nil || *rule != (RateLimitRule{Max: 3, Window: 10 * time.Second}) {
			t.Fatal("unexpected built-in rule", route, rule)
		}
		blocked := 0
		for range 4 {
			if a.rejectRateLimited(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/auth"+route, nil), route) {
				blocked++
			}
		}
		if blocked != 1 {
			t.Fatal("the fourth request was not limited", route, blocked)
		}
	}
}

// IPv6 addresses are keyed by their /64 by default or the configured prefix,
// whatever their spelling; IPv4 addresses are keyed as they are.
func TestRateLimitIPv6Subnets(t *testing.T) {
	key := func(bits *int, ip string) string {
		a, err := New(Options{BaseURL: "http://example.test", Store: &refreshFixture{}, Secret: strings.Repeat("x", 32), ClientIP: ClientIPOptions{IPv6Subnet: bits}})
		if err != nil {
			t.Fatal(err)
		}
		return a.rateLimitIP(ip)
	}
	n := func(v int) *int { return &v }
	for _, tc := range []struct {
		bits *int
		ip   string
		want string
	}{
		{nil, "2001:db8:abcd:12ff::5", "2001:db8:abcd:12ff::/64"},
		{nil, "2001:0db8:abcd:12ff:0000:0000:0000:0009", "2001:db8:abcd:12ff::/64"},
		{n(128), "2001:db8::5", "2001:db8::5/128"},
		{n(48), "2001:db8:abcd:12ff::5", "2001:db8:abcd::/48"},
		{n(32), "2001:db8:abcd:12ff::5", "2001:db8::/32"},
		{n(48), "192.0.2.7", "192.0.2.7"},
	} {
		if got := key(tc.bits, tc.ip); got != tc.want {
			t.Errorf("%s with %v: got %s, want %s", tc.ip, tc.bits, got, tc.want)
		}
	}
	for _, bits := range []int{-1, 129} {
		if _, err := New(Options{BaseURL: "http://example.test", Store: &refreshFixture{}, Secret: strings.Repeat("x", 32), ClientIP: ClientIPOptions{IPv6Subnet: &bits}}); err == nil {
			t.Fatal("an out-of-range IPv6 subnet was accepted", bits)
		}
	}
}
