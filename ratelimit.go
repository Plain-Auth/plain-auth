package plainauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

func prepareRateLimits(opts *Options) error {
	if opts.RateLimit != nil {
		v := *opts.RateLimit
		opts.RateLimit = &v
	}
	base := RateLimitRule{Max: 100, Window: 10 * time.Second}
	if opts.RateLimitDefault != nil {
		base = *opts.RateLimitDefault
		if base.Max < 1 || base.Window < time.Millisecond {
			return errors.New("auth: default rate limit needs a positive maximum and window of at least one millisecond")
		}
	}
	opts.RateLimitDefault = &base
	cloned := make(map[string]*RateLimitRule, len(opts.RateLimitRules))
	for pattern, v := range opts.RateLimitRules {
		if !validRateLimitRoute(pattern) {
			return fmt.Errorf("auth: invalid rate-limit route %q", pattern)
		}
		if v == nil {
			cloned[pattern] = nil
			continue
		}
		rule := *v
		if rule.Max < 1 || rule.Window < time.Millisecond {
			return fmt.Errorf("auth: invalid rate-limit rule for %q", pattern)
		}
		cloned[pattern] = &rule
	}
	opts.RateLimitRules = cloned
	funcs := make(map[string]RateLimitRuleFunc, len(opts.RateLimitRuleFuncs))
	for pattern, f := range opts.RateLimitRuleFuncs {
		if !validRateLimitRoute(pattern) {
			return fmt.Errorf("auth: invalid rate-limit route %q", pattern)
		}
		if _, both := cloned[pattern]; both || f == nil {
			return fmt.Errorf("auth: rate-limit route %q needs either a rule or a function", pattern)
		}
		funcs[pattern] = f
	}
	opts.RateLimitRuleFuncs = funcs
	return nil
}

// validRateLimitRoute accepts an exact route or a wildcard covering the
// descendants of a path segment.
func validRateLimitRoute(pattern string) bool {
	clean := strings.TrimSuffix(pattern, "/*")
	return pattern == "/*" || strings.HasPrefix(clean, "/") && path.Clean(clean) == clean && !strings.ContainsAny(clean, "*?%#\\ \t\r\n")
}

func (a *Auth) ruleForRoute(method, route string) *RateLimitRule {
	if rule, _, ok := a.hostRateLimitRule(route); ok {
		return rule
	}
	return a.builtInRateLimitRule(method, route)
}

// hostRateLimitRule finds the host's entry for route, a rule or a function,
// by exact path or the closest trailing /* prefix.
func (a *Auth) hostRateLimitRule(route string) (*RateLimitRule, RateLimitRuleFunc, bool) {
	rules, funcs := a.opts.RateLimitRules, a.opts.RateLimitRuleFuncs
	lookup := func(pattern string) (*RateLimitRule, RateLimitRuleFunc, bool) {
		if f, ok := funcs[pattern]; ok {
			return nil, f, true
		}
		rule, ok := rules[pattern]
		return rule, nil, ok
	}
	if rule, f, ok := lookup(route); ok {
		return rule, f, true
	}
	for p := route; len(rules)+len(funcs) != 0; {
		i := strings.LastIndexByte(p, '/')
		if i < 0 {
			break
		}
		p = p[:i]
		if rule, f, ok := lookup(p + "/*"); ok {
			return rule, f, true
		}
	}
	return nil, nil, false
}

// requestRateLimitRule is the rule for one request. A host function that
// panics or returns an invalid rule keeps the rule that would apply without it.
func (a *Auth) requestRateLimitRule(r *http.Request, route string) (rule *RateLimitRule) {
	rule, f, ok := a.hostRateLimitRule(route)
	if !ok {
		return a.builtInRateLimitRule(r.Method, route)
	}
	if f == nil {
		return rule
	}
	current := *a.builtInRateLimitRule(r.Method, route)
	defer func() {
		if recover() != nil {
			a.Logger().ErrorContext(r.Context(), "auth: a rate-limit rule function panicked", "route", route)
			rule = &current
		}
	}()
	rule = f(r, current)
	if rule != nil && (rule.Max < 1 || rule.Window < time.Millisecond) {
		a.Logger().ErrorContext(r.Context(), "auth: a rate-limit rule function returned an invalid rule", "route", route)
		return &current
	}
	return rule
}

// builtInRateLimitRule is the plugin, built-in or default rule for route.
func (a *Auth) builtInRateLimitRule(method, route string) *RateLimitRule {
	if ep := a.plugins[endpointKey{method, route}]; ep.RateLimit != nil {
		return ep.RateLimit
	}
	switch {
	case strings.HasPrefix(route, "/sign-in/"), strings.HasPrefix(route, "/sign-up/"), route == "/change-password", route == "/change-email", strings.HasPrefix(route, "/two-factor/"):
		return &RateLimitRule{Max: 3, Window: 10 * time.Second}
	case route == "/request-password-reset", route == "/send-verification-email":
		return &RateLimitRule{Max: 3, Window: time.Minute}
	default:
		return a.opts.RateLimitDefault
	}
}

// RateLimitStorage atomically admits one request, or returns how long the
// caller must wait. An error prevents the request from reaching its handler.
type RateLimitStorage interface {
	ConsumeRateLimit(ctx context.Context, key string, maximum int, window time.Duration, now time.Time) (time.Duration, error)
}

type rateLimitKey struct {
	ip, route string
}

type rateLimitEntry struct {
	count   int
	expires time.Time
}

type rateLimiter struct {
	mu        sync.Mutex
	entries   map[rateLimitKey]rateLimitEntry
	nextSweep time.Time
}

func (a *Auth) rejectRateLimited(w http.ResponseWriter, r *http.Request, route string) bool {
	enabled := a.httpsDeployment()
	if a.opts.RateLimit != nil {
		enabled = *a.opts.RateLimit
	}
	if !enabled || a.opts.ClientIP.DisableTracking {
		return false
	}
	client := a.clientIP(r)
	if client == "" {
		a.missingClientIP.Do(func() {
			a.Logger().WarnContext(r.Context(), "Rate limiting could not determine a client IP and is using one shared counter per route. "+
				"Check that ClientIP.TrustedProxies lists your proxies and that they send a valid address in one of ClientIP.Headers.")
		})
	}
	ip := a.rateLimitIP(client)
	rule := a.requestRateLimitRule(r, route)
	if rule == nil {
		return false
	}
	maximum, window := rule.Max, rule.Window
	now := a.now()
	var retry int
	if store := a.opts.RateLimitStorage; store != nil {
		delay, err := store.ConsumeRateLimit(r.Context(), ip+"|"+route, maximum, window, now)
		if err != nil {
			a.writeAuthError(w, r, err)
			return true
		}
		retry = retrySeconds(delay)
	} else {
		retry = a.limiter.consume(rateLimitKey{ip: ip, route: route}, maximum, window, now)
	}
	if retry > 0 {
		w.Header().Set("X-Retry-After", strconv.Itoa(retry))
		writeAuthJSON(w, http.StatusTooManyRequests, map[string]string{"message": "Too many requests. Please try again later."})
		return true
	}
	return false
}

// consume counts accepted requests within the rolling window. Denied requests
// do not extend it. The entry limit bounds memory consumed by distinct peers.
func (l *rateLimiter) consume(key rateLimitKey, maximum int, window time.Duration, now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		l.entries = make(map[rateLimitKey]rateLimitEntry)
	}
	if !now.Before(l.nextSweep) {
		for k, v := range l.entries {
			if !now.Before(v.expires) {
				delete(l.entries, k)
			}
		}
		l.nextSweep = now.Add(10 * time.Second)
	}
	entry, found := l.entries[key]
	if !found && len(l.entries) >= 100_000 {
		return retrySeconds(window)
	}
	if !now.Before(entry.expires) {
		entry.count = 0
	}
	if entry.count >= maximum {
		return retrySeconds(entry.expires.Sub(now))
	}
	l.entries[key] = rateLimitEntry{count: entry.count + 1, expires: now.Add(window)}
	return 0
}

func retrySeconds(delay time.Duration) int {
	if delay <= 0 {
		return 0
	}
	return int((delay-1)/time.Second) + 1
}
