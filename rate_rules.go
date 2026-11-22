package plainauth

import (
	"errors"
	"fmt"
	"path"
	"strings"
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
		// Only accept a wildcard covering descendants of a path segment.
		clean := strings.TrimSuffix(pattern, "/*")
		if pattern != "/*" && (!strings.HasPrefix(clean, "/") || path.Clean(clean) != clean || strings.ContainsAny(clean, "*?%#\\ \t\r\n")) {
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
	return nil
}

func (a *Auth) ruleForRoute(method, route string) *RateLimitRule {
	rules := a.opts.RateLimitRules
	if rule, ok := rules[route]; ok {
		return rule
	}
	for p := route; len(rules) != 0; {
		i := strings.LastIndexByte(p, '/')
		if i < 0 {
			break
		}
		p = p[:i]
		if rule, ok := rules[p+"/*"]; ok {
			return rule
		}
	}
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
