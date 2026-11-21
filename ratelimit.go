package stonewrit

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

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
	enabled := strings.HasPrefix(a.opts.BaseURL, "https://")
	if a.opts.RateLimit != nil {
		enabled = *a.opts.RateLimit
	}
	if !enabled || a.opts.ClientIP.DisableTracking {
		return false
	}
	ip := a.rateLimitIP(a.clientIP(r))
	rule := a.ruleForRoute(r.Method, route)
	if rule == nil {
		return false
	}
	maximum, window := rule.Max, rule.Window
	now := a.now()
	var retry int
	if store := a.opts.RateLimitStorage; store != nil {
		delay, err := store.ConsumeRateLimit(r.Context(), ip+"|"+route, maximum, window, now)
		if err != nil {
			writeAuthError(w, err)
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
