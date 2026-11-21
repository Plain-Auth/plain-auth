package betterauth

import (
	"context"
	"net/http"
	"net/netip"
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
	if !enabled {
		return false
	}
	ip := remoteIP(r.RemoteAddr)
	if ip == "" {
		ip = "no-trusted-ip"
	}
	if addr, err := netip.ParseAddr(ip); err == nil && addr.Is6() {
		ip = netip.PrefixFrom(addr, 64).Masked().String()
	}
	maximum := 100
	window := 10 * time.Second
	switch {
	case strings.HasPrefix(route, "/sign-in/"), strings.HasPrefix(route, "/sign-up/"), route == "/change-password", route == "/change-email", strings.HasPrefix(route, "/two-factor/"):
		maximum = 3
	case route == "/request-password-reset", route == "/send-verification-email":
		maximum = 3
		window = time.Minute
	}
	now := a.now()
	var retry int
	if store := a.opts.RateLimitStorage; store != nil {
		delay, err := store.ConsumeRateLimit(r.Context(), ip+"|"+route, maximum, window, now)
		if err != nil {
			writeAuthError(w, err)
			return true
		}
		retry = int((delay + time.Second - 1) / time.Second)
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
		return int(window / time.Second)
	}
	if !now.Before(entry.expires) {
		entry.count = 0
	}
	if entry.count >= maximum {
		return int((entry.expires.Sub(now) + time.Second - 1) / time.Second)
	}
	l.entries[key] = rateLimitEntry{count: entry.count + 1, expires: now.Add(window)}
	return 0
}
