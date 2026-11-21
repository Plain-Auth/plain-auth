package betterauth

import (
	"net/netip"
	"strings"
	"sync"
	"time"
)

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

func (a *Auth) limitRequest(ip, route string) int {
	enabled := strings.HasPrefix(a.opts.BaseURL, "https://")
	if a.opts.RateLimit != nil {
		enabled = *a.opts.RateLimit
	}
	if !enabled {
		return 0
	}
	if addr, err := netip.ParseAddr(ip); err == nil && addr.Is6() {
		ip = netip.PrefixFrom(addr, 64).Masked().String()
	}
	maximum := 100
	window := 10 * time.Second
	switch route {
	case "/sign-in/email", "/sign-up/email", "/change-password", "/change-email":
		maximum = 3
	case "/request-password-reset", "/send-verification-email":
		maximum = 3
		window = time.Minute
	}
	return a.limiter.consume(rateLimitKey{ip: ip, route: route}, maximum, window, time.Now())
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
