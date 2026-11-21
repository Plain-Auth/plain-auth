// Package lastlogin remembers the last login method in a browser-readable cookie.
package lastlogin

import (
	"net/http"
	"strings"
	"time"

	auth "github.com/nabuhadba/go-better-auth"
)

type Options struct {
	CookieName string
	MaxAge     time.Duration
	Resolve    func(*http.Request) string
	Allow      func(*http.Request, string) bool
}

func New(opts Options) auth.Plugin {
	if opts.CookieName == "" {
		opts.CookieName = "better-auth.last_used_login_method"
	}
	if opts.MaxAge == 0 {
		opts.MaxAge = 30 * 24 * time.Hour
	}
	return auth.Plugin{ID: "last-login-method", OnSessionCookie: func(e auth.SessionCookieEvent) {
		var method string
		if opts.Resolve != nil {
			method = opts.Resolve(e.Request)
		}
		if method == "" {
			method = methodForRoute(e.Route)
		}
		if method == "" || (opts.Allow != nil && !opts.Allow(e.Request, method)) {
			return
		}
		cookie := e.Cookie
		cookie.Name, cookie.Value, cookie.HttpOnly, cookie.MaxAge = opts.CookieName, method, false, int(opts.MaxAge/time.Second)
		if cookie.Valid() == nil {
			e.Header.Add("Set-Cookie", cookie.String())
		}
	}}
}

func methodForRoute(route string) string {
	switch route {
	case "/sign-in/email", "/sign-up/email":
		return "email"
	case "/one-tap/callback":
		return "google"
	case "/sign-in/email-otp":
		return "email-otp"
	}
	if id, ok := strings.CutPrefix(route, "/callback/"); ok {
		return id
	}
	if strings.HasPrefix(route, "/magic-link/verify") {
		return "magic-link"
	}
	if strings.Contains(route, "/passkey/verify-authentication") {
		return "passkey"
	}
	if strings.Contains(route, "siwe") {
		return "siwe"
	}
	return ""
}
