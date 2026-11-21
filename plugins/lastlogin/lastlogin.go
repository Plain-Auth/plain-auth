// Package lastlogin remembers the last login method in a browser-readable cookie.
package lastlogin

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	auth "github.com/FineStack/frost-auth"
)

// Store persists a login method only for the owner of a live session.
type Store interface {
	SaveSessionLoginMethod(context.Context, string, string, time.Time) error
	UserLoginMethod(context.Context, string) (string, error)
}

type Options struct {
	// Database records recognized sign-ins and exposes the method on session reads.
	Database   Store
	CookieName string
	MaxAge     time.Duration
	Resolve    func(*http.Request) string
	Allow      func(*http.Request, string) bool
}

func New(opts Options) auth.Plugin {
	if opts.MaxAge == 0 {
		opts.MaxAge = 30 * 24 * time.Hour
	}
	p := auth.Plugin{ID: "last-login-method", OnSessionCookie: func(e auth.SessionCookieEvent) {
		var method string
		if opts.Resolve != nil {
			method = opts.Resolve(e.Request)
		}
		if method == "" {
			method = methodForRoute(e.Route)
		}
		if method == "" {
			return
		}
		if opts.Database != nil {
			token := e.Auth.VerifySignedSessionToken(e.Cookie.Value)
			if err := opts.Database.SaveSessionLoginMethod(e.Request.Context(), token, method, time.Now().UTC()); err != nil {
				slog.ErrorContext(e.Request.Context(), "Could not save last login method")
			}
		}
		if opts.Allow != nil && !opts.Allow(e.Request, method) {
			return
		}
		cookie := e.Cookie
		cookie.Name = opts.CookieName
		if cookie.Name == "" {
			cookie.Name = strings.TrimSuffix(e.Cookie.Name, ".session_token") + ".last_used_login_method"
		}
		cookie.Value, cookie.HttpOnly, cookie.MaxAge = url.PathEscape(method), false, int(opts.MaxAge/time.Second)
		if cookie.Valid() == nil {
			e.Header.Add("Set-Cookie", cookie.String())
		}
	}}
	if opts.Database != nil {
		p.ValidateStore = func(auth.Store) error {
			if check, ok := opts.Database.(interface{ CheckLastLogin() error }); ok {
				return check.CheckLastLogin()
			}
			return nil
		}
		p.OnReadSession = func(ctx context.Context, session *auth.SessionResult) error {
			method, err := opts.Database.UserLoginMethod(ctx, session.User.ID)
			if err == nil && method != "" {
				session.User.LastLoginMethod = &method
			}
			return err
		}
	}
	return p
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
