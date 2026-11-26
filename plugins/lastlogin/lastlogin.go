// Package lastlogin remembers the last login method in a browser-readable cookie.
package lastlogin

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
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
	// Resolve names the method for a sign-in request. When it is nil or
	// returns "", the route decides: email, the provider ID of
	// /callback/:id (also behind the OAuth proxy), google for One Tap,
	// siwe, passkey, magic-link or email-otp.
	Resolve func(*http.Request) string
	Allow   func(*http.Request, string) bool
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
				e.Auth.Logger().ErrorContext(e.Request.Context(), "Could not save last login method")
			}
		}
		if opts.Allow != nil && !opts.Allow(e.Request, method) {
			return
		}
		// The preference takes the session cookie's attributes, except that
		// pages anywhere on the site must be able to read and clear it.
		cookie := e.Cookie
		cookie.Name, cookie.Path = opts.CookieName, "/"
		if cookie.Name == "" {
			cookie.Name = e.Auth.Cookie("last_used_login_method", "", 0).Name
		}
		lowerName := strings.ToLower(cookie.Name)
		if strings.HasPrefix(lowerName, "__host-") {
			cookie.Domain = ""
		}
		if !cookie.Secure && (strings.HasPrefix(lowerName, "__host-") || strings.HasPrefix(lowerName, "__secure-")) {
			return
		}
		cookie.Value, cookie.HttpOnly, cookie.MaxAge = url.PathEscape(method), false, int(opts.MaxAge/time.Second)
		if cookie.Valid() == nil {
			e.Header.Add("Set-Cookie", cookie.String())
		}
	}}
	if opts.Database != nil {
		p.StoredUserFields = map[string]auth.UserField{"lastLoginMethod": {Type: auth.FieldString}}
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
	if rest, ok := strings.CutPrefix(route, "/callback/"); ok {
		// The provider ID is the first path segment, so the OAuth proxy's
		// /callback/:id/oauth-proxy completion records the provider too.
		id, _, _ := strings.Cut(rest, "/")
		return id
	}
	if strings.HasPrefix(route, "/magic-link/verify") {
		return "magic-link"
	}
	if strings.Contains(route, "/passkey/verify-authentication") {
		return "passkey"
	}
	// The route is the request path, so only SIWE's own routes match: an
	// SSO provider ID such as "siwe-guild" in a callback path records nothing.
	if strings.HasPrefix(route, "/siwe/") {
		return "siwe"
	}
	return ""
}
