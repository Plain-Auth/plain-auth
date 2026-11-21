package frostauth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// DeviceSessionStore operates on sessions proven by signed device cookies.
// The map keys are exact, case-sensitive tokens. RevokeDeviceSession checks the
// active session in the same transaction as the deletion and returns ErrNotFound
// if the active login has expired or was revoked.
type DeviceSessionStore interface {
	DeviceSessions(context.Context, []string, time.Time) (map[string]SessionResult, error)
	DeleteDeviceSessions(context.Context, []string) error
	RevokeDeviceSession(ctx context.Context, activeToken, targetToken string, now time.Time) error
}

type MultiSessionOptions struct {
	// MaximumSessions defaults to five. An explicit zero disables remembering new accounts.
	MaximumSessions *int
}

func NewMultiSession(options MultiSessionOptions) (Plugin, error) {
	maximum := 5
	if options.MaximumSessions != nil {
		maximum = *options.MaximumSessions
	}
	if maximum < 0 {
		return Plugin{}, errors.New("authn: maximum device sessions must be nonnegative")
	}
	return Plugin{ID: "multi-session", maxDeviceSessions: &maximum, Endpoints: []Endpoint{
		{Method: http.MethodGet, Path: "/multi-session/list-device-sessions", Handler: listDeviceSessions},
		{Method: http.MethodPost, Path: "/multi-session/set-active", Handler: setActiveDeviceSession},
		{Method: http.MethodPost, Path: "/multi-session/revoke", Handler: revokeDeviceSession},
	}}, nil
}

type deviceCookies struct {
	tokens     []string
	persistent map[string]bool
}

func (a *Auth) deviceCookieName(token string) string {
	return a.cookieName() + "_multi-" + strings.ToLower(token)
}

// Sign the namespace, purpose and original remember-me setting along with the
// token. Switching back to a browser-only account must preserve that choice.
func (a *Auth) deviceCookie(token string, persistent bool) *http.Cookie {
	mode := "browser"
	if persistent {
		mode = "persistent"
	}
	cookie := a.sessionCookie(a.cookieName()+"|device|"+mode+"|"+token, persistent)
	cookie.Name = a.deviceCookieName(token)
	return cookie
}

func (a *Auth) readDeviceCookies(headers http.Header) deviceCookies {
	result := deviceCookies{persistent: make(map[string]bool)}
	r := http.Request{Header: headers}
	name := a.cookieName()
	for _, cookie := range r.Cookies() {
		if !strings.HasPrefix(cookie.Name, name+"_multi-") {
			continue
		}
		payload := a.VerifySignedSessionToken(cookie.Value)
		value, ok := strings.CutPrefix(payload, name+"|device|")
		if !ok {
			continue
		}
		mode, token, ok := strings.Cut(value, "|")
		if !ok || token == "" || (mode != "browser" && mode != "persistent") || cookie.Name != a.deviceCookieName(token) {
			continue
		}
		if _, seen := result.persistent[token]; seen {
			continue
		}
		result.tokens = append(result.tokens, token)
		result.persistent[token] = mode == "persistent"
	}
	return result
}

func (a *Auth) clearDeviceCookie(headers http.Header, token string) {
	c := a.clearSessionCookie()
	c.Name = a.deviceCookieName(token)
	headers.Add("Set-Cookie", c.String())
}

// Remembering another login is optional. If storage is unavailable, keep the
// already-issued primary login and leave the browser's existing entries intact.
func (a *Auth) rememberDeviceSession(h http.Header, r *http.Request, token string, persistent bool) {
	held := a.readDeviceCookies(r.Header)
	if _, exists := held.persistent[token]; exists {
		return
	}
	if len(held.tokens) == 0 {
		if a.maxDeviceSessions > 0 {
			h.Add("Set-Cookie", a.deviceCookie(token, persistent).String())
		}
		return
	}
	ctx := r.Context()
	live, err := a.deviceSessions.DeviceSessions(ctx, append(held.tokens, token), a.now())
	if err != nil {
		slog.Warn("could not read remembered sessions")
		return
	}
	newSession, ok := live[token]
	if !ok {
		return
	}
	var stale, replaced []string
	otherUsers := map[string]bool{}
	for _, old := range held.tokens {
		item, ok := live[old]
		switch {
		case !ok:
			stale = append(stale, old)
		case item.User.ID == newSession.User.ID:
			replaced = append(replaced, old)
		default:
			otherUsers[item.User.ID] = true
		}
	}
	if len(replaced) > 0 {
		if err := a.deviceSessions.DeleteDeviceSessions(ctx, replaced); err != nil {
			slog.Warn("could not replace remembered sessions")
			return
		}
	}
	for _, old := range append(stale, replaced...) {
		a.clearDeviceCookie(h, old)
	}
	if len(otherUsers) < a.maxDeviceSessions {
		h.Add("Set-Cookie", a.deviceCookie(token, persistent).String())
	}
}

func listDeviceSessions(c EndpointContext) (any, error) {
	a, r := c.Auth, c.Request
	held := a.readDeviceCookies(r.Header)
	live, err := a.deviceSessions.DeviceSessions(r.Context(), held.tokens, a.now())
	if err != nil {
		return nil, err
	}
	out := []any{}
	seen := map[string]bool{}
	for _, token := range held.tokens {
		item, ok := live[token]
		if !ok || seen[item.User.ID] || len(out) >= a.maxDeviceSessions {
			a.clearDeviceCookie(c.ResponseHeader, token)
			continue
		}
		seen[item.User.ID] = true
		result, err := a.withSessionPlugins(r.Context(), item.Session, item.User)
		if err != nil {
			return nil, err
		}
		var view any = result
		if a.deviceSessionResponse != nil {
			view, err = a.deviceSessionResponse(c, *result)
			if err != nil {
				return nil, err
			}
		}
		out = append(out, view)
	}
	return out, nil
}

func invalidDeviceToken() error {
	return &APIError{401, "INVALID_SESSION_TOKEN", "Invalid session token"}
}

func provenDeviceToken(c EndpointContext) (string, deviceCookies, error) {
	token, err := requiredString(c.Body, "sessionToken")
	if err != nil {
		return "", deviceCookies{}, err
	}
	cookies := c.Auth.readDeviceCookies(c.Request.Header)
	if _, ok := cookies.persistent[token]; !ok {
		return "", cookies, invalidDeviceToken()
	}
	return token, cookies, nil
}

func (a *Auth) activateDeviceCookie(c EndpointContext, row Session, persistent bool) {
	cookie := a.sessionCookie(row.Token, persistent)
	if persistent {
		remaining := row.ExpiresAt.Sub(a.now()).Round(time.Second)
		cookie.MaxAge = max(1, min(cookie.MaxAge, int(remaining/time.Second)))
	}
	a.emitSessionCookieHeaders(c.ResponseHeader, c.Request, cookie)
	a.writeRememberPreference(c.ResponseHeader, c.Request, persistent)
}

func setActiveDeviceSession(c EndpointContext) (any, error) {
	token, held, err := provenDeviceToken(c)
	if err != nil {
		return nil, err
	}
	a := c.Auth
	live, err := a.deviceSessions.DeviceSessions(c.Request.Context(), []string{token}, a.now())
	if err != nil {
		return nil, err
	}
	item, ok := live[token]
	if !ok {
		a.clearDeviceCookie(c.ResponseHeader, token)
		return nil, invalidDeviceToken()
	}
	result, err := a.withSessionPlugins(c.Request.Context(), item.Session, item.User)
	if err != nil {
		return nil, err
	}
	a.activateDeviceCookie(c, item.Session, held.persistent[token])
	return result, nil
}

func revokeDeviceSession(c EndpointContext) (any, error) {
	a, r := c.Auth, c.Request
	active := a.cookieToken(r.Header)
	if active == "" {
		return nil, &APIError{401, "UNAUTHORIZED", "Unauthorized"}
	}
	token, held, err := provenDeviceToken(c)
	if err != nil {
		return nil, err
	}
	if err := a.deviceSessions.RevokeDeviceSession(r.Context(), active, token, a.now()); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, &APIError{401, "UNAUTHORIZED", "Unauthorized"}
		}
		return nil, err
	}
	a.clearDeviceCookie(c.ResponseHeader, token)
	if active == token {
		live, err := a.deviceSessions.DeviceSessions(r.Context(), held.tokens, a.now())
		if err != nil {
			a.expireSessionCookieHeaders(c.ResponseHeader, r)
			return nil, err
		}
		for _, next := range held.tokens {
			if item, ok := live[next]; ok {
				a.activateDeviceCookie(c, item.Session, held.persistent[next])
				return map[string]bool{"status": true}, nil
			}
		}
		a.expireSessionCookieHeaders(c.ResponseHeader, r)
	}
	return map[string]bool{"status": true}, nil
}
