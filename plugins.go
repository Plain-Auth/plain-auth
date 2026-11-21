package authn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"
)

// SessionResponseFunc projects a validated HTTP session into a JSON response.
type SessionResponseFunc func(EndpointContext, SessionResult) (any, error)

// Plugin contributes HTTP endpoints to an Auth instance.
type Plugin struct {
	maxDeviceSessions *int

	// OnRequest can reject an HTTP request before endpoint dispatch. Path is
	// relative to the auth mount. ClientIP follows the host's proxy policy.
	OnRequest func(RequestContext) error
	// SessionResponse shapes the authenticated GET /get-session JSON response.
	// One plugin per instance may supply it. An anonymous response stays null.
	SessionResponse SessionResponseFunc
	// ProjectDeviceSessions also applies SessionResponse to each remembered account.
	ProjectDeviceSessions bool
	serviceJWT            *JWTOptions
	ValidateStore         func(Store) error
	oneTime               *OneTimeTokenOptions
	// OnValidateNewPassword checks a proposed credential before it is stored.
	OnValidateNewPassword func(ctx context.Context, path, password string) error
	factor                *TwoFactorOptions
	// OnReadSession populates fields owned by an enabled plugin after session authentication.
	OnReadSession func(context.Context, *SessionResult) error
	ID            string
	Endpoints     []Endpoint
	// SessionToken can supply an alternate credential for session lookups.
	SessionToken func(*Auth, http.Header) string
	// OnSessionCookie runs when a handler issues a session cookie.
	OnSessionCookie func(SessionCookieEvent)
}

type RequestContext struct {
	Request        *http.Request
	Path, ClientIP string
}

func (a *Auth) runRequestHooks(r *http.Request, route string) error {
	var c RequestContext
	for _, plugin := range a.opts.Plugins {
		if plugin.OnRequest == nil {
			continue
		}
		if c.Request == nil {
			c = RequestContext{Request: r, Path: route, ClientIP: a.clientIP(r)}
		}
		if err := plugin.OnRequest(c); err != nil {
			return err
		}
	}
	return nil
}

// RateLimitRule configures the maximum number of requests per peer and route during Window.
type RateLimitRule struct {
	Max    int
	Window time.Duration
}

// Endpoint declares the HTTP operation and its optional IP-based limit.
type Endpoint struct {
	RateLimit *RateLimitRule
	Method    string
	Path      string
	RawBody   bool
	Handler   func(EndpointContext) (any, error)
}

// EndpointContext gives a plugin access to the host auth instance, incoming
// request, decoded JSON fields, and headers for its JSON response. Body is nil
// for GET and raw-body endpoints.
type EndpointContext struct {
	Auth           *Auth
	Request        *http.Request
	Body           map[string]any
	ResponseHeader http.Header
}

type endpointKey struct{ method, path string }

func registerPlugins(plugins []Plugin) (map[endpointKey]Endpoint, error) {
	routes := make(map[endpointKey]Endpoint)
	ids := make(map[string]bool)
	hasSessionResponse := false
	for _, p := range plugins {
		if strings.TrimSpace(p.ID) == "" || ids[p.ID] {
			return nil, fmt.Errorf("authn: missing or duplicate plugin ID %q", p.ID)
		}
		ids[p.ID] = true
		if p.SessionResponse != nil {
			if hasSessionResponse {
				return nil, errors.New("auth: only one plugin may customize the session response")
			}
			hasSessionResponse = true
		}
		for _, ep := range p.Endpoints {
			if !strings.HasPrefix(ep.Path, "/") || ep.Path == "/" || path.Clean(ep.Path) != ep.Path || strings.ContainsAny(ep.Path, "%?#\\ \t\r\n") {
				return nil, fmt.Errorf("authn: plugin %q has invalid endpoint path %q", p.ID, ep.Path)
			}
			switch ep.Method {
			case http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodPut, http.MethodPatch:
			default:
				return nil, fmt.Errorf("authn: plugin %q has unsupported method %q", p.ID, ep.Method)
			}
			if ep.RateLimit != nil {
				rule := *ep.RateLimit
				if rule.Max < 1 || rule.Window <= 0 {
					return nil, fmt.Errorf("auth: invalid rate limit for %s", ep.Path)
				}
				ep.RateLimit = &rule
			}
			if ep.Handler == nil {
				return nil, errors.New("authn: plugin endpoint requires a handler")
			}
			key := endpointKey{ep.Method, ep.Path}
			if _, found := routes[key]; found || coreMethods[ep.Path] == ep.Method || (ep.Path == "/get-session" && ep.Method == http.MethodPost) {
				return nil, fmt.Errorf("authn: duplicate %s endpoint %q", ep.Method, ep.Path)
			}
			routes[key] = ep
		}
	}
	return routes, nil
}

// SessionCookieEvent lets an extension add response headers when a session is issued.
type SessionCookieEvent struct {
	Cookie  http.Cookie
	Route   string
	Request *http.Request
	Header  http.Header
}

func (a *Auth) withSessionPlugins(ctx context.Context, session Session, user User) (*SessionResult, error) {
	if a.factorStore != nil {
		enabled, err := a.factorStore.FactorEnabled(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		user.TwoFactorEnabled = &enabled
	}
	result := &SessionResult{Session: session, User: user}
	for _, plugin := range a.opts.Plugins {
		if plugin.OnReadSession != nil {
			if err := plugin.OnReadSession(ctx, result); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}
