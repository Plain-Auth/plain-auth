package betterauth

import (
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
)

// Plugin contributes HTTP endpoints to an Auth instance.
type Plugin struct {
	ID        string
	Endpoints []Endpoint
	// SessionToken can supply an alternate credential for session lookups.
	SessionToken func(*Auth, http.Header) string
	// OnSessionCookie runs when a handler issues a session cookie.
	OnSessionCookie func(SessionCookieEvent)
}

// Endpoint serves one method at an exact path relative to the auth base path.
// RawBody preserves a size-limited request body for protocols with signed payloads.
type Endpoint struct {
	Method  string
	Path    string
	RawBody bool
	Handler func(EndpointContext) (any, error)
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
	for _, p := range plugins {
		if strings.TrimSpace(p.ID) == "" || ids[p.ID] {
			return nil, fmt.Errorf("betterauth: missing or duplicate plugin ID %q", p.ID)
		}
		ids[p.ID] = true
		for _, ep := range p.Endpoints {
			if !strings.HasPrefix(ep.Path, "/") || ep.Path == "/" || path.Clean(ep.Path) != ep.Path || strings.ContainsAny(ep.Path, "%?#\\ \t\r\n") {
				return nil, fmt.Errorf("betterauth: plugin %q has invalid endpoint path %q", p.ID, ep.Path)
			}
			switch ep.Method {
			case http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodPut, http.MethodPatch:
			default:
				return nil, fmt.Errorf("betterauth: plugin %q has unsupported method %q", p.ID, ep.Method)
			}
			if ep.Handler == nil {
				return nil, errors.New("betterauth: plugin endpoint requires a handler")
			}
			key := endpointKey{ep.Method, ep.Path}
			if _, found := routes[key]; found || coreMethods[ep.Path] == ep.Method || (ep.Path == "/get-session" && ep.Method == http.MethodPost) {
				return nil, fmt.Errorf("betterauth: duplicate %s endpoint %q", ep.Method, ep.Path)
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
