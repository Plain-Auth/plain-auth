package plainauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"
)

// SessionResponseFunc projects a validated HTTP session into a JSON response.
type SessionResponseFunc func(EndpointContext, SessionResult) (any, error)

// OAuthLoginContinuation builds the issuer authorization request after a login
// endpoint actually issues a new browser session. The host installs its signed
// cookie and dispatches the request through the normal authorization route.
type OAuthLoginContinuation func(Session) (*http.Request, error)

// Plugin contributes HTTP endpoints to an Auth instance.
type Plugin struct {
	// StoredUserFields declares this plugin's scalar user columns for trusted
	// profile readers. The keys are logical names and may map to different columns.
	StoredUserFields map[string]UserField
	// OrganizationRoleFields describes fields on the installed role endpoints.
	OrganizationRoleFields map[string]SessionField
	oauthProxy             *OAuthProxyOptions
	magicLinkRegistration  bool
	phoneNumber            *PhoneNumberOptions
	// TranslateError returns a localized HTTP error message for the request.
	// An empty result preserves the original error response.
	TranslateError     func(ErrorContext, APIError) string
	CredentialSessions *CredentialSessionResolver
	username           *UsernameOptions
	anonymous          *AnonymousOptions
	admin              *AdminOptions
	maxDeviceSessions  *int
	emailOTP           *EmailOTPOptions
	// Hooks run before and after each mounted HTTP endpoint, after the
	// Options hooks and the hooks of earlier plugins.
	Hooks EndpointHooks
	// DatabaseHooks run before and after user, session, account and
	// verification writes, before the Options database hooks and after those
	// of earlier plugins.
	DatabaseHooks DatabaseHooks
	// OnRequest runs for each mounted HTTP request before routing, after the
	// disabled-path check. An error interrupts the request and is written as
	// the response. Request is a copy the hook may edit: header and query
	// changes reach the endpoint. Path is relative to the auth mount and is
	// not re-resolved. ClientIP follows the host's proxy policy.
	OnRequest func(RequestContext) error
	// OnResponse runs once for each response to a request that passed
	// OnRequest, before anything is written to the client, and may change its
	// status, headers and body. Each plugin's OnResponse runs, in plugin order.
	OnResponse func(*ResponseContext)
	// Middleware runs before the endpoint hooks for the routes its path matches.
	Middleware []Middleware
	// OnSessionsEnded observes sessions the store ended, after its
	// transaction commits and outside it, when the store implements
	// SessionEndReporter. Observers run in plugin order; a panic is logged.
	OnSessionsEnded func(context.Context, SessionsEnded)
	// PrepareOAuthLogin verifies a signed oauth_query before credential handling.
	PrepareOAuthLogin func(EndpointContext, string) (OAuthLoginContinuation, error)
	// PrepareOAuthSelection verifies a signed post-login query before an
	// organization or team switch. It resumes only after a session cookie is issued.
	PrepareOAuthSelection func(EndpointContext, string) (OAuthLoginContinuation, error)
	// SessionResponse shapes the authenticated GET /get-session JSON response.
	// One plugin per instance may supply it. An anonymous response stays null.
	SessionResponse SessionResponseFunc
	// ProjectDeviceSessions also applies SessionResponse to each remembered account.
	ProjectDeviceSessions bool
	serviceJWT            *JWTOptions
	// ConfigureStore returns the store view this instance uses, such as one
	// that reads the plugin's declared columns. New calls it once, in plugin
	// order, and later plugins and ValidateStore see the returned view.
	ConfigureStore func(Store) (Store, error)
	ValidateStore  func(Store) error
	// ValidateVerificationStore is set by a plugin that keeps verification
	// records in its own store and runs their hooks with
	// EndpointContext.CreateVerification and SpendVerification, or with
	// GateVerifications when its store decides them in a transaction. When
	// verification hooks are set, New calls it with the store and the hooks
	// that are set, and fails with its error, which names what the store
	// lacks, rather than let the plugin spend a record its hooks never saw.
	ValidateVerificationStore func(Store, VerificationHookSet) error
	oneTime                   *OneTimeTokenOptions
	// OnValidateNewPassword checks a proposed credential before it is stored.
	OnValidateNewPassword func(ctx context.Context, path, password string) error
	factor                *TwoFactorOptions
	// OnReadSession populates fields owned by an enabled plugin after session authentication.
	OnReadSession func(context.Context, *SessionResult) error
	ID            string
	Endpoints     []Endpoint
	// WellKnown publishes static JSON documents at issuer-relative discovery
	// paths. It runs once per host after all plugins and stores are configured.
	WellKnown func(*Auth, Store) (map[string]WellKnownDocument, error)
	// SessionToken can supply an alternate credential for session lookups.
	SessionToken func(*Auth, http.Header) string
	// OnSessionCookie runs when a handler issues a session cookie.
	OnSessionCookie func(SessionCookieEvent)
}

type RequestContext struct {
	Request        *http.Request
	Path, ClientIP string
}

// runRequestHooks returns the request the remaining dispatch uses: a copy
// the OnRequest hooks may have edited, or r when no plugin sets OnRequest.
func (a *Auth) runRequestHooks(r *http.Request, route string) (*http.Request, error) {
	var c RequestContext
	for _, plugin := range a.opts.Plugins {
		if plugin.OnRequest == nil {
			continue
		}
		if c.Request == nil {
			c = RequestContext{Request: r.Clone(r.Context()), Path: route, ClientIP: a.clientIP(r)}
		}
		if err := plugin.OnRequest(c); err != nil {
			return r, err
		}
	}
	if c.Request == nil {
		return r, nil
	}
	return c.Request, nil
}

// RateLimitRule configures the maximum number of requests per peer and route during Window.
type RateLimitRule struct {
	Max    int
	Window time.Duration
}

// RateLimitRuleFunc chooses the limit for one request. It receives the
// plugin, built-in or default rule for the route, never a RateLimitRules
// entry, and returns the rule to use, or nil to not limit the request.
type RateLimitRuleFunc func(r *http.Request, current RateLimitRule) *RateLimitRule

// Endpoint declares the HTTP operation and its optional IP-based limit.
type Endpoint struct {
	// OpenAPI is optional JSON operation metadata for this endpoint. It is copied at registration.
	OpenAPI   json.RawMessage
	RateLimit *RateLimitRule
	// SuccessStatus defaults to 200. A 204 response omits the body.
	SuccessStatus int
	Method        string
	Path          string
	RawBody       bool
	Handler       func(EndpointContext) (any, error)
	pluginID      string
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

// Session returns the caller's current session, or nil when the request is
// not authenticated.
func (c EndpointContext) Session() (*SessionResult, error) {
	return c.Auth.GetSession(c.Request.Context(), c.Request.Header)
}

// CallbackURL resolves an application callback like Auth.CallbackURL, also
// trusting the origins TrustedOriginsForRequest added for this request.
func (c EndpointContext) CallbackURL(raw string) (string, error) {
	return c.Auth.callbackURL(c.context(), raw)
}

// PublicURL returns the auth handler's public URL for this request: BaseURL
// and BasePath, or with DynamicBaseURL the request's own allowed host.
func (c EndpointContext) PublicURL() (string, error) {
	return c.Auth.publicURL(c.context())
}

// RequestOrigin returns the origin this request reached with DynamicBaseURL:
// its host, or the host a trusted proxy forwarded, whether or not it is
// allowed, so compare it with a URL built for the request. It is "" for an
// invalid host and reports false without DynamicBaseURL.
func (c EndpointContext) RequestOrigin() (string, bool) {
	return c.Auth.reachedOrigin(c.context())
}

// ErrorPageURL returns the browser error destination for this request.
func (c EndpointContext) ErrorPageURL() (string, error) {
	return c.Auth.errorPageURL(c.context())
}

func (c EndpointContext) context() context.Context {
	if c.Request == nil {
		return context.Background()
	}
	return c.Request.Context()
}

// RequestMetadata returns a detached copy of the HTTP request headers and URL
// for a host callback. The body and parsed form data are excluded.
func (c EndpointContext) RequestMetadata() *http.Request {
	if c.Request == nil {
		return nil
	}
	return accountObserverRequest(c.Request.Context(), c.Request)
}

type endpointKey struct{ method, path string }

func registerPlugins(plugins []Plugin) (map[endpointKey]Endpoint, error) {
	routes := make(map[endpointKey]Endpoint)
	ids := make(map[string]bool)
	hasSessionResponse := false
	hasCredentialResolver := false
	for _, p := range plugins {
		if strings.TrimSpace(p.ID) == "" || ids[p.ID] {
			return nil, fmt.Errorf("authn: missing or duplicate plugin ID %q", p.ID)
		}
		ids[p.ID] = true
		if resolver := p.CredentialSessions; resolver != nil {
			legacy := resolver.Matches != nil || resolver.Resolve != nil
			if hasCredentialResolver || legacy == (resolver.SelectRequest != nil) || legacy && (resolver.Matches == nil || resolver.Resolve == nil) {
				return nil, errors.New("only one complete application credential resolver may be installed")
			}
			hasCredentialResolver = true
		}
		if p.ProjectDeviceSessions && p.SessionResponse == nil {
			return nil, errors.New("auth: projecting remembered sessions requires a session response function")
		}
		if p.SessionResponse != nil {
			if hasSessionResponse {
				return nil, errors.New("auth: only one plugin may customize the session response")
			}
			hasSessionResponse = true
		}
		for _, ep := range p.Endpoints {
			ep.pluginID = p.ID
			if ep.SuccessStatus != 0 && (ep.SuccessStatus < 200 || ep.SuccessStatus >= 300) {
				return nil, fmt.Errorf("invalid success status for %s", ep.Path)
			}
			if ep.OpenAPI != nil {
				var op map[string]json.RawMessage
				if err := json.Unmarshal(ep.OpenAPI, &op); err != nil || op == nil {
					return nil, fmt.Errorf("invalid OpenAPI operation for %s", ep.Path)
				}
				ep.OpenAPI = append(json.RawMessage(nil), ep.OpenAPI...)
			}
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
	Auth    *Auth
	Cookie  http.Cookie
	Route   string
	Request *http.Request
	Header  http.Header
}

func (a *Auth) withSessionPlugins(ctx context.Context, session Session, user User) (*SessionResult, error) {
	session.extraJSON = ""
	if len(a.opts.SessionAdditionalFields) > 0 && !session.IsApplicationCredential() {
		rows := []Session{session}
		if err := a.projectSessionFields(ctx, rows); err != nil {
			return nil, err
		}
		session = rows[0]
		if session.ID == "" {
			return nil, ErrNotFound
		}
	}
	if a.admin != nil && user.AdminUserFields == nil && !session.IsApplicationCredential() {
		stored, owner, err := a.adminStore.Session(ctx, session.Token)
		if errors.Is(err, ErrNotFound) {
			return nil, &APIError{401, "UNAUTHORIZED", "Unauthorized"}
		}
		if err != nil {
			return nil, err
		}
		if stored.ID != session.ID || owner.ID != user.ID {
			return nil, &APIError{401, "UNAUTHORIZED", "Unauthorized"}
		}
		user.AdminUserFields = owner.AdminUserFields
		session.ImpersonatedBy = stored.ImpersonatedBy
	}
	if a.factorStore != nil {
		enabled, err := a.factorStore.FactorEnabled(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		user.TwoFactorEnabled = &enabled
	}
	if err := a.readPublicUserFields(ctx, &user); err != nil {
		return nil, err
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
