package plainauth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// EndpointHooks run around the mounted HTTP endpoints. Options hooks run
// first, then each plugin's hooks in plugin order.
//
// Before hooks run once a request has passed disabled paths, rate limits, the
// origin check and body decoding, and before the endpoint reads its input.
// After hooks run once the endpoint returns, before the response is written.
// Neither runs for direct Go method calls such as Auth.SignUpEmail.
type EndpointHooks struct {
	Before []EndpointHook
	After  []EndpointHook
}

// EndpointHook runs Run for each endpoint call Match accepts. A nil Match
// accepts every endpoint.
//
// In a before hook, an error rejects the request: it is written as the
// response and neither the endpoint nor the after hooks run. A hook may also
// answer with HookContext.Respond, or edit HookContext.Body and the request's
// query and headers for the endpoint to read.
//
// In an after hook, HookContext.Result and HookContext.Err hold the outcome so
// far and may be replaced. A returned APIError or OAuthError replaces the
// outcome and the remaining after hooks still run.
//
// Any other error, or a panic, ends the call with a 500 response.
type EndpointHook struct {
	Match func(*HookContext) bool
	Run   func(*HookContext) error
}

// HookContext describes one HTTP endpoint call to its hooks. Request is a copy
// of the incoming request, so header and query edits never reach the host's
// request. ResponseHeader collects the response headers and cookies.
type HookContext struct {
	EndpointContext
	// Path is the endpoint's route relative to the auth mount, with
	// ":name" segments, such as "/sign-up/email" or "/reset-password/:token".
	Path string
	// Params holds the values of the ":name" segments in Path.
	Params map[string]string
	// Result and Err hold the endpoint's outcome in after hooks.
	Result any
	Err    error

	requestPath string
	responded   bool
}

// Respond answers the request with result from a before hook. The remaining
// before hooks, the endpoint and the after hooks do not run. A result is
// written as JSON unless it is a Redirect, HTMLPage, XMLDocument or
// EmptyResponse.
func (c *HookContext) Respond(result any) {
	c.Result, c.Err, c.responded = result, nil, true
}

// NewSession returns the session whose cookie this response issues, or nil
// when it issues none. Use it in after hooks, for example to notify a new
// user after sign-up. It is nil after a failed sign-in, after a sign-out and
// after DeleteSessionCookie.
func (c *HookContext) NewSession() (*SessionResult, error) {
	token := c.Auth.issuedSessionToken(c.ResponseHeader)
	if token == "" {
		return nil, nil
	}
	return c.Auth.sessionForToken(c.Request.Context(), token)
}

// SetCookie adds a Set-Cookie header to the response. Auth.Cookie and
// Auth.SignedCookie build cookies with the instance's prefix and attributes.
func (c *HookContext) SetCookie(cookie *http.Cookie) {
	if line := cookie.String(); line != "" {
		c.ResponseHeader.Add("Set-Cookie", line)
	}
}

// DeleteSessionCookie removes the session cookies this response would issue
// and expires the browser's session cookies instead. Call it when an after
// hook turns a successful sign-in into an error.
func (c *HookContext) DeleteSessionCookie() {
	expired := make(http.Header)
	c.Auth.expireSessionCookieHeaders(expired, c.Request)
	names := map[string]bool{}
	for _, line := range expired.Values("Set-Cookie") {
		if cookie, err := http.ParseSetCookie(line); err == nil {
			names[cookie.Name] = true
		}
	}
	var kept []string
	for _, line := range c.ResponseHeader.Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(line)
		if err == nil && (names[cookie.Name] || names[chunkedCookieBase(cookie.Name)]) {
			continue
		}
		kept = append(kept, line)
	}
	c.ResponseHeader.Del("Set-Cookie")
	for _, line := range append(kept, expired.Values("Set-Cookie")...) {
		c.ResponseHeader.Add("Set-Cookie", line)
	}
}

// chunkedCookieBase returns the cookie name a "<name>.<index>" chunk belongs to.
func chunkedCookieBase(name string) string {
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		if _, err := strconv.ParseUint(name[i+1:], 10, 53); err == nil {
			return name[:i]
		}
	}
	return name
}

type boundHook struct {
	EndpointHook
	source string
}

func endpointHooks(opts Options) (before, after []boundHook) {
	add := func(hooks EndpointHooks, source string) {
		for _, h := range hooks.Before {
			before = append(before, boundHook{h, source})
		}
		for _, h := range hooks.After {
			after = append(after, boundHook{h, source})
		}
	}
	before = middlewareHooks(opts.Plugins)
	add(opts.Hooks, "user")
	for _, p := range opts.Plugins {
		add(p.Hooks, "plugin:"+p.ID)
	}
	return before, after
}

func validEndpointHooks(hooks EndpointHooks, source string) error {
	for _, list := range [][]EndpointHook{hooks.Before, hooks.After} {
		for _, h := range list {
			if h.Run == nil {
				return fmt.Errorf("auth: %s endpoint hook needs Run", source)
			}
		}
	}
	return nil
}

// errHookFailed answers a hook panic or an internal hook error.
var errHookFailed = errors.New("auth: endpoint hook failed")

// runHook runs Match and Run for one hook and reports whether the hook matched.
func (a *Auth) runHook(h boundHook, c *HookContext) (matched bool, err error) {
	defer func() {
		if p := recover(); p != nil {
			a.Logger().ErrorContext(c.Request.Context(), "auth: endpoint hook panicked", "source", h.source, "path", c.Path, "panic", p)
			err = errHookFailed
		}
	}()
	if h.Match != nil && !h.Match(c) {
		return false, nil
	}
	return true, h.Run(c)
}

// publicError reports whether writeAuthError answers err with its own status
// rather than a generic 500.
func publicError(err error) bool {
	var status interface{ statusOnlyCode() int }
	var oauthErr *OAuthError
	var apiErr *APIError
	return errors.As(err, &status) || errors.As(err, &oauthErr) && oauthErr.Status >= 400 && oauthErr.Status <= 599 || errors.As(err, &apiErr)
}

// callEndpoint runs the endpoint hooks around endpoint and returns the final
// outcome. path is the route template and actual the request's mount-relative
// path, which supplies the template's parameters.
func (a *Auth) callEndpoint(w http.ResponseWriter, r *http.Request, path, actual string, body wireBody, endpoint func(*http.Request, wireBody) (any, error)) (any, error) {
	if len(a.beforeHooks) == 0 && len(a.afterHooks) == 0 {
		return endpoint(r, body)
	}
	c := &HookContext{
		EndpointContext: EndpointContext{Auth: a, Request: r.Clone(r.Context()), Body: body, ResponseHeader: w.Header()},
		Path:            path,
		Params:          routeParams(path, actual),
		requestPath:     actual,
	}
	ran := false
	for _, h := range a.beforeHooks {
		matched, err := a.runHook(h, c)
		if err != nil {
			return nil, hookError(err)
		}
		ran = ran || matched
		if c.responded {
			return c.Result, nil
		}
	}
	if ran && c.Request.Method != http.MethodGet {
		// A hook may have written a callback from another source into the input.
		if err := a.validateCallbacks(wireBody(c.Body), c.Request.URL.Query()); err != nil {
			return nil, err
		}
	}
	c.Result, c.Err = endpoint(c.Request, wireBody(c.Body))
	if c.Err != nil && !publicError(c.Err) {
		return nil, c.Err
	}
	for _, h := range a.afterHooks {
		if _, err := a.runHook(h, c); err != nil {
			if !publicError(err) {
				return nil, hookError(err)
			}
			c.Result, c.Err = nil, err
		}
	}
	if c.Err != nil {
		return nil, c.Err
	}
	return c.Result, nil
}

func hookError(err error) error {
	if publicError(err) {
		return err
	}
	return fmt.Errorf("%w: %w", errHookFailed, err)
}

// routeParams maps each ":name" segment of template to the matching segment of path.
func routeParams(template, path string) map[string]string {
	if !strings.Contains(template, "/:") {
		return nil
	}
	names, values := strings.Split(template, "/"), strings.Split(path, "/")
	if len(names) != len(values) {
		return nil
	}
	params := make(map[string]string)
	for i, name := range names {
		if key, ok := strings.CutPrefix(name, ":"); ok {
			value, err := url.PathUnescape(values[i])
			if err != nil {
				value = values[i]
			}
			params[key] = value
		}
	}
	return params
}
