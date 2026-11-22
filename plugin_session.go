package plainauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// Store returns the current instance's configured identity store.
func (c EndpointContext) Store() Store { return c.Auth.opts.Store }

// SignUpAllowed reports whether a plugin may create a new account.
func (c EndpointContext) SignUpAllowed() bool { return !c.Auth.opts.DisableSignUp }

// RequireFreshSession checks the authoritative session and the configured age for
// a sensitive operation such as enrolling an additional credential.
func (c EndpointContext) RequireFreshSession() (*SessionResult, error) {
	user, err := c.Auth.requireOwnerSession(c.Request.Context(), c.Request.Header)
	if err != nil {
		return nil, err
	}
	if c.Auth.now().Sub(user.Session.CreatedAt) >= c.Auth.opts.FreshAge {
		return nil, &APIError{403, "SESSION_NOT_FRESH", "Session is not fresh"}
	}
	return user, nil
}

// IssueSession lets an authentication plugin persist its verified proof and the
// resulting session in one transaction. The callback must verify the current
// proof owner and commit the provided session before returning its user.
func (c EndpointContext) IssueSession(userID string, commit func(context.Context, StoredSession) (User, error)) (*SessionResult, error) {
	a, r := c.Auth, c.Request
	session, _ := a.newSession(userID, RequestMeta{IPAddress: a.clientIP(r), UserAgent: r.UserAgent()})
	user, err := commit(r.Context(), session)
	if err != nil {
		return nil, err
	}
	if user.ID != userID {
		return nil, ErrNotFound
	}
	result, err := a.withSessionPlugins(r.Context(), session.Session, user)
	if err != nil {
		return nil, err
	}
	if err := a.addSessionCookieHeaders(c.ResponseHeader, r, session.Token, true); err != nil {
		return nil, err
	}
	return result, nil
}

func (a *Auth) presentSession(w http.ResponseWriter, r *http.Request) (any, error) {
	if a.sessionResponse == nil {
		return a.sessionHTTP(w.Header(), r)
	}
	// The underlying endpoint owns renewal, cookie attributes and cache policy.
	// Buffer its headers until the application projection succeeds.
	inner := make(http.Header)
	inner.Set("Cache-Control", "no-store")
	inner.Set("Pragma", "no-cache")
	for _, value := range w.Header().Values("Access-Control-Expose-Headers") {
		inner.Add("Access-Control-Expose-Headers", value)
	}
	body, err := a.sessionHTTP(inner, r)
	if err != nil {
		var public *APIError
		if errors.As(err, &public) {
			return nil, err
		}
		return nil, &APIError{500, "FAILED_TO_GET_SESSION", "Failed to get session"}
	}
	session, ok := body.(*SessionResult)
	if !ok || session == nil {
		mergeSessionHeaders(w.Header(), inner)
		return nil, nil
	}
	if a.translateError != nil {
		a.noteErrorUser(r.Context(), session.Session.Token, session.User)
	}
	output := make(http.Header)
	value, err := a.sessionResponse(EndpointContext{Auth: a, Request: r, ResponseHeader: output}, *session)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	mergeSessionHeaders(w.Header(), output)
	mergeSessionHeaders(w.Header(), inner)
	return json.RawMessage(raw), nil
}

func mergeSessionHeaders(to, from http.Header) {
	for name, values := range from {
		if http.CanonicalHeaderKey(name) != "Set-Cookie" {
			to.Del(name)
		}
		for _, value := range values {
			to.Add(name, value)
		}
	}
}

// ReissueSessionCookie emits the current session cookie and its normal response
// hooks after a plugin changes that session's active context. It preserves the
// browser's persistence choice and leaves the stored session lifetime intact.
func (c EndpointContext) ReissueSessionCookie(session Session) {
	if err := c.TryReissueSessionCookie(session); err != nil {
		c.Auth.Logger().ErrorContext(c.Request.Context(), "Could not reissue the session cookie")
	}
}

// TryReissueSessionCookie reissues the cookie and reports host configuration
// errors to plugins that need to fail the response when publication fails.
func (c EndpointContext) TryReissueSessionCookie(session Session) error {
	return c.Auth.writeSessionCookieHeaders(c.ResponseHeader, c.Request, session.Token, !c.Auth.dontRemember(c.Request))
}
