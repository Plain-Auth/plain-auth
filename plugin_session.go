package authn

import (
	"context"
	"net/http"
)

// Store returns the current instance's configured identity store.
func (c EndpointContext) Store() Store { return c.Auth.opts.Store }

// RequireFreshSession checks the authoritative session and the configured age for
// a sensitive operation such as enrolling an additional credential.
func (c EndpointContext) RequireFreshSession() (*SessionResult, error) {
	user, err := c.Auth.requireSession(c.Request.Context(), c.Request.Header)
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
	a.addSessionCookieHeaders(c.ResponseHeader, r, session.Token, true)
	return result, nil
}

func (a *Auth) presentSession(w http.ResponseWriter, r *http.Request) (any, error) {
	body, err := a.sessionHTTP(w, r)
	if err != nil || a.sessionResponse == nil || r.Method != http.MethodGet {
		return body, err
	}
	var session *SessionResult
	switch result := body.(type) {
	case *SessionResult:
		session = result
	case deferredSessionResponse:
		session = result.SessionResult
	default:
		return body, nil
	}
	return a.sessionResponse(EndpointContext{Auth: a, Request: r, ResponseHeader: w.Header()}, *session)
}

// ReissueSessionCookie emits the current session cookie and its normal response
// hooks after a plugin changes that session's active context. It preserves the
// browser's persistence choice and leaves the stored session lifetime intact.
func (c EndpointContext) ReissueSessionCookie(session Session) {
	c.Auth.writeSessionCookieHeaders(c.ResponseHeader, c.Request, session.Token, !c.Auth.dontRemember(c.Request))
}
