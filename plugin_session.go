package authn

import "context"

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
