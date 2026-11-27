package plainauth

// EndSession ends the session with this token, running the session delete
// hooks as sign-out does, so a store that reports session ends reports it.
// When the browser's signed session cookie names it, the response also
// expires the browser's session cookies, and with multi-session its device
// cookie. A delete hook that skips the write keeps the session; the cookies
// still expire, as with sign-out.
func (c EndpointContext) EndSession(token string) error {
	ctx := c.Request.Context()
	if _, err := c.Auth.deleteSessionsWithHooks(ctx, func() ([]Session, error) { return c.Auth.sessionRows(ctx, token) }, func() error {
		return c.Auth.opts.Store.DeleteSession(ctx, token)
	}); err != nil {
		return err
	}
	if token != "" && c.SAMLLogoutBrowserToken() == token {
		c.Auth.expireSessionCookieHeaders(c.ResponseHeader, c.Request)
		if c.Auth.deviceSessions != nil {
			c.Auth.clearDeviceCookie(c.ResponseHeader, c.Request, token)
		}
	}
	return nil
}
