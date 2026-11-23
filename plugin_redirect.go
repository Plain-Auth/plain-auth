package plainauth

import "strings"

// Redirect returns a 302 endpoint result for a callback allowed by this Auth instance.
func (c EndpointContext) Redirect(callback string) (any, error) {
	target, err := c.Auth.CallbackURL(callback)
	if err != nil {
		return nil, err
	}
	return authRedirect(target), nil
}

// RegisteredOAuthRedirect delivers the result of an authorization request to
// a URI the issuer has already validated against the client's registration,
// or to an issuer-controlled page. Fetch clients consume the URL as JSON.
func (c EndpointContext) RegisteredOAuthRedirect(target string) any {
	c.ResponseHeader.Set("Cache-Control", "no-store")
	c.ResponseHeader.Set("Pragma", "no-cache")
	c.ResponseHeader.Set("Referrer-Policy", "no-referrer")
	if c.Request.Header.Get("Sec-Fetch-Mode") == "cors" || strings.Contains(c.Request.Header.Get("Accept"), "application/json") {
		return map[string]any{"redirect": true, "url": target}
	}
	return authRedirect(target)
}
