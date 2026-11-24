package plainauth

import (
	"net/http"
	"time"
)

// DirectBrowserSession reports whether the current browser supplied the signed
// cookie for this session. Provider logout cannot be initiated with a bearer credential.
func (c EndpointContext) DirectBrowserSession(token string) bool {
	if token == "" || c.Request.Header.Get("Authorization") != "" {
		return false
	}
	cookies := c.Request.CookiesNamed(c.Auth.cookieName())
	return len(cookies) == 1 && c.Auth.VerifySignedSessionToken(cookies[0].Value) == token
}

func (c EndpointContext) samlLogoutCookie(value string, age int) *http.Cookie {
	cookie := c.Auth.oauthCookie("saml_logout", value, age)
	cookie.Secure = true
	cookie.SameSite = http.SameSiteLaxMode
	return cookie
}

// SAMLLogoutCookie returns the independent browser proof for a logout round trip.
func (c EndpointContext) SAMLLogoutCookie() string {
	cookies := c.Request.CookiesNamed(c.samlLogoutCookie("", 0).Name)
	if len(cookies) != 1 {
		return ""
	}
	return cookies[0].Value
}

// SAMLLogoutStarted clears the just-revoked session's browser credentials and
// redirects to the already validated identity provider's signed protocol URL.
func (c EndpointContext) SAMLLogoutStarted(token, target, binding string, ttl time.Duration) any {
	c.Auth.expireSessionCookieHeaders(c.ResponseHeader, c.Request)
	if c.Auth.deviceSessions != nil {
		c.Auth.clearDeviceCookie(c.ResponseHeader, c.Request, token)
	}
	c.ResponseHeader.Add("Set-Cookie", c.samlLogoutCookie(binding, int(ttl/time.Second)).String())
	return Redirect(target)
}

// SAMLLogoutCompleted expires the logout binding. A new login that happened
// while the identity provider processed the request keeps its own session.
func (c EndpointContext) SAMLLogoutCompleted() {
	c.ResponseHeader.Add("Set-Cookie", c.samlLogoutCookie("", -1).String())
}

// SAMLLogoutBrowserToken identifies the one signed local browser cookie so
// an IdP logout can clear it only when its underlying session was revoked.
func (c EndpointContext) SAMLLogoutBrowserToken() string {
	cookies := c.Request.CookiesNamed(c.Auth.cookieName())
	if len(cookies) != 1 {
		return ""
	}
	return c.Auth.VerifySignedSessionToken(cookies[0].Value)
}

// SAMLIDPLogoutCompleted returns the signed response to the registered IdP.
func (c EndpointContext) SAMLIDPLogoutCompleted(target, token string, revoked bool) any {
	if revoked && token != "" && c.DirectBrowserSession(token) {
		c.Auth.expireSessionCookieHeaders(c.ResponseHeader, c.Request)
		if c.Auth.deviceSessions != nil {
			c.Auth.clearDeviceCookie(c.ResponseHeader, c.Request, token)
		}
	}
	return Redirect(target)
}
