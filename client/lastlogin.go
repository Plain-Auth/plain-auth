package client

import (
	"net/http"
	"net/url"
)

func (c *Client) loginMethodCookie(name string) (*url.URL, string) {
	u, _ := url.Parse(c.base) // New validates the absolute endpoint.
	if name == "" {
		name = "authn.last_used_login_method"
		if u.Scheme == "https" {
			name = "__Secure-" + name
		}
	}
	return u, name
}

// LastLoginMethod reads the browser preference in this client's jar. An empty
// cookieName selects the default for the configured origin.
func (c *Client) LastLoginMethod(cookieName string) string {
	u, name := c.loginMethodCookie(cookieName)
	for _, cookie := range c.http.Jar.Cookies(u) {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

// ClearLastLoginMethod removes the client preference for this origin.
func (c *Client) ClearLastLoginMethod(cookieName string) {
	u, name := c.loginMethodCookie(cookieName)
	c.http.Jar.SetCookies(u, []*http.Cookie{{Name: name, Path: "/", MaxAge: -1, Secure: u.Scheme == "https"}})
}
