package client

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/Stonewrit/stonewrit-auth/internal/configenv"
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
			if decoded, err := url.PathUnescape(cookie.Value); err == nil {
				return decoded
			}
			return cookie.Value
		}
	}
	return ""
}

// ClearLastLoginMethod removes the client preference for this origin.
func (c *Client) ClearLastLoginMethod(cookieName string) {
	u, name := c.loginMethodCookie(cookieName)
	c.http.Jar.SetCookies(u, []*http.Cookie{preferenceExpiry(u, name)})
}

func preferenceExpiry(u *url.URL, name string) *http.Cookie {
	prefix := strings.ToLower(name)
	secure := u.Scheme == "https" || strings.HasPrefix(prefix, "__host-") || strings.HasPrefix(prefix, "__secure-")
	return &http.Cookie{Name: name, Path: "/", MaxAge: -1, Secure: secure}
}

// ClearSharedLastLoginMethod removes both a shared preference and an older
// host-only preference. Use the same cookie name and domain as the server.
// An empty domain selects the configured server hostname.
func (c *Client) ClearSharedLastLoginMethod(cookieName, domain string) error {
	u, name := c.loginMethodCookie(cookieName)
	scope, err := configenv.CookieDomain(u.Hostname(), domain)
	if err != nil {
		return err
	}
	cookie := preferenceExpiry(u, name)
	cookie.Domain = scope
	if err := cookie.Valid(); err != nil {
		return err
	}
	c.ClearLastLoginMethod(cookieName)
	if !strings.HasPrefix(strings.ToLower(name), "__host-") {
		c.http.Jar.SetCookies(u, []*http.Cookie{cookie})
	}
	return nil
}
