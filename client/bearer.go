package client

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// WithBearerToken creates a client for one bearer credential on the same auth
// origin. Calls through the returned client neither read nor store cookies.
// The original cookie-authenticated client can continue its own login.
func (c *Client) WithBearerToken(token string) (*Client, error) {
	const symbols = "-._~+/%="
	if token == "" || strings.ContainsFunc(token, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' || strings.ContainsRune(symbols, r))
	}) {
		return nil, errors.New("plainauth/client: invalid bearer credential")
	}
	h := &http.Client{
		Transport: c.http.Transport, Timeout: c.http.Timeout,
		CheckRedirect: c.http.CheckRedirect, Jar: bearerJar{},
	}
	return &Client{base: c.base, origin: c.origin, http: h, bearer: token}, nil
}

// Bearer requests must remain bound to their supplied identity even if a
// previous response tried to set a session cookie.
type bearerJar struct{}

func (bearerJar) Cookies(*url.URL) []*http.Cookie     { return nil }
func (bearerJar) SetCookies(*url.URL, []*http.Cookie) {}
