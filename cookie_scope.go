package plainauth

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/Plain-Auth/plain-auth/internal/configenv"
)

// CrossSubDomainCookiesOptions selects the host and descendants that receive
// shared cookies. Use a parent domain to share cookies with sibling hosts.
type CrossSubDomainCookiesOptions struct {
	Domain string
}

func secureCookies(opts *Options) bool {
	if opts.UseSecureCookies != nil {
		return *opts.UseSecureCookies
	}
	return strings.HasPrefix(opts.BaseURL, "https://")
}

func prepareCookieScope(opts *Options) error {
	secure := secureCookies(opts)
	opts.UseSecureCookies = &secure
	prefix := strings.ToLower(opts.CookiePrefix)
	hostOnly := strings.HasPrefix(prefix, "__host-")
	if !secure && (hostOnly || strings.HasPrefix(prefix, "__secure-")) {
		return errors.New("auth: a reserved cookie prefix requires Secure cookies")
	}
	if opts.CrossSubDomainCookies == nil {
		return nil
	}
	if hostOnly {
		return errors.New("auth: a __Host- cookie prefix requires host-only cookies")
	}
	base, err := url.Parse(opts.BaseURL)
	if err != nil {
		return err
	}
	domain, err := configenv.CookieDomain(base.Hostname(), opts.CrossSubDomainCookies.Domain)
	if err != nil {
		return err
	}
	opts.CrossSubDomainCookies = &CrossSubDomainCookiesOptions{Domain: domain}
	return nil
}

func (a *Auth) browserCookie(name, value string, maxAge int) *http.Cookie {
	c := &http.Cookie{Name: a.prefixedCookieName(name), Value: value, Path: "/", MaxAge: maxAge,
		Secure: secureCookies(&a.opts), HttpOnly: true, SameSite: http.SameSiteLaxMode}
	if a.opts.CrossSubDomainCookies != nil {
		c.Domain = a.opts.CrossSubDomainCookies.Domain
	}
	return c
}

// Expire an issuing host's previous host-only cookie when a deployment begins
// sharing this credential. A request cookie does not carry its original scope.
func expireHostCopy(h http.Header, r *http.Request, c *http.Cookie) {
	if c.Domain == "" {
		return
	}
	if _, err := r.Cookie(c.Name); err != nil {
		return
	}
	host := *c
	host.Domain, host.Value, host.MaxAge = "", "", -1
	h.Add("Set-Cookie", host.String())
}
