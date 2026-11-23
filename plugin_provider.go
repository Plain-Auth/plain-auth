package plainauth

import (
	"net/url"
	"strings"

	"github.com/Plain-Org/plain-auth/internal/httporigin"
)

// HasOAuthProvider reports whether an account provider ID belongs to a
// startup-configured OAuth integration. SQL collations may fold provider IDs.
func (a *Auth) HasOAuthProvider(id string) bool {
	for name := range a.opts.SocialProviders {
		if strings.EqualFold(name, id) {
			return true
		}
	}
	return false
}

// ExplicitlyTrustedOrigin permits server-side discovery only at an exact
// configured origin. Browser wildcard rules do not grant network access.
func (a *Auth) ExplicitlyTrustedOrigin(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	origin := httporigin.Canonical(u)
	if origin == "" {
		return false
	}
	base, _ := url.Parse(a.opts.BaseURL)
	if base != nil && httporigin.Canonical(base) == origin {
		return true
	}
	for _, rule := range a.trustedOrigins {
		if rule.Exact(origin) {
			return true
		}
	}
	return false
}
