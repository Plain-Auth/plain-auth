package plainauth

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
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

// OAuthProviderName returns the display name of the configured provider id,
// which defaults to id, and whether it is configured.
func (a *Auth) OAuthProviderName(id string) (string, bool) {
	p, ok := a.opts.SocialProviders[id]
	return p.Name, ok
}

// TrustedProviderIDs returns the provider IDs trusted for account linking on
// this request, from TrustedProviders or TrustedProvidersForRequest.
func (a *Auth) TrustedProviderIDs(r *http.Request) ([]string, error) {
	if a.opts.TrustedProvidersForRequest == nil {
		return slices.Clone(a.opts.TrustedProviders), nil
	}
	if r == nil {
		return nil, nil
	}
	ids, err := a.opts.TrustedProvidersForRequest(accountObserverRequest(r.Context(), r))
	if err != nil {
		return nil, fmt.Errorf("auth: trusted providers: %w", err)
	}
	return ids, nil
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
