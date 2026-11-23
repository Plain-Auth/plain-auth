package providers

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/Plain-Org/plain-auth"
)

// Auth0 discovers the tenant's OIDC endpoints from its domain or HTTPS origin.
func Auth0(ctx context.Context, domain, clientID, secret string) (plainauth.OAuthProvider, error) {
	if !strings.Contains(domain, "://") {
		domain = "https://" + domain
	}
	u, err := url.Parse(domain)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return plainauth.OAuthProvider{}, errors.New("auth0: expected a tenant domain or HTTPS origin")
	}
	// Auth0's issuer identifier includes the root path.
	return OpenIDConnect(ctx, "https://"+strings.ToLower(u.Host)+"/", clientID, secret)
}

// Keycloak discovers the issuer for the configured realm, including its base path.
func Keycloak(ctx context.Context, issuer, clientID, secret string) (plainauth.OAuthProvider, error) {
	return discoverTenantIssuer(ctx, issuer, clientID, secret)
}

// Okta discovers an organization or custom authorization server issuer.
func Okta(ctx context.Context, issuer, clientID, secret string) (plainauth.OAuthProvider, error) {
	return discoverTenantIssuer(ctx, issuer, clientID, secret)
}

func discoverTenantIssuer(ctx context.Context, issuer, clientID, secret string) (plainauth.OAuthProvider, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return plainauth.OAuthProvider{}, errors.New("invalid OpenID Connect issuer")
	}
	return OpenIDConnect(ctx, strings.TrimRight(issuer, "/"), clientID, secret)
}
