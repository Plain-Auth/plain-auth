package oauthprovider

import (
	"context"
	"encoding/json"
	"slices"

	auth "github.com/Plain-Org/plain-auth"
)

// TokenClaimsInput describes one access-token issuance to a claims
// contributor. User is nil for a client token.
type TokenClaimsInput struct {
	User      *auth.User
	ClientID  string
	Scopes    []string
	GrantType string
	Resources []string
	// Metadata is the registered client's metadata object.
	Metadata map[string]json.RawMessage
	// UserFields holds the account's configured attributes for ID-token
	// contributors.
	UserFields map[string]json.RawMessage
}

// TokenClaimsFunc contributes application claims to an access token. It runs
// outside store transactions; an error aborts issuance.
type TokenClaimsFunc func(context.Context, TokenClaimsInput) (map[string]any, error)

// providerClaim reports a protocol claim the issuer owns, including one a
// particular grant omits.
func providerClaim(name string) bool {
	switch name {
	case "active", "azp", "sid", "token_type":
		return true
	}
	return reservedAccessClaim(name)
}

// reservedAccessClaim reports a claim no contributor may set on a signed
// access token, the same set another runtime strips. The signer still
// writes azp and sid where the grant has them.
func reservedAccessClaim(name string) bool {
	switch name {
	case "iss", "sub", "aud", "exp", "iat", "jti", "client_id", "scope", "auth_time", "acr", "amr", "cnf":
		return true
	}
	return false
}

// accessTokenClaims merges the claim contributors lowest first, as another
// runtime does: each extension in order, where the first keeps a shared
// name with a warning, then Tokens.CustomAccessTokenClaims. Resource claims
// and the issuer's own claims are applied above them by the caller; names
// the issuer owns are dropped here with a warning.
func (opts Options) accessTokenClaims(c auth.EndpointContext, in TokenClaimsInput) (map[string]any, error) {
	ctx := c.Request.Context()
	claims := map[string]any{}
	var ignored []string
	add := func(extra map[string]any, extension bool) {
		for name, value := range extra {
			if reservedAccessClaim(name) {
				ignored = append(ignored, name)
				continue
			}
			if _, taken := claims[name]; taken && extension {
				c.Auth.Logger().WarnContext(ctx, "OAuth provider extensions supplied the same access token claim", "claim", name)
				continue
			}
			claims[name] = value
		}
	}
	for _, extension := range opts.Extensions {
		if extension.AccessTokenClaims == nil {
			continue
		}
		extra, err := extension.AccessTokenClaims(ctx, in)
		if err != nil {
			return nil, err
		}
		add(extra, true)
	}
	if opts.Tokens.CustomAccessTokenClaims != nil {
		extra, err := opts.Tokens.CustomAccessTokenClaims(ctx, in)
		if err != nil {
			return nil, err
		}
		add(extra, false)
	}
	if len(ignored) > 0 {
		slices.Sort(ignored)
		c.Auth.Logger().WarnContext(ctx, "OAuth access token ignored reserved claim names", "claims", slices.Compact(ignored))
	}
	return claims, nil
}
