package sso

import (
	"context"
	"errors"

	auth "github.com/Plain-Org/plain-auth"
)

// OrganizationRoleInput describes a sign-in for ResolveOrganizationRole. It
// runs before the sign-in transaction, so User is the provider's view of
// the user.
type OrganizationRoleInput struct {
	// UserID is the stored user's ID for an assignment by verified email
	// domain after a social sign-in; it is empty for a provider sign-in,
	// whose user may not be stored yet.
	UserID string
	User   ProviderUser
	// UserInfo is the mapped provider profile, with the raw claims or SAML
	// attributes in Data.
	UserInfo auth.OAuthProfile
	// Token holds the OIDC tokens; it is nil for SAML.
	Token    *auth.OAuthTokens
	Provider Provider
}

var errOrganizationRole = errors.New("sso: ResolveOrganizationRole failed")

func organizationRole(role string) bool { return role == "member" || role == "admin" }

// membershipRole returns the role the provider's organization gives this
// sign-in, or "" when it provisions no membership.
func (o Options) membershipRole(ctx context.Context, p Provider, profile auth.OAuthProfile, tokens *auth.OAuthTokens) (string, error) {
	return o.organizationRoleFor(ctx, p, OrganizationRoleInput{User: providerUser(profile), UserInfo: profile, Token: tokens, Provider: p})
}

// organizationRoleFor resolves the role the provider's organization gives
// the sign-in described by in, or "" when it provisions no membership.
func (o Options) organizationRoleFor(ctx context.Context, p Provider, in OrganizationRoleInput) (role string, err error) {
	if o.DisableOrganizationProvisioning || p.OrganizationID == nil || *p.OrganizationID == "" {
		return "", nil
	}
	if o.ResolveOrganizationRole == nil {
		if o.DefaultOrganizationRole != "" {
			return o.DefaultOrganizationRole, nil
		}
		return "member", nil
	}
	// A panic fails like an error; its value is never logged.
	defer func() {
		if recover() != nil {
			role, err = "", errOrganizationRole
		}
	}()
	role, err = o.ResolveOrganizationRole(ctx, in)
	if err != nil {
		return "", errors.Join(errOrganizationRole, err)
	}
	if !organizationRole(role) {
		return "", errOrganizationRole
	}
	return role, nil
}

// roleFailure answers a failed ResolveOrganizationRole with its own API
// error, or 500.
func roleFailure(c auth.EndpointContext, err error) error {
	c.Auth.Logger().ErrorContext(c.Request.Context(), "sso: ResolveOrganizationRole failed")
	var ae *auth.APIError
	if errors.As(err, &ae) {
		return ae
	}
	return &auth.APIError{Status: 500, Message: "Failed to resolve the SSO organization role"}
}
