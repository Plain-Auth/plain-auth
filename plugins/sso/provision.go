package sso

import (
	"context"
	"errors"

	auth "github.com/Plain-Org/plain-auth"
)

// Provisioning is what ProvisionUser receives after an enterprise sign-in.
type Provisioning struct {
	// User is the signed-in user as stored.
	User auth.User
	// UserInfo is the mapped provider profile, with the raw claims or SAML
	// attributes in Data.
	UserInfo auth.OAuthProfile
	// Token holds the OIDC tokens; it is nil for SAML.
	Token *auth.OAuthTokens
	// Provider is the provider the sign-in went through, with its
	// configuration.
	Provider Provider
}

var errProvisioning = errors.New("sso: ProvisionUser failed")

// provisioned returns the Committed hook that runs ProvisionUser for a new
// user, or for every sign-in with ProvisionUserOnEveryLogin. The store adds
// organization membership inside the sign-in transaction, so ProvisionUser
// runs after it; another runtime runs it before organization assignment.
func (o Options) provisioned(p Provider, profile auth.OAuthProfile, tokens *auth.OAuthTokens) func(context.Context, auth.User, bool) error {
	if o.ProvisionUser == nil {
		return nil
	}
	return func(ctx context.Context, u auth.User, created bool) (err error) {
		if !created && !o.ProvisionUserOnEveryLogin {
			return nil
		}
		// A panic fails like an error; its value is never logged.
		defer func() {
			if recover() != nil {
				err = errProvisioning
			}
		}()
		if err := o.ProvisionUser(ctx, Provisioning{User: u, UserInfo: profile, Token: tokens, Provider: p}); err != nil {
			return errors.Join(errProvisioning, err)
		}
		return nil
	}
}

// provisioningFailure answers a failed ProvisionUser with its own API error,
// or 500.
func provisioningFailure(c auth.EndpointContext, err error) (any, error, bool) {
	if !errors.Is(err, errProvisioning) {
		return nil, nil, false
	}
	c.Auth.Logger().ErrorContext(c.Request.Context(), "sso: ProvisionUser failed")
	var ae *auth.APIError
	if errors.As(err, &ae) {
		return nil, ae, true
	}
	return nil, &auth.APIError{Status: 500, Message: "Failed to provision the SSO user"}, true
}
