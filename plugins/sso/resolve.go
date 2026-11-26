package sso

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
)

// UserResolutionStore marks a store whose enterprise sign-in honours
// OAuthLoginOptions.SelectUserID and UpdateSelectedProfile.
type UserResolutionStore interface {
	ResolvesSSOUsers()
}

// ResolutionAction is what a ResolveUser decision does with a verified
// enterprise identity.
type ResolutionAction string

const (
	// ResolveContinue signs in by the built-in rules.
	ResolveContinue ResolutionAction = "continue"
	// ResolveLink signs the identity in to a chosen user.
	ResolveLink ResolutionAction = "link"
	// ResolveReject refuses the sign-in.
	ResolveReject ResolutionAction = "reject"
)

// UserResolution is a ResolveUser decision. A link signs the identity in to
// UserID; Profile "preserve" keeps that user's profile and "update" copies
// the provider's name, image, email and mapped user fields to it. A rejection needs Code, which
// the browser receives as error, and Message, when set, as
// error_description.
type UserResolution struct {
	Action        ResolutionAction
	UserID        string
	Profile       string
	Code, Message string
	// RequireActiveSCIMUser, on a link, makes the sign-in transaction
	// confirm that this SCIM User is still active and links to UserID;
	// otherwise the sign-in fails with SSO_USER_RESOLUTION_FAILED.
	RequireActiveSCIMUser *auth.SCIMUserReference
}

func (r UserResolution) valid() bool {
	if ref := r.RequireActiveSCIMUser; ref != nil && (r.Action != ResolveLink || ref.ConnectionID == "" || ref.ExternalID == "") {
		return false
	}
	switch r.Action {
	case ResolveContinue:
		return true
	case ResolveLink:
		return strings.TrimSpace(r.UserID) != "" && (r.Profile == "preserve" || r.Profile == "update")
	case ResolveReject:
		return strings.TrimSpace(r.Code) != ""
	}
	return false
}

// updates reports a link that copies the provider's profile, so the
// mapped user fields are prepared for it.
func (r UserResolution) updates() bool { return r.Action == ResolveLink && r.Profile == "update" }

func (r UserResolution) apply(opts *auth.OAuthLoginOptions) {
	if r.Action == ResolveLink {
		opts.SelectUserID = r.UserID
		opts.UpdateSelectedProfile = r.Profile == "update"
		opts.RequireActiveSCIMUser = r.RequireActiveSCIMUser
	}
}

// AccountKey names the external account a sign-in proves.
type AccountKey struct {
	// Issuer is the ID token's iss for OIDC, or the IdP entity ID for SAML.
	Issuer string
	// AccountID is the ID token's sub for OIDC, or the signed NameID for
	// SAML; compare it case-sensitively.
	AccountID string
}

// ProviderUser is the normalized profile the provider asserted.
// EmailVerified is false unless the provider's verification is trusted
// (SAMLOptions.TrustEmailVerified with mapping.emailVerified). Mapped extra
// fields are not included; read other claims from UserResolutionInput.Claims.
type ProviderUser struct {
	Email         string
	EmailVerified bool
	Name          string
	Image         *string
}

func providerUser(p auth.OAuthProfile) ProviderUser {
	u := ProviderUser{Email: p.Email, EmailVerified: p.EmailVerified, Name: p.Name}
	if p.Image != nil {
		image := *p.Image
		u.Image = &image
	}
	return u
}

// UserResolutionInput is a verified enterprise identity for ResolveUser.
type UserResolutionInput struct {
	// Protocol is "oidc" or "saml".
	Protocol   string
	ProviderID string
	AccountKey AccountKey
	User       ProviderUser
	// Claims are the UserInfo claims, or the ID token claims without a
	// UserInfo endpoint, for OIDC, and the verified assertion attributes for
	// SAML, one value as a string and several as a list; numbers are
	// json.Number. Validate them before using them for authorization.
	Claims map[string]any
	// IDTokenClaims is the verified ID token payload, nil for SAML.
	IDTokenClaims map[string]any
	// ProviderReference is an opaque, transient fingerprint of the provider
	// configuration this sign-in accepted; never store it as a tenant or
	// user binding.
	ProviderReference string
}

// cloneClaims copies claims through JSON, so a resolver's edits never reach
// the profile the sign-in uses.
func cloneClaims(v any) map[string]any {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&out) != nil {
		return nil
	}
	return out
}

var errResolution = &auth.APIError{Status: 500, Code: "SSO_USER_RESOLUTION_FAILED", Message: "Unable to resolve the SSO user"}

// resolveUser runs ResolveUser outside any transaction. A failing,
// panicking or invalid resolver fails closed; its error and decision are
// never logged.
func (o Options) resolveUser(c auth.EndpointContext, in UserResolutionInput) (r UserResolution, err error) {
	ctx := c.Request.Context()
	defer func() {
		if recover() != nil {
			c.Auth.Logger().ErrorContext(ctx, "sso: ResolveUser failed", "providerId", in.ProviderID)
			r, err = UserResolution{}, errResolution
		}
	}()
	r, err = o.ResolveUser(ctx, in)
	if err != nil {
		c.Auth.Logger().ErrorContext(ctx, "sso: ResolveUser failed", "providerId", in.ProviderID)
		return UserResolution{}, errResolution
	}
	if !r.valid() {
		c.Auth.Logger().ErrorContext(ctx, "sso: ResolveUser returned an invalid decision", "providerId", in.ProviderID)
		return UserResolution{}, errResolution
	}
	return r, nil
}

// resolutionFailure maps a store's refusal of a link decision to its
// redirect code; it reports false for any other error.
func resolutionFailure(c auth.EndpointContext, flow auth.OAuthFlow, r UserResolution, err error) (any, error, bool) {
	if r.Action != ResolveLink {
		return nil, nil, false
	}
	switch {
	case errors.Is(err, auth.ErrNotFound):
		out, e := enterpriseFailure(c, flow, "user_not_found", "User not found")
		return out, e, true
	case errors.Is(err, auth.ErrOAuthAccountAlreadyLinked):
		out, e := enterpriseFailure(c, flow, "account_ownership_conflict", "Account is already linked to another user")
		return out, e, true
	case errors.Is(err, auth.ErrSCIMUserInactive):
		out, e := enterpriseFailure(c, flow, errResolution.Code, errResolution.Message)
		return out, e, true
	}
	return nil, nil, false
}
