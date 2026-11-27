package sso

import (
	"context"
	"errors"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
)

// DomainOrganization is the provider through which a verified email domain
// selects one organization. Ambiguous reports a domain that maps to several
// organizations, which joins none.
type DomainOrganization struct {
	Provider  Provider
	Ambiguous bool
}

// DomainOrganizationStore finds and joins the organization a verified email
// domain selects after a social sign-in, with DomainVerification on.
type DomainOrganizationStore interface {
	// SSODomainOrganization returns the first provider, by provider ID,
	// that holds a current DNS proof for domain and belongs to an
	// organization, and false when there is none, no organization table, or
	// the user with this ID and email is already a member or holds a pending
	// invitation there.
	SSODomainOrganization(ctx context.Context, domain, userID, email string) (DomainOrganization, bool, error)
	// AddSSODomainMember adds the user with role unless they are already a
	// member or hold a pending invitation, within the organization's limits.
	AddSSODomainMember(ctx context.Context, organizationID, userID, email, role string) error
}

// assignDomainOrganization runs after a social callback that signed a user
// in, as another runtime's after hook does: a verified email whose domain
// the verified providers of exactly one organization serve joins that
// organization. The sign-in has already committed, so a failure is logged
// and never answered, where another runtime fails the response.
func (o Options) assignDomainOrganization(c *auth.HookContext) error {
	if c.Err != nil || !strings.HasPrefix(c.Path, "/callback/") {
		return nil
	}
	store, ok := c.Store().(DomainOrganizationStore)
	if !ok {
		return nil
	}
	result, err := c.NewSession()
	if err != nil || result == nil || !result.User.EmailVerified {
		return nil
	}
	u := result.User
	local, domain, ok := strings.Cut(strings.ToLower(strings.TrimSpace(u.Email)), "@")
	if !ok || local == "" || strings.ContainsAny(domain, "@/\\:") {
		return nil
	}
	if domain, err = domains(domain); err != nil || domain == "" || strings.Contains(domain, ",") {
		return nil
	}
	ctx := c.Request.Context()
	logger := c.Auth.Logger()
	found, ok, err := store.SSODomainOrganization(ctx, domain, u.ID, u.Email)
	if err != nil {
		logger.ErrorContext(ctx, "sso: organization lookup by verified domain failed")
		return nil
	}
	if found.Ambiguous {
		logger.WarnContext(ctx, "Skipped SSO organization provisioning because a verified domain maps to multiple organizations", "domain", domain, "userId", u.ID)
		return nil
	}
	if !ok {
		return nil
	}
	// The role input carries the stored user and, as in another runtime, no
	// provider profile or token.
	role, err := o.organizationRoleFor(ctx, found.Provider, OrganizationRoleInput{UserID: u.ID, User: ProviderUser{Email: u.Email, EmailVerified: u.EmailVerified, Name: u.Name, Image: u.Image}, Provider: found.Provider})
	if err != nil {
		logger.ErrorContext(ctx, "sso: ResolveOrganizationRole failed")
		return nil
	}
	if role == "" {
		return nil
	}
	if err := store.AddSSODomainMember(ctx, *found.Provider.OrganizationID, u.ID, u.Email, role); err != nil && !errors.Is(err, context.Canceled) {
		logger.ErrorContext(ctx, "sso: organization provisioning by verified domain failed")
	}
	return nil
}
