package sso

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// TXTResolver returns one string for each TXT resource record, concatenating
// that record's character strings. The lookup name is fully qualified.
type TXTResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}

type DomainVerificationOptions struct {
	// TokenPrefix defaults to "plain-auth-token". A prefix is one DNS label fragment.
	TokenPrefix string
	// Resolver defaults to the system resolver.
	Resolver TXTResolver
}

var dnsPrefix = regexp.MustCompile("^[A-Za-z0-9_-]+$")

func (o DomainVerificationOptions) normalized() (DomainVerificationOptions, error) {
	if o.TokenPrefix == "" {
		o.TokenPrefix = "plain-auth-token"
	}
	if !dnsPrefix.MatchString(o.TokenPrefix) || len(o.TokenPrefix) > 63 {
		return o, errors.New("sso: invalid domain verification token prefix")
	}
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
	return o, nil
}
func (o DomainVerificationOptions) identifier(id string) string {
	return "_" + o.TokenPrefix + "-" + id
}

// DomainChallenge is a pending DNS challenge bound to the exact directory and domain set.
// Scope is an opaque store identifier. The token is public only to an authorized manager.
type DomainChallenge struct{ ProviderID, Domain, Identifier, Token, Scope string }

type DomainStore interface {
	CheckSSODomainSchema(context.Context) error
	FindVerifiedBrowserProvider(context.Context, Selector) (BrowserProvider, error)
	CreateSSODomainProvider(ctx context.Context, actor Actor, provider Provider, limit int, identifier string) (string, error)
	SSODomainChallenge(ctx context.Context, actor Actor, providerID, identifier string, issue bool) (DomainChallenge, error)
	// ConfirmSSODomain is a trusted server operation. Its caller must first observe
	// the challenge token at every domain using the configured DNS resolver.
	ConfirmSSODomain(context.Context, Actor, DomainChallenge) error
	// SSODomainVerified matches the captured reference before authorization or token exchange.
	// An empty reference requests the latest management projection.
	SSODomainVerified(ctx context.Context, provider Provider, reference string) (bool, error)
	// SSODomainRequired reports a persisted opt-in across differently configured nodes.
	SSODomainRequired(context.Context, Provider) (bool, error)
	CompleteVerifiedEnterpriseLogin(ctx context.Context, ref string, role string, id, subject string, tokens auth.OAuthTokens, user auth.User, session auth.StoredSession, opts auth.OAuthLoginOptions) (auth.User, bool, error)
}

var (
	ErrDomainVerified   = &auth.APIError{Status: 409, Code: "DOMAIN_VERIFIED", Message: "Domain has already been verified"}
	ErrDomainUnverified = apiError(401, "Provider domain has not been verified")
	ErrNoChallenge      = &auth.APIError{Status: 404, Code: "NO_PENDING_VERIFICATION", Message: "No pending domain verification exists"}
	ErrDomainChanged    = &auth.APIError{Status: 409, Code: "SSO_PROVIDER_CHANGED", Message: "SSO provider changed while domain verification was in progress. Reload the provider and try again"}
	ErrInvalidDNSLabel  = &auth.APIError{Status: 400, Code: "INVALID_VERIFICATION_IDENTIFIER", Message: "The DNS verification identifier must be a single label using letters, digits, underscores and hyphens"}
	ErrLabelTooLong     = &auth.APIError{Status: 400, Code: "IDENTIFIER_TOO_LONG", Message: "Verification identifier exceeds the DNS label limit of 63 characters"}
)

// DomainTargets returns the normalized domains for one well-formed challenge.
// Requiring one DNS label keeps proof under the registered domain.
func DomainTargets(id, identifier, rawDomains string) ([]string, error) {
	if !MutableProviderID(id) || !dnsPrefix.MatchString(identifier) || !strings.HasPrefix(identifier, "_") || !strings.HasSuffix(identifier, "-"+id) || len(identifier) <= len(id)+2 {
		return nil, ErrInvalidDNSLabel
	}
	if len(identifier) > 63 {
		return nil, ErrLabelTooLong
	}
	normalized, err := domains(rawDomains)
	if err != nil {
		return nil, &auth.APIError{Status: 400, Code: "INVALID_DOMAIN", Message: "Invalid domain"}
	}
	names := strings.Split(normalized, ",")
	for _, name := range names {
		if len(identifier)+1+len(name) > 253 {
			return nil, &auth.APIError{Status: 400, Code: "INVALID_DOMAIN", Message: "The verification DNS name exceeds 253 characters"}
		}
	}
	return names, nil
}

func (o DomainVerificationOptions) challenge(c auth.EndpointContext, store Store, actor Actor, issue bool) (DomainChallenge, error) {
	id, ok := c.Body["providerId"].(string)
	if !ok || id == "" {
		return DomainChallenge{}, apiError(400, "providerId is required")
	}
	if !MutableProviderID(id) || c.Auth.HasOAuthProvider(id) {
		return DomainChallenge{}, ErrMissing
	}
	// The store asks the request's gate before storing a new token, so its
	// verification hooks run outside the store's transaction.
	var ch DomainChallenge
	err := c.GateVerifications(func(ctx context.Context) (err error) {
		ch, err = store.(DomainStore).SSODomainChallenge(ctx, actor, id, o.identifier(id), issue)
		return err
	})
	return ch, err
}
func (o DomainVerificationOptions) request(c auth.EndpointContext, store Store, actor Actor) (any, error) {
	challenge, err := o.challenge(c, store, actor, true)
	if err != nil {
		return nil, err
	}
	return map[string]string{"domainVerificationToken": challenge.Token}, nil
}
func (o DomainVerificationOptions) verify(c auth.EndpointContext, store Store, actor Actor) (any, error) {
	challenge, err := o.challenge(c, store, actor, false)
	if err != nil {
		return nil, err
	}
	names, err := DomainTargets(challenge.ProviderID, challenge.Identifier, challenge.Domain)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	for _, domain := range names {
		records, err := o.Resolver.LookupTXT(ctx, challenge.Identifier+"."+domain+".")
		found := false
		if err == nil {
			for _, record := range records {
				v := strings.TrimSpace(record)
				if v == challenge.Token || v == challenge.Identifier+"="+challenge.Token {
					found = true
					break
				}
			}
		}
		if !found {
			return nil, &auth.APIError{Status: 502, Code: "DOMAIN_VERIFICATION_FAILED", Message: "Unable to verify domain ownership for " + domain + ". Try again later"}
		}
	}
	return nil, store.(DomainStore).ConfirmSSODomain(ctx, actor, challenge)
}

// domainStatus also honors a registration already enrolled by another node.
func (o Options) domainStatus(ctx context.Context, store Store, p Provider, reference string) (required, verified bool, err error) {
	ds, ok := store.(DomainStore)
	required = o.DomainVerification != nil
	if !required && ok {
		required, err = ds.SSODomainRequired(ctx, p)
		if err != nil {
			return false, false, err
		}
	}
	if !required {
		return false, false, nil
	}
	verified, err = ds.SSODomainVerified(ctx, p, reference)
	return required, verified, err
}

func (o Options) domainGate(c auth.EndpointContext, p BrowserProvider) (bool, error) {
	required, verified, err := o.domainStatus(c.Request.Context(), c.Store().(Store), p.Provider, p.Reference)
	if err != nil {
		return false, err
	}
	if required && !verified {
		return false, ErrDomainUnverified
	}
	return required, nil
}
