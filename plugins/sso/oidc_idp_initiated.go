package sso

import (
	"context"
	"errors"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
)

// OIDCDirectory identifies the current OIDC registration for a host's
// IdP-initiated sign-in policy. RecordID changes on re-registration and
// Reference on any configuration change other than the client secret.
type OIDCDirectory struct {
	RecordID, Reference, ProviderID, Issuer, ClientID, OrganizationID string
}

// OIDCDirectoryPolicy approves restarting a stateless callback for a
// reviewed provider. A nil policy disables IdP-initiated OIDC sign-in.
// Return an error to fail closed.
type OIDCDirectoryPolicy func(context.Context, OIDCDirectory) (bool, error)

func (p OIDCDirectoryPolicy) authorize(ctx context.Context, d OIDCDirectory) (allowed bool, err error) {
	defer func() {
		if recover() != nil {
			allowed, err = false, errors.New("OIDC directory authorization failed")
		}
	}()
	allowed, err = p(ctx, d)
	if err != nil {
		return false, err
	}
	return allowed, nil
}

func oidcDirectory(p BrowserProvider) OIDCDirectory {
	d := OIDCDirectory{RecordID: p.ID, Reference: p.Reference, ProviderID: p.ProviderID, Issuer: p.Issuer, ClientID: p.OIDC.ClientID}
	if p.OrganizationID != nil {
		d.OrganizationID = *p.OrganizationID
	}
	return d
}

// restartIDPInitiated answers a stateless callback on a provider's own
// callback path, for a provider the host approves, by starting a fresh
// authorization at the provider. Any other request is not handled and goes
// on to the ordinary callback, which reports the missing state.
func (o Options) restartIDPInitiated(c auth.EndpointContext, store BrowserStore) (any, bool, error) {
	q := c.Request.URL.Query()
	if _, has := q["state"]; has || len(q["code"]) != 1 || q.Get("code") == "" {
		return nil, false, nil
	}
	id, ok := strings.CutPrefix(c.Request.URL.EscapedPath(), strings.TrimSuffix(c.Auth.BasePath(), "/")+"/sso/callback/")
	if !ok || !MutableProviderID(id) || c.Auth.HasOAuthProvider(id) {
		return nil, false, nil
	}
	ctx := c.Request.Context()
	find := store.FindBrowserProvider
	if o.DomainVerification != nil {
		find = store.(DomainStore).FindVerifiedBrowserProvider
	}
	p, err := find(ctx, Selector{ProviderID: id, Protocol: "oidc"})
	if errors.Is(err, ErrMissing) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	if p.OIDC == nil || !available(c, p) {
		return nil, false, nil
	}
	allowed, err := o.AllowIDPInitiatedOIDC.authorize(ctx, oidcDirectory(p))
	if err != nil {
		return nil, true, apiError(503, "OIDC directory authorization is unavailable")
	}
	if !allowed {
		return nil, false, nil
	}
	proof, err := o.domainGate(c, p)
	if err != nil {
		return nil, true, err
	}
	if p, err = o.withRuntimeDiscovery(ctx, c.Auth, p); err != nil {
		c.Auth.Logger().ErrorContext(ctx, "IdP-initiated OIDC restart skipped: discovery failed", "providerId", id)
		return nil, false, nil
	}
	c.Body = map[string]any{"callbackURL": "/"}
	target, err := o.authorize(c, p, proof, false, nil, nil)
	if err != nil {
		return nil, true, err
	}
	// The target is the provider's stored authorization endpoint, not an
	// application callback.
	return auth.Redirect(target), true, nil
}
