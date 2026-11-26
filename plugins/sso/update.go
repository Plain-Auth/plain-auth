package sso

import (
	"context"
	"encoding/json"

	auth "github.com/Plain-Org/plain-auth"
)

// ProviderChange derives a managed provider's next issuer, domain and OIDC
// configuration from the row the store has locked, and reports whether the
// issuer, client ID or an endpoint changed.
type ProviderChange func(current Provider) (next Provider, identityChanged bool, err error)

// ProviderUpdateStore applies a general provider update under a live
// direct-session and tenant check. It locks the exact record, applies change
// to it, counts its linked accounts, runs guard inside the transaction as
// deletion does, and refuses an identity change while accounts are linked.
// A change to the domain or the identity resets a DNS proof; other changes
// carry it forward.
type ProviderUpdateStore interface {
	UpdateSSOProvider(ctx context.Context, actor Actor, id, recordID string, change ProviderChange, guard MutationGuard) (Provider, error)
}

// updateProvider changes a provider's issuer, domain or OIDC configuration.
// A body with samlConfig replaces a SAML directory's metadata instead.
func (o Options) updateProvider(c auth.EndpointContext, store Store, actor Actor) (any, error) {
	if _, ok := c.Body["samlConfig"]; ok && o.SAML != nil {
		return o.updateSAMLMetadata(c, store, actor)
	}
	id, _ := c.Body["providerId"].(string)
	if !MutableProviderID(id) || c.Auth.HasOAuthProvider(id) {
		return nil, ErrMissing
	}
	for key := range c.Body {
		switch key {
		case "providerId", "issuer", "domain", "oidcConfig":
		default:
			return nil, apiError(400, "Unsupported update field")
		}
	}
	if len(c.Body) == 1 {
		return nil, apiError(400, "No fields provided for update")
	}
	var issuer, domain *string
	if raw, ok := c.Body["issuer"]; ok {
		value, ok := raw.(string)
		if !ok {
			return nil, apiError(400, "Invalid issuer")
		}
		if _, err := endpointURL(value); err != nil {
			return nil, err
		}
		issuer = &value
	}
	if raw, ok := c.Body["domain"]; ok {
		value, ok := raw.(string)
		if !ok {
			return nil, apiError(400, "Invalid domain")
		}
		normalized, err := domains(value)
		if err != nil {
			return nil, err
		}
		if opt := o.DomainVerification; opt != nil {
			if _, err := DomainTargets(id, opt.identifier(id), normalized); err != nil {
				return nil, err
			}
		}
		domain = &normalized
	}
	var patch map[string]any
	if raw, ok := c.Body["oidcConfig"]; ok {
		if patch, ok = raw.(map[string]any); !ok {
			return nil, apiError(400, "Invalid OpenID Connect configuration")
		}
	}
	ctx := c.Request.Context()
	visible, err := store.ReadSSOProviders(ctx, actor, id)
	if err != nil {
		return nil, err
	}
	if len(visible) != 1 {
		return nil, ErrMissing
	}
	writer, ok := store.(ProviderUpdateStore)
	if !ok {
		return nil, apiError(501, "This store does not support transactional provider updates")
	}
	change := func(current Provider) (Provider, bool, error) {
		next, identity := current, false
		if issuer != nil {
			if current.SAML != nil {
				return next, false, apiError(400, "Register a SAML directory again to change its issuer")
			}
			identity = *issuer != current.Issuer
			next.Issuer = *issuer
		}
		if domain != nil {
			next.Domain = *domain
		}
		if current.OIDC == nil {
			if patch != nil {
				return next, false, apiError(400, "oidcConfig applies only to an OpenID Connect provider")
			}
			return next, identity, nil
		}
		cfg, err := mergeOIDCUpdate(*current.OIDC, patch)
		if err != nil {
			return next, false, err
		}
		cfg.Issuer = next.Issuer
		for _, endpoint := range []string{cfg.AuthorizationEndpoint, cfg.TokenEndpoint, cfg.JWKSEndpoint, cfg.UserInfoEndpoint, cfg.DiscoveryEndpoint} {
			if endpoint != "" {
				if err := checkEndpoint(c.Auth, endpoint); err != nil {
					return next, false, err
				}
			}
		}
		if err := o.checkClientAuth(&cfg); err != nil {
			return next, false, err
		}
		if !validMapping(cfg.Mapping) {
			return next, false, apiError(400, "Invalid OpenID Connect mapping")
		}
		next.OIDC = &cfg
		return next, identity || oidcIdentityChanged(*current.OIDC, cfg), nil
	}
	p, err := writer.UpdateSSOProvider(ctx, actor, id, visible[0].ID, change, o.GuardProviderMutation)
	if err != nil {
		return nil, err
	}
	public := sanitized(c, p)
	_, public.DomainVerified, err = o.domainStatus(ctx, store, p, "")
	return public, err
}

// mergeOIDCUpdate overlays the supplied OIDC fields on the current
// configuration. A supplied mapping replaces the whole mapping, and
// skipDiscovery is accepted and ignored, as at registration.
func mergeOIDCUpdate(current Config, patch map[string]any) (Config, error) {
	invalid := apiError(400, "Invalid OpenID Connect configuration")
	raw, err := json.Marshal(current)
	if err != nil {
		return current, err
	}
	var merged map[string]any
	if err = json.Unmarshal(raw, &merged); err != nil {
		return current, err
	}
	for key, value := range patch {
		switch key {
		case "skipDiscovery":
			if _, ok := value.(bool); !ok {
				return current, invalid
			}
			continue
		case "clientId", "clientSecret", "authorizationEndpoint", "tokenEndpoint", "userInfoEndpoint", "jwksEndpoint", "discoveryEndpoint", "tokenEndpointAuthentication", "privateKeyId", "privateKeyAlgorithm":
			if text, ok := value.(string); !ok || text == "" {
				return current, invalid
			}
		case "scopes", "pkce", "mapping", "overrideUserInfo":
			if value == nil {
				return current, invalid
			}
		default:
			return current, apiError(400, "Unsupported OpenID Connect update field")
		}
		merged[key] = value
	}
	if raw, err = json.Marshal(merged); err != nil {
		return current, err
	}
	var next Config
	if json.Unmarshal(raw, &next) != nil {
		return current, invalid
	}
	return next, nil
}

// oidcIdentityChanged reports a new client ID or endpoint, which changes the
// identities linked accounts belong to.
func oidcIdentityChanged(a, b Config) bool {
	return a.ClientID != b.ClientID || a.AuthorizationEndpoint != b.AuthorizationEndpoint || a.TokenEndpoint != b.TokenEndpoint ||
		a.UserInfoEndpoint != b.UserInfoEndpoint || a.JWKSEndpoint != b.JWKSEndpoint || a.DiscoveryEndpoint != b.DiscoveryEndpoint
}
