package sso

import (
	"context"
	"encoding/json"
	"github.com/Plain-Org/plain-auth/internal/jsjson"
	"maps"

	auth "github.com/Plain-Org/plain-auth"
)

// ProviderChange derives a managed provider's next issuer, domain and OIDC
// configuration from the row the store has locked, and reports whether the
// issuer, client ID or an endpoint changed. That flag does not cover the
// claim mapping, which the store compares itself.
type ProviderChange func(current Provider) (next Provider, identityChanged bool, err error)

// ProviderUpdateStore applies a general provider update under a live
// direct-session and tenant check. It locks the exact record, applies change
// to it, counts its linked accounts, asks guard as MutationGuard describes,
// and refuses an identity change while accounts are linked. A change to the
// domain, the identity or the OIDC claim mapping resets a DNS proof,
// because the mapping chooses the email the proof vouches for; other changes
// carry it forward.
type ProviderUpdateStore interface {
	UpdateSSOProvider(ctx context.Context, actor Actor, id, recordID string, change ProviderChange, guard MutationGuard) (Provider, error)
}

// updateProvider changes a provider's issuer, domain or OIDC configuration.
// A body with samlConfig replaces a SAML directory's metadata instead.
func (o Options) updateProvider(c auth.EndpointContext, store Store, actor Actor) (any, error) {
	// A missing or non-string providerId fails the body schema, as in
	// another runtime; a string that names no provider answers 404 below.
	raw, present := c.Body["providerId"]
	id, ok := raw.(string)
	if !ok {
		received := "undefined"
		if present {
			received = jsjson.TypeName(raw)
		}
		return nil, &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "[body.providerId] Invalid input: expected string, received " + received}
	}
	if metadataOnlyUpdate(c.Body) && o.SAML != nil {
		return o.updateSAMLMetadata(c, store, actor)
	}
	if !MutableProviderID(id) || c.Auth.HasOAuthProvider(id) {
		return nil, ErrMissing
	}
	for key := range c.Body {
		switch key {
		case "providerId", "issuer", "domain", "oidcConfig":
		case "samlConfig":
			if o.SAML == nil {
				return nil, apiError(400, "Unsupported update field")
			}
		default:
			if _, declared := o.ProviderAdditionalFields[key]; !declared {
				return nil, apiError(400, "Unsupported update field")
			}
		}
	}
	if len(c.Body) == 1 {
		return nil, apiError(400, "No fields provided for update")
	}
	var issuer, domain *string
	if raw, ok := c.Body["issuer"]; ok {
		// Checked and normalized as at registration. The session is checked
		// first and only the first invalid field is reported, where another
		// runtime validates the whole body before the session and lists
		// every issue.
		value, ok := raw.(string)
		if !ok {
			return nil, &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "[body.issuer] Invalid input: expected string, received " + jsjson.TypeName(raw)}
		}
		value, err := issuerURL(value)
		if err != nil {
			return nil, err
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
	fields, err := o.providerFieldInput(c.Body, false)
	if err != nil {
		return nil, err
	}
	var samlPatch map[string]any
	if raw, ok := c.Body["samlConfig"]; ok {
		if samlPatch, ok = raw.(map[string]any); !ok {
			return nil, ErrInvalidSAML
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
	if samlPatch != nil {
		if err := o.checkSAMLPatch(samlPatch); err != nil {
			return nil, err
		}
	}
	writer, ok := store.(ProviderUpdateStore)
	if !ok {
		return nil, apiError(501, "This store does not support transactional provider updates")
	}
	change := func(current Provider) (Provider, bool, error) {
		next, identity := current, false
		if issuer != nil {
			identity = *issuer != current.Issuer
			next.Issuer = *issuer
		}
		if domain != nil {
			next.Domain = *domain
		}
		// Declared fields never change the provider's identity.
		if fields != nil {
			next.AdditionalFields = maps.Clone(current.AdditionalFields)
			if next.AdditionalFields == nil {
				next.AdditionalFields = make(map[string]any, len(fields))
			}
			maps.Copy(next.AdditionalFields, fields)
		}
		if current.SAML != nil {
			if patch != nil {
				return next, false, apiError(400, "Cannot update OIDC config for a provider that doesn't have OIDC configured")
			}
			if samlPatch == nil && issuer == nil {
				return next, identity, nil
			}
			// The stored SAML configuration always carries the provider's
			// issuer, so an issuer change also moves the default SP entity ID
			// and audience; another runtime keeps the old samlConfig.issuer
			// when the request does not also send samlConfig. Library code
			// only: the request's trusted origins were resolved at entry, so
			// no host code runs inside the store transaction.
			cfg, err := o.mergeSAMLUpdate(*current.SAML, samlPatch, next.Issuer)
			if err != nil {
				return next, false, err
			}
			next.SAML = cfg
			if _, err := o.samlSP(c, next); err != nil {
				return next, false, err
			}
			return next, identity || !SameSAMLIdentity(*current.SAML, *cfg), nil
		}
		if samlPatch != nil {
			return next, false, errNotSAML
		}
		if current.OIDC == nil {
			if patch != nil {
				return next, false, apiError(400, "Cannot update OIDC config for a provider that doesn't have OIDC configured")
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
				if err := checkEndpoint(requestTrust(c.Request.Context(), c.Auth), endpoint); err != nil {
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
	public := o.public(c, p)
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
