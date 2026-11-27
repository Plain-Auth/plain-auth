package mcp

import (
	"encoding/json"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

// Options are the OAuth provider's options plus the MCP resource, as
// another runtime's mcp() takes them.
type Options struct {
	oauthprovider.Options
	// Resource is the canonical MCP resource URL: HTTPS, or HTTP on a
	// loopback host, without credentials, fragment or query. Issued tokens
	// are bound to it.
	Resource string
}

// authorizationServerScopes stay out of the resource's metadata.
var authorizationServerScopes = []string{"openid", "profile", "email", "phone", "address", "offline_access"}

// New runs the OAuth provider for an MCP resource, as another runtime's
// mcp() does: the resource is added to the provider's resources and to the
// default resources of registered clients, and the RFC 9728 protected
// resource metadata is served at /.well-known/oauth-protected-resource and
// at that path plus the resource's path. The plugin is the OAuth provider, so it cannot be combined with
// another. The metadata is built once when the host starts, where another
// runtime builds it on each request (simplicity).
func New(opts Options) (auth.Plugin, error) {
	resource, err := validateResource(opts.Resource)
	if err != nil {
		return auth.Plugin{}, err
	}
	provider := opts.provider()
	p, err := oauthprovider.New(provider)
	if err != nil {
		return auth.Plugin{}, err
	}
	serve := p.WellKnown
	p.WellKnown = func(a *auth.Auth, store auth.Store) (map[string]auth.WellKnownDocument, error) {
		docs := map[string]auth.WellKnownDocument{}
		if serve != nil {
			var err error
			if docs, err = serve(a, store); err != nil {
				return nil, err
			}
			if docs == nil {
				docs = map[string]auth.WellKnownDocument{}
			}
		}
		doc, err := resourceMetadata(a, provider, opts.Resource)
		if err != nil {
			return nil, err
		}
		// The provider publishes no protected resource metadata, so these
		// paths are free, as another runtime serves them when the provider
		// leaves them unhandled.
		const root = "/.well-known/oauth-protected-resource"
		for _, path := range []string{root, root + strings.TrimSuffix(resource.EscapedPath(), "/")} {
			docs[path] = doc
		}
		return docs, nil
	}
	return p, nil
}

// provider returns the provider options with the MCP resource declared and
// given to registered clients by default, without changing the caller's.
// The refresh reuse window defaults to 30 seconds, as another runtime's
// MCP plugin defaults it, so a retried refresh recovers its response; a
// negative value turns it off, where another runtime uses 0, since a zero
// Duration means unset.
func (opts Options) provider() oauthprovider.Options {
	p := opts.Options
	switch {
	case p.Tokens.RefreshReuseInterval == 0:
		p.Tokens.RefreshReuseInterval = 30 * time.Second
	case p.Tokens.RefreshReuseInterval < 0:
		p.Tokens.RefreshReuseInterval = 0
	}
	if !slices.Contains(p.Registration.DefaultResources, opts.Resource) {
		p.Registration.DefaultResources = append(slices.Clone(p.Registration.DefaultResources), opts.Resource)
	}
	if !slices.ContainsFunc(p.Resources, func(d oauthprovider.ResourceDefinition) bool { return d.Identifier == opts.Resource }) {
		p.Resources = append(slices.Clone(p.Resources), oauthprovider.ResourceDefinition{Identifier: opts.Resource})
	}
	return p
}

// resourceMetadata builds the protected resource document: the provider's
// issuer, header bearer tokens, its DPoP algorithms, the resource's DPoP
// requirement, and its scopes without the authorization server's own.
func resourceMetadata(a *auth.Auth, provider oauthprovider.Options, resource string) (auth.WellKnownDocument, error) {
	scopes := provider.Metadata.Scopes
	if scopes == nil {
		scopes = provider.Scopes
	}
	scopes = slices.DeleteFunc(slices.Clone(scopes), func(scope string) bool { return slices.Contains(authorizationServerScopes, scope) })
	doc := oauthprovider.ResourceMetadata{Resource: resource, AuthorizationServers: []string{a.OAuthIssuer()}, BearerMethodsSupported: []string{"header"},
		DPoPSigningAlgorithms: provider.DPoP.SigningAlgorithms, ScopesSupported: scopes}
	for _, d := range provider.Resources {
		var declared oauthprovider.Resource
		if d.Identifier == resource && d.Policy.Apply(&declared) == nil && declared.DPoPBoundAccessTokensRequired {
			required := true
			doc.DPoPBoundAccessTokensRequired = &required
		}
	}
	discovery, err := oauthprovider.NewResourceDiscovery(doc, oauthprovider.DiscoveryOptions{ProviderScopes: provider.Scopes})
	if err != nil {
		return auth.WellKnownDocument{}, err
	}
	body, err := discovery.MarshalJSON()
	if err != nil {
		return auth.WellKnownDocument{}, err
	}
	return oauthprovider.NewMetadataResponse(json.RawMessage(body), nil)
}
