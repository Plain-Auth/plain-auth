package oauthprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
)

const issuerMetadataPath = "/.well-known/oauth-authorization-server"
const issuerMetadataCache = "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400"

// IssuerMetadataOptions configures the public authorization-server document.
// The scope and authentication lists describe capabilities to advertise.
// They do not change which requests the token endpoint accepts.
type IssuerMetadataOptions struct {
	Disabled         bool
	Scopes           []string
	TokenAuthMethods []string
	Headers          http.Header
}

func (o *IssuerMetadataOptions) prepare(scopes []string) error {
	for _, scope := range o.Scopes {
		if !slices.Contains(scopes, scope) {
			return fmt.Errorf("oauthprovider: advertised scope %q is not configured", scope)
		}
	}
	if o.TokenAuthMethods != nil && len(o.TokenAuthMethods) == 0 {
		return errors.New("oauthprovider: advertised token authentication methods cannot be empty")
	}
	for i, method := range o.TokenAuthMethods {
		if method != "client_secret_basic" && method != "client_secret_post" && method != "private_key_jwt" {
			return fmt.Errorf("oauthprovider: unsupported machine authentication method %q", method)
		}
		if slices.Contains(o.TokenAuthMethods[:i], method) {
			return fmt.Errorf("oauthprovider: repeated advertised authentication method %q", method)
		}
	}
	o.Scopes = slices.Clone(o.Scopes)
	o.TokenAuthMethods = slices.Clone(o.TokenAuthMethods)
	o.Headers = o.Headers.Clone()
	return nil
}

// AuthorizationServerMetadata describes the public RFC 8414 issuer document.
type AuthorizationServerMetadata struct {
	Issuer                                     string   `json:"issuer"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	JWKSURI                                    string   `json:"jwks_uri,omitempty"`
	RegistrationEndpoint                       string   `json:"registration_endpoint,omitempty"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint                         string   `json:"revocation_endpoint,omitempty"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	TokenEndpointAuthMethods                   []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgorithms         []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionEndpointAuthMethods           []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgorithms []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	RevocationEndpointAuthMethods              []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgorithms    []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	DPoPSigningAlgorithms                      []string `json:"dpop_signing_alg_values_supported,omitzero"`
}

// Public discovery requires HTTPS. Loopback HTTP supports local development.
func issuerDiscoveryURL(raw string) (*url.URL, error) {
	if tail, local := strings.CutPrefix(raw, "http://"); local {
		u, err := metadataURL("https://"+tail, false)
		if err != nil {
			return nil, err
		}
		if !loopback(u.Hostname()) {
			return nil, errors.New("oauthprovider: HTTP discovery requires a loopback host")
		}
		u.Scheme = "http"
		return u, nil
	}
	return metadataURL(raw, false)
}

func issuerAliases(u *url.URL) []string {
	base := strings.TrimSuffix(u.EscapedPath(), "/")
	return distinct([]string{issuerMetadataPath + base, base + issuerMetadataPath})
}

// GetAuthorizationServerConfig returns the same metadata that discovery serves.
// An issuer without a published document returns auth.ErrNotFound.
func GetAuthorizationServerConfig(a *auth.Auth) (AuthorizationServerMetadata, error) {
	var doc AuthorizationServerMetadata
	if a == nil || !a.HasPlugin("oauth-provider") {
		return doc, auth.ErrNotFound
	}
	u, err := issuerDiscoveryURL(a.OAuthIssuer())
	if err != nil {
		return doc, auth.ErrNotFound
	}
	for _, path := range issuerAliases(u) {
		if raw, ok := a.WellKnownJSON(path); ok {
			err := json.Unmarshal(raw, &doc)
			return doc, err
		}
	}
	return doc, auth.ErrNotFound
}

func (opts Options) issuerDocuments(a *auth.Auth, store auth.Store) (map[string]auth.WellKnownDocument, error) {
	if _, ok := store.(MachineTokenStore); !ok || opts.Metadata.Disabled || !slices.Contains(opts.GrantTypes, "client_credentials") {
		return nil, nil
	}
	base := a.PublicURL()
	if _, err := issuerDiscoveryURL(base); err != nil {
		return nil, nil
	}
	u, err := issuerDiscoveryURL(a.OAuthIssuer())
	if err != nil {
		return nil, nil
	}
	routes := a.DescribeHTTP().Routes
	endpoint := func(path string) string {
		if slices.ContainsFunc(routes, func(r auth.HTTPRoute) bool {
			return r.Plugin == "oauth-provider" && r.Method == http.MethodPost && r.Path == path
		}) {
			return base + path
		}
		return ""
	}
	tokenURL := endpoint("/oauth2/token")
	if tokenURL == "" {
		return nil, nil
	}
	scopes := opts.Metadata.Scopes
	if scopes == nil {
		scopes = opts.Scopes
	}
	methods := []string{"client_secret_basic", "client_secret_post"}
	var algorithms []string
	if _, ok := store.(ClientAssertionStore); ok {
		methods = append(methods, "private_key_jwt")
		for _, alg := range assertionAlgorithms {
			algorithms = append(algorithms, string(alg))
		}
	}
	tokenMethods := opts.Metadata.TokenAuthMethods
	if tokenMethods == nil {
		tokenMethods = methods
	}
	for _, method := range tokenMethods {
		if !slices.Contains(methods, method) {
			return nil, fmt.Errorf("oauthprovider: store cannot support advertised authentication method %q", method)
		}
	}
	doc := AuthorizationServerMetadata{
		Issuer: a.OAuthIssuer(), TokenEndpoint: tokenURL, JWKSURI: a.PublicJWKSURL(),
		ResponseTypesSupported: []string{}, GrantTypesSupported: []string{"client_credentials"},
		ScopesSupported: slices.DeleteFunc(distinct(scopes), userDelegatedScope), TokenEndpointAuthMethods: tokenMethods,
		TokenEndpointAuthSigningAlgorithms: algorithms,
	}
	if opts.Registration.Enabled {
		doc.RegistrationEndpoint = endpoint("/oauth2/register")
	}
	_, machine := store.(MachineIntrospectionStore)
	_, opaque := store.(OpaqueAccessIntrospectionStore)
	_, signed := store.(SignedAccessIntrospectionStore)
	if machine || opaque || signed {
		if doc.IntrospectionEndpoint = endpoint("/oauth2/introspect"); doc.IntrospectionEndpoint != "" {
			doc.IntrospectionEndpointAuthMethods = methods
			doc.IntrospectionEndpointAuthSigningAlgorithms = algorithms
		}
	}
	if _, ok := store.(RevocationStore); ok {
		if doc.RevocationEndpoint = endpoint("/oauth2/revoke"); doc.RevocationEndpoint != "" {
			doc.RevocationEndpointAuthMethods = methods
			doc.RevocationEndpointAuthSigningAlgorithms = algorithms
		}
	}
	_, bindsUntargeted := store.(DPoPMachineTokenStore)
	_, bindsTargeted := store.(ResourceMachineTokenStore)
	if bindsUntargeted || bindsTargeted {
		doc.DPoPSigningAlgorithms = make([]string, 0, len(opts.proofVerifier.algorithms))
		for _, alg := range opts.proofVerifier.algorithms {
			doc.DPoPSigningAlgorithms = append(doc.DPoPSigningAlgorithms, string(alg))
		}
	}
	response, err := NewMetadataResponse(doc, opts.Metadata.Headers)
	if err != nil {
		return nil, err
	}
	docs := make(map[string]auth.WellKnownDocument)
	for _, path := range issuerAliases(u) {
		docs[path] = response
	}
	return docs, nil
}

// NewMetadataResponse serializes a metadata value and snapshots the host's headers.
// Mount the resulting http.Handler at a path owned by the application.
func NewMetadataResponse(value any, headers http.Header) (auth.WellKnownDocument, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return auth.WellKnownDocument{}, err
	}
	h := make(http.Header, len(headers)+1)
	for key, values := range headers {
		for _, value := range values {
			h.Add(key, value)
		}
	}
	if _, specified := h["Cache-Control"]; !specified {
		h.Set("Cache-Control", issuerMetadataCache)
	}
	return auth.WellKnownDocument{Body: body, Headers: h}, nil
}
