package oauthprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
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

func (o *IssuerMetadataOptions) prepare(scopes, extensionMethods []string) error {
	for _, scope := range o.Scopes {
		if !slices.Contains(scopes, scope) {
			return fmt.Errorf("oauthprovider: advertised scope %q is not configured", scope)
		}
	}
	if o.TokenAuthMethods != nil && len(o.TokenAuthMethods) == 0 {
		return errors.New("oauthprovider: advertised token authentication methods cannot be empty")
	}
	for i, method := range o.TokenAuthMethods {
		if method != "none" && method != "client_secret_basic" && method != "client_secret_post" && method != "private_key_jwt" && !slices.Contains(extensionMethods, method) {
			return fmt.Errorf("oauthprovider: unsupported token authentication method %q", method)
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
	AuthorizationEndpoint                      string   `json:"authorization_endpoint,omitempty"`
	ResponseModesSupported                     []string `json:"response_modes_supported,omitempty"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported,omitempty"`
	AuthorizationResponseIssuerSupported       bool     `json:"authorization_response_iss_parameter_supported,omitempty"`
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
	// The back-channel logout flags are always published, false included.
	BackchannelLogoutSupported        bool `json:"backchannel_logout_supported"`
	BackchannelLogoutSessionSupported bool `json:"backchannel_logout_session_supported"`
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

// GetAuthorizationServerConfig reads the OAuth fields from a published discovery document.
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

func (opts Options) discoveryGrants(store auth.Store, authorizeURL string) []string {
	_, browser := store.(BrowserAuthorizationStore)
	_, redeem := store.(AuthorizationCodeStore)
	_, refresh := store.(RefreshGrantStore)
	_, machine := store.(MachineTokenStore)
	available := map[string]bool{
		"authorization_code": browser && redeem && authorizeURL != "",
		"refresh_token":      refresh,
		"client_credentials": machine,
	}
	return slices.DeleteFunc(slices.Clone(opts.GrantTypes), func(grant string) bool { return !available[grant] })
}

func (opts Options) issuerDocuments(a *auth.Auth, store auth.Store) (map[string]auth.WellKnownDocument, error) {
	if opts.Metadata.Disabled {
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
	endpoint := func(method, path string) string {
		if slices.ContainsFunc(routes, func(r auth.HTTPRoute) bool {
			return r.Plugin == "oauth-provider" && r.Method == method && r.Path == path
		}) {
			return base + path
		}
		return ""
	}
	tokenURL := endpoint(http.MethodPost, "/oauth2/token")
	if tokenURL == "" {
		return nil, nil
	}
	authorizeURL := endpoint(http.MethodGet, "/oauth2/authorize")
	grants := opts.discoveryGrants(store, authorizeURL)
	if len(grants) == 0 {
		return nil, nil
	}
	canAuthorize := slices.Contains(grants, "authorization_code")
	canRefresh := slices.Contains(grants, "refresh_token")
	_, offline := store.(OfflineAuthorizationCodeStore)
	_, identityStore := store.(OpenIDGrantStore)
	// DisableJWTPlugin signs ID tokens with client secrets, so the jwt
	// plugin's issuer and keys must not also be in play.
	if opts.DisableJWTPlugin && a.PublicJWKSURL() != "" {
		return nil, errors.New("oauthprovider: DisableJWTPlugin cannot be used with the jwt plugin")
	}
	openid := canAuthorize && identityStore && (opts.DisableJWTPlugin || a.PublicJWKSURL() != "") && slices.Contains(opts.Scopes, "openid")
	scopes := opts.Metadata.Scopes
	if scopes == nil {
		scopes = opts.Scopes
	}
	scopes = slices.DeleteFunc(distinct(scopes), func(scope string) bool {
		if !canAuthorize && !canRefresh {
			return userDelegatedScope(scope)
		}
		return scope == "openid" && !openid || scope == "offline_access" && !(canRefresh && offline)
	})
	methods := []string{"client_secret_basic", "client_secret_post"}
	var algorithms []string
	if _, ok := store.(ClientAssertionStore); ok {
		methods = append(methods, "private_key_jwt")
		for _, alg := range assertionAlgorithms {
			algorithms = append(algorithms, string(alg))
		}
	}
	// Extension methods are advertised after the built-in ones, as in
	// another runtime.
	methods = append(methods, opts.extensionAuthMethods()...)
	tokenMethods := opts.Metadata.TokenAuthMethods
	if tokenMethods == nil {
		tokenMethods = methods
		if (canAuthorize || canRefresh) && opts.Registration.Enabled && opts.Registration.AllowUnauthenticated {
			tokenMethods = append([]string{"none"}, methods...)
		}
	}
	for _, method := range tokenMethods {
		if !(method == "none" && (canAuthorize || canRefresh)) && !slices.Contains(methods, method) {
			return nil, fmt.Errorf("oauthprovider: store cannot support advertised authentication method %q", method)
		}
	}
	doc := AuthorizationServerMetadata{
		Issuer: a.OAuthIssuer(), TokenEndpoint: tokenURL, JWKSURI: a.PublicJWKSURL(),
		ResponseTypesSupported: []string{}, GrantTypesSupported: grants,
		ScopesSupported: scopes, TokenEndpointAuthMethods: tokenMethods,
		TokenEndpointAuthSigningAlgorithms: algorithms,
	}
	if canAuthorize {
		doc.AuthorizationEndpoint = authorizeURL
		doc.ResponseTypesSupported = []string{"code"}
		doc.ResponseModesSupported = []string{"query"}
		doc.CodeChallengeMethodsSupported = []string{"S256"}
		doc.AuthorizationResponseIssuerSupported = true
	}
	if opts.Registration.Enabled {
		doc.RegistrationEndpoint = endpoint(http.MethodPost, "/oauth2/register")
	}
	_, machine := store.(MachineIntrospectionStore)
	_, opaque := store.(OpaqueAccessIntrospectionStore)
	_, signed := store.(SignedAccessIntrospectionStore)
	if machine || opaque || signed {
		if doc.IntrospectionEndpoint = endpoint(http.MethodPost, "/oauth2/introspect"); doc.IntrospectionEndpoint != "" {
			doc.IntrospectionEndpointAuthMethods = methods
			doc.IntrospectionEndpointAuthSigningAlgorithms = algorithms
		}
	}
	if _, ok := store.(RevocationStore); ok {
		if doc.RevocationEndpoint = endpoint(http.MethodPost, "/oauth2/revoke"); doc.RevocationEndpoint != "" {
			doc.RevocationEndpointAuthMethods = methods
			doc.RevocationEndpointAuthSigningAlgorithms = algorithms
		}
	}
	_, bindsUntargeted := store.(DPoPMachineTokenStore)
	_, bindsTargeted := store.(ResourceMachineTokenStore)
	if slices.Contains(grants, "client_credentials") && (bindsUntargeted || bindsTargeted) {
		doc.DPoPSigningAlgorithms = make([]string, 0, len(opts.proofVerifier.algorithms))
		for _, alg := range opts.proofVerifier.algorithms {
			doc.DPoPSigningAlgorithms = append(doc.DPoPSigningAlgorithms, string(alg))
		}
	}
	doc.BackchannelLogoutSupported = backchannelSupported(a, store)
	doc.BackchannelLogoutSessionSupported = doc.BackchannelLogoutSupported
	var metadata any = doc
	input := MetadataInput{Type: MetadataAuthorizationServer, Server: doc}
	if openid {
		var userInfoURL string
		if _, ok := store.(UserInfoStore); ok {
			userInfoURL = endpoint(http.MethodGet, "/oauth2/userinfo")
		}
		var endSessionURL string
		if _, ok := store.(EndSessionStore); ok {
			endSessionURL = endpoint(http.MethodGet, endSessionPath)
		}
		openIDDoc := opts.openIDMetadata(a, doc, userInfoURL, endSessionURL, endpoint(http.MethodPost, "/oauth2/consent") != "")
		metadata, input.OpenID = openIDDoc, &openIDDoc
		// Every path serves the OpenID document, so extensions see its
		// type on all of them, as another runtime passes it.
		input.Type = MetadataOpenIDConfiguration
	}
	docs := make(map[string]auth.WellKnownDocument)
	serve := func(paths []string, input MetadataInput) error {
		extended, err := opts.extendMetadata(a, metadata, input)
		if err != nil {
			return err
		}
		response, err := NewMetadataResponse(extended, opts.Metadata.Headers)
		if err != nil {
			return err
		}
		for _, path := range paths {
			docs[path] = response
		}
		return nil
	}
	paths := issuerAliases(u)
	if openid {
		paths = append(paths, openIDConfigPath(u))
	}
	if err := serve(paths, input); err != nil {
		return nil, err
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
