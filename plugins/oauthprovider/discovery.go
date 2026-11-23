// Package oauthprovider provides OAuth authorization-server and protected-resource integrations.
package oauthprovider

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
)

// ResourceMetadata describes a protected API under RFC 9728. A nil slice omits
// an optional field unless a discovery default applies. An empty slice emits [].
type ResourceMetadata struct {
	Resource                      string   `json:"resource"`
	AuthorizationServers          []string `json:"authorization_servers,omitzero"`
	JWKSURI                       string   `json:"jwks_uri,omitempty"`
	ScopesSupported               []string `json:"scopes_supported,omitzero"`
	BearerMethodsSupported        []string `json:"bearer_methods_supported,omitzero"`
	ResourceSigningAlgorithms     []string `json:"resource_signing_alg_values_supported,omitzero"`
	ResourceName                  string   `json:"resource_name,omitempty"`
	ResourceDocumentation         string   `json:"resource_documentation,omitempty"`
	ResourcePolicyURI             string   `json:"resource_policy_uri,omitempty"`
	ResourceTOSURI                string   `json:"resource_tos_uri,omitempty"`
	TLSClientCertificateBound     *bool    `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	AuthorizationDetailsTypes     []string `json:"authorization_details_types_supported,omitzero"`
	DPoPSigningAlgorithms         []string `json:"dpop_signing_alg_values_supported,omitzero"`
	DPoPBoundAccessTokensRequired *bool    `json:"dpop_bound_access_tokens_required,omitempty"`
}

// DiscoveryOptions supplies the resource's trusted configuration. Auth supplies
// the default resource URL and issuer. ProviderScopes and ExternalScopes define
// which scopes this API may advertise from local and other issuers respectively.
type DiscoveryOptions struct {
	Auth           *auth.Auth
	ProviderScopes []string
	ExternalScopes []string
	// DefaultDPoPSigningAlgorithms reflects the resource verifier's configuration.
	// An explicit value in ResourceMetadata overrides this list.
	DefaultDPoPSigningAlgorithms []string
	// Extra publishes application-specific or language-tagged metadata, such
	// as resource_name#fr. Typed fields must be configured in ResourceMetadata.
	Extra map[string]json.RawMessage
}

// ResourceDiscovery is an immutable metadata document and HTTP handler.
type ResourceDiscovery struct {
	url, path, requestURI string
	body                  []byte
}

// NewResourceDiscovery resolves metadata once at startup. Explicit values take
// precedence over the local auth instance. The resource and issuer identifiers
// are independent of the host, forwarding headers and cookies of an incoming request.
func NewResourceDiscovery(doc ResourceMetadata, opts DiscoveryOptions) (*ResourceDiscovery, error) {
	if opts.Auth != nil {
		if doc.Resource == "" {
			doc.Resource = opts.Auth.PublicURL()
		}
		if doc.AuthorizationServers == nil {
			doc.AuthorizationServers = []string{opts.Auth.OAuthIssuer()}
		}
	}
	u, err := metadataURL(doc.Resource, true)
	if err != nil {
		return nil, fmt.Errorf("oauthprovider: invalid resource: %w", err)
	}
	for _, issuer := range doc.AuthorizationServers {
		if _, err := metadataURL(issuer, false); err != nil {
			return nil, fmt.Errorf("oauthprovider: invalid authorization server: %w", err)
		}
	}
	if doc.JWKSURI != "" {
		if _, err := metadataURL(doc.JWKSURI, true); err != nil {
			return nil, fmt.Errorf("oauthprovider: invalid jwks_uri: %w", err)
		}
	}
	if opts.ProviderScopes != nil && opts.ExternalScopes != nil && len(doc.AuthorizationServers) <= 1 {
		return nil, errors.New("oauthprovider: external scopes alongside provider scopes require multiple authorization servers")
	}
	for _, scope := range doc.ScopesSupported {
		if !validScope(scope) || scope == "openid" || !(slices.Contains(opts.ProviderScopes, scope) || slices.Contains(opts.ExternalScopes, scope)) {
			return nil, fmt.Errorf("oauthprovider: unsupported resource scope %q", scope)
		}
	}
	for _, method := range doc.BearerMethodsSupported {
		if method != "header" && method != "body" && method != "query" {
			return nil, fmt.Errorf("oauthprovider: unknown bearer method %q", method)
		}
	}
	if doc.DPoPSigningAlgorithms == nil {
		doc.DPoPSigningAlgorithms = opts.DefaultDPoPSigningAlgorithms
		if doc.DPoPSigningAlgorithms == nil {
			doc.DPoPSigningAlgorithms = resourceSigningAlgorithms()
		}
	}
	for _, alg := range doc.ResourceSigningAlgorithms {
		if alg == "" || strings.EqualFold(alg, "none") {
			return nil, fmt.Errorf("oauthprovider: invalid resource signing algorithm %q", alg)
		}
	}
	for _, alg := range doc.DPoPSigningAlgorithms {
		if !validDPoPAlgorithm(alg) {
			return nil, fmt.Errorf("oauthprovider: invalid DPoP signing algorithm %q", alg)
		}
	}
	if doc.DPoPBoundAccessTokensRequired != nil && *doc.DPoPBoundAccessTokensRequired && len(doc.DPoPSigningAlgorithms) == 0 {
		return nil, errors.New("oauthprovider: required DPoP needs a signing algorithm")
	}
	body, err := marshalMetadata(doc, opts.Extra)
	if err != nil {
		return nil, err
	}
	path, target := resourceMetadataPath(u)
	return &ResourceDiscovery{url: u.Scheme + "://" + u.Host + target, path: path, requestURI: target, body: body}, nil
}

func resourceSigningAlgorithms() []string {
	return []string{"EdDSA", "ES256", "ES512", "PS256", "RS256"}
}

func validDPoPAlgorithm(alg string) bool {
	return validScope(alg) && !strings.EqualFold(alg, "none") && !strings.HasPrefix(strings.ToUpper(alg), "HS")
}

func resourceMetadataPath(u *url.URL) (string, string) {
	path := "/.well-known/oauth-protected-resource" + strings.TrimSuffix(u.EscapedPath(), "/")
	target := path
	if u.ForceQuery || u.RawQuery != "" {
		target += "?" + u.RawQuery
	}
	return path, target
}

func marshalMetadata(doc ResourceMetadata, extra map[string]json.RawMessage) ([]byte, error) {
	body, err := json.Marshal(doc)
	if err != nil || len(extra) == 0 {
		return body, err
	}
	typ := reflect.TypeFor[ResourceMetadata]()
	for i := range typ.NumField() {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		if _, exists := extra[name]; exists {
			return nil, fmt.Errorf("oauthprovider: use the typed metadata field for %q", name)
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, err
	}
	for key, value := range extra {
		if key == "" || !json.Valid(value) {
			return nil, fmt.Errorf("oauthprovider: invalid extra metadata field %q", key)
		}
		fields[key] = value
	}
	return json.Marshal(fields)
}

func metadataURL(raw string, allowQuery bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || strings.ContainsAny(raw, "#\\ \t\r\n") {
		return nil, errors.New("expected an absolute HTTPS URL without credentials or fragment")
	}
	if !allowQuery && (u.RawQuery != "" || u.ForceQuery) {
		return nil, errors.New("issuer URLs cannot contain a query")
	}
	if _, err := url.QueryUnescape(u.RawQuery); err != nil {
		return nil, errors.New("invalid percent encoding in query")
	}
	if port := u.Port(); port != "" {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return nil, errors.New("port exceeds 65535")
		}
	}
	return u, nil
}

func validScope(scope string) bool {
	for _, c := range scope {
		if c < '!' || c > '~' || c == '"' || c == '\\' {
			return false
		}
	}
	return scope != ""
}

// URL returns the absolute metadata URL, including any resource query.
func (d *ResourceDiscovery) URL() string { return d.url }

// Path returns the escaped metadata path for registration with a host router.
func (d *ResourceDiscovery) Path() string { return d.path }

// MarshalJSON returns the configured discovery document.
func (d *ResourceDiscovery) MarshalJSON() ([]byte, error) { return bytes.Clone(d.body), nil }

func (d *ResourceDiscovery) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.RequestURI() != d.requestURI {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	switch r.Method {
	case http.MethodOptions:
		w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
	case http.MethodGet, http.MethodHead:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(d.body)))
		if r.Method == http.MethodGet {
			_, _ = w.Write(d.body)
		}
	default:
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
