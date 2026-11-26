package sso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/publicnet"
)

func discoveryError(status int, code, msg string) error {
	return &auth.APIError{Status: status, Code: code, Message: msg}
}

// endpointURL follows the documented URL rules and is stricter than another
// runtime's code: credentials, a fragment and a backslash are refused too.
func endpointURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 4096 || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") || strings.Contains(raw, "\\") {
		return nil, discoveryError(400, "discovery_invalid_url", "Invalid OpenID Connect endpoint URL")
	}
	return u, nil
}

// checkEndpoint refuses a private or malformed endpoint unless trusted names
// its exact origin.
// checkEndpoint classifies the literal host only. A name that resolves to a
// non-public address is refused when the server connects to it, not here,
// where another runtime resolves it first.
func checkEndpoint(trusted func(string) bool, raw string) error {
	u, err := endpointURL(raw)
	if err != nil {
		return err
	}
	if trusted(raw) {
		return nil
	}
	name := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	isLocal := name == "metadata.goog" || !strings.Contains(name, ".") || strings.HasSuffix(name, ".localhost") || strings.HasSuffix(name, ".local") || strings.HasSuffix(name, ".internal")
	if a, err := netip.ParseAddr(name); err == nil {
		isLocal = !publicnet.Address(a)
	}

	if isLocal {
		return discoveryError(400, "discovery_private_host", "An internal identity provider endpoint needs an explicitly trusted origin")
	}
	return nil
}

type discoveryDocument struct {
	Issuer        string   `json:"issuer"`
	Authorization string   `json:"authorization_endpoint"`
	Token         string   `json:"token_endpoint"`
	Keys          string   `json:"jwks_uri"`
	UserInfo      string   `json:"userinfo_endpoint"`
	Revocation    string   `json:"revocation_endpoint"`
	EndSession    string   `json:"end_session_endpoint"`
	Introspection string   `json:"introspection_endpoint"`
	Methods       []string `json:"token_endpoint_auth_methods_supported"`
}

func hydrate(ctx context.Context, trusted func(string) bool, client *http.Client, cfg *Config, skip bool) error {
	if cfg.TokenEndpointAuthentication != "" && cfg.TokenEndpointAuthentication != "client_secret_basic" && cfg.TokenEndpointAuthentication != "client_secret_post" && cfg.TokenEndpointAuthentication != privateKeyJWT {
		return apiError(400, "Unsupported OpenID Connect client authentication method")
	}
	// The supplied endpoints are checked first, in another runtime's order,
	// so a private one answers discovery_private_host. A discovery URL
	// derived from the issuer is not supplied: it is checked only when it is
	// fetched.
	for _, raw := range []string{cfg.AuthorizationEndpoint, cfg.TokenEndpoint, cfg.UserInfoEndpoint, cfg.JWKSEndpoint, cfg.DiscoveryEndpoint} {
		if raw != "" {
			if err := checkEndpoint(trusted, raw); err != nil {
				return err
			}
		}
	}
	if cfg.DiscoveryEndpoint == "" {
		cfg.DiscoveryEndpoint = strings.TrimSuffix(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	}
	if _, err := endpointURL(cfg.DiscoveryEndpoint); err != nil {
		return err
	}
	// Discovery takes a customer-supplied URL. Only contact an independently
	// trusted origin. Never forward it to a redirect target.
	if !skip && !trusted(cfg.DiscoveryEndpoint) {
		return untrustedDiscovery(cfg.DiscoveryEndpoint)
	}
	if !skip {
		doc, err := fetchDiscovery(ctx, client, cfg.DiscoveryEndpoint)
		if err != nil {
			return err
		}
		// The messages are the ones another runtime sends.
		var missing []string
		for _, f := range []struct{ name, value string }{{"issuer", doc.Issuer}, {"authorization_endpoint", doc.Authorization}, {"token_endpoint", doc.Token}, {"jwks_uri", doc.Keys}} {
			if f.value == "" {
				missing = append(missing, f.name)
			}
		}
		if len(missing) > 0 {
			return discoveryError(400, "discovery_incomplete", "OIDC discovery document is missing required fields: Discovery document is missing required fields: "+strings.Join(missing, ", "))
		}
		if doc.Issuer != cfg.Issuer {
			return discoveryError(400, "issuer_mismatch", fmt.Sprintf("OIDC issuer mismatch: Discovered issuer %q does not match configured issuer %q", doc.Issuer, cfg.Issuer))
		}
		base, _ := endpointURL(cfg.Issuer)
		// The revocation, end-session and introspection endpoints are checked
		// like the others but not stored, because sign-in never calls them.
		for _, f := range []struct {
			name     string
			stored   *string
			document string
		}{{"token_endpoint", &cfg.TokenEndpoint, doc.Token}, {"authorization_endpoint", &cfg.AuthorizationEndpoint, doc.Authorization}, {"jwks_uri", &cfg.JWKSEndpoint, doc.Keys},
			{"userinfo_endpoint", &cfg.UserInfoEndpoint, doc.UserInfo}, {"revocation_endpoint", nil, doc.Revocation}, {"end_session_endpoint", nil, doc.EndSession}, {"introspection_endpoint", nil, doc.Introspection}} {
			if f.document == "" {
				continue
			}
			parsed, err := url.Parse(f.document)
			if err == nil && !parsed.IsAbs() {
				root := *base
				root.RawQuery = ""
				root.Fragment = ""
				root.Path = strings.TrimRight(base.Path, "/") + "/"
				parsed, err = root.Parse(strings.TrimLeft(f.document, "/"))
			}
			if err != nil {
				return discoveryError(400, "discovery_invalid_url", "Invalid URL in the discovery document")
			}
			// Stored as another runtime's URL parser writes it.
			raw := whatwgURL(parsed.String())
			if _, err = endpointURL(raw); err != nil {
				return err
			}
			// A discovered endpoint must sit on a trusted origin, so a
			// document cannot send the client secret elsewhere. A private
			// host outside the trusted origins answers this code too. Trust
			// uses exact TrustedOrigins entries only; another runtime also
			// honours wildcard patterns.
			if !trusted(raw) {
				return discoveryError(400, "discovery_untrusted_origin", untrustedPrefix+"The "+f.name+" \""+whatwgURL(raw)+"\" is not trusted by your trusted origins configuration.")
			}
			if f.stored != nil && *f.stored == "" {
				*f.stored = raw
			}
		}
		if cfg.TokenEndpointAuthentication == "" {
			switch {
			case slices.Contains(doc.Methods, "client_secret_basic") || len(doc.Methods) == 0:
				cfg.TokenEndpointAuthentication = "client_secret_basic"
			case slices.Contains(doc.Methods, "client_secret_post"):
				cfg.TokenEndpointAuthentication = "client_secret_post"
			case slices.Contains(doc.Methods, privateKeyJWT):
				cfg.TokenEndpointAuthentication = privateKeyJWT
			default:
				cfg.TokenEndpointAuthentication = "client_secret_basic"
			}
		}
	}
	// A skipDiscovery registration may leave endpoints out; sign-in then
	// discovers them for each request.
	return nil
}

// needsRuntimeDiscovery reports whether a stored OIDC configuration lacks an
// endpoint that sign-in needs: the authorization, token or JWKS endpoint.
func needsRuntimeDiscovery(c *Config) bool {
	return c == nil || c.AuthorizationEndpoint == "" || c.TokenEndpoint == "" || c.JWKSEndpoint == ""
}

// withRuntimeDiscovery fills the endpoints a stored configuration leaves out
// from the issuer's discovery document, under the registration rules: an
// exactly trusted discovery origin, a matching issuer, a bounded fetch and
// trusted endpoint origins. Stored endpoints win. The filled copy serves this
// request only and is never stored.
func (o Options) withRuntimeDiscovery(ctx context.Context, host *auth.Auth, p BrowserProvider) (BrowserProvider, error) {
	if p.OIDC == nil || !needsRuntimeDiscovery(p.OIDC) {
		return p, nil
	}
	cfg := *p.OIDC
	if cfg.Issuer == "" {
		cfg.Issuer = p.Issuer
	}
	// An unset method means client_secret_basic; runtime discovery never changes it.
	if cfg.TokenEndpointAuthentication == "" {
		cfg.TokenEndpointAuthentication = "client_secret_basic"
	}
	// Another runtime fetches the document before it checks the stored
	// endpoints, so an untrusted discovery origin is named first.
	trust := requestTrust(ctx, host)
	discovery := cfg.DiscoveryEndpoint
	if discovery == "" {
		discovery = strings.TrimSuffix(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	}
	if !trust(discovery) {
		return p, untrustedDiscovery(discovery)
	}
	if err := hydrate(ctx, trust, o.HTTPClient, &cfg, false); err != nil {
		return p, err
	}
	p.OIDC = &cfg
	return p, nil
}
func fetchDiscovery(ctx context.Context, client *http.Client, endpoint string) (doc discoveryDocument, err error) {
	if client == nil {
		client = http.DefaultClient
	}
	requestClient := *client
	requestClient.Jar = nil
	requestClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return doc, discoveryError(400, "discovery_invalid_url", "Invalid discovery endpoint")
	}
	req.Header.Set("Accept", "application/json")
	res, err := requestClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			return doc, discoveryError(502, "discovery_timeout", "Discovery timed out")
		}
		return doc, discoveryError(502, "discovery_unexpected_error", "Could not reach the discovery endpoint")
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return doc, discoveryError(400, "oidc_endpoint_redirect", "Configure the final discovery endpoint URL")
	}
	if res.StatusCode == 408 {
		return doc, discoveryError(502, "discovery_timeout", "Discovery timed out")
	}
	if res.StatusCode == 404 {
		return doc, discoveryError(400, "discovery_not_found", "Discovery document not found")
	}
	// Any 2xx answer carries the document, as in another runtime; an empty
	// one is invalid JSON.
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return doc, discoveryError(502, "discovery_unexpected_error", "Discovery document could not be retrieved")
	}
	const bound = 1 << 20
	data, e := io.ReadAll(io.LimitReader(res.Body, bound+1))
	if e != nil || len(data) > bound || strings.TrimSpace(string(data)) == "null" || json.Unmarshal(data, &doc) != nil {
		return doc, discoveryError(400, "discovery_invalid_json", "Invalid discovery document")
	}
	return doc, nil
}

// untrustedPrefix starts another runtime's route message for an untrusted
// discovery URL; the callback's error_description leaves it out.
const untrustedPrefix = "Untrusted OIDC discovery URL: "

// untrustedDiscovery refuses a discovery URL outside the trusted origins
// with another runtime's message.
func untrustedDiscovery(raw string) error {
	return discoveryError(400, "discovery_untrusted_origin", untrustedPrefix+"The main discovery endpoint \""+whatwgURL(raw)+"\" is not trusted by your trusted origins configuration.")
}

// whatwgURL writes an absolute URL as another runtime's URL parser does:
// lowercase scheme and host, no default port and "/" for an empty path.
func whatwgURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return raw
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if u.Scheme == "https" && port == "443" || u.Scheme == "http" && port == "80" {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	u.Host = host
	if port != "" {
		u.Host += ":" + port
	}
	if u.Path == "" && u.Opaque == "" {
		u.Path = "/"
	}
	return u.String()
}

// requestTrust trusts the exact origins configured for the request ctx
// belongs to, including those TrustedOriginsForRequest returned. OIDC
// discovery, endpoint checks and identity provider requests use it.
func requestTrust(ctx context.Context, host *auth.Auth) func(string) bool {
	return func(raw string) bool { return host.ExplicitlyTrustedOriginFor(ctx, raw) }
}
