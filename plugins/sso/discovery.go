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

func checkEndpoint(host *auth.Auth, raw string) error {
	u, err := endpointURL(raw)
	if err != nil {
		return err
	}
	if host.ExplicitlyTrustedOrigin(raw) {
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

func hydrate(ctx context.Context, host *auth.Auth, client *http.Client, cfg *Config, skip bool) error {
	if cfg.TokenEndpointAuthentication != "" && cfg.TokenEndpointAuthentication != "client_secret_basic" && cfg.TokenEndpointAuthentication != "client_secret_post" {
		return apiError(400, "Unsupported OpenID Connect client authentication method")
	}
	if cfg.DiscoveryEndpoint == "" {
		cfg.DiscoveryEndpoint = strings.TrimRight(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	}
	for _, raw := range []string{cfg.DiscoveryEndpoint, cfg.AuthorizationEndpoint, cfg.TokenEndpoint, cfg.JWKSEndpoint, cfg.UserInfoEndpoint} {
		if raw != "" {
			if err := checkEndpoint(host, raw); err != nil {
				return err
			}
		}
	}
	if !skip {
		// Discovery takes a customer-supplied URL. Only contact an independently
		// trusted origin. Never forward it to a redirect target.
		if !host.ExplicitlyTrustedOrigin(cfg.DiscoveryEndpoint) {
			return discoveryError(400, "discovery_untrusted_origin", "The discovery endpoint origin is not trusted")
		}
		doc, err := fetchDiscovery(ctx, client, cfg.DiscoveryEndpoint)
		if err != nil {
			return err
		}
		if doc.Issuer == "" || doc.Authorization == "" || doc.Token == "" || doc.Keys == "" {
			return discoveryError(400, "discovery_incomplete", "The discovery document is missing required fields")
		}
		if doc.Issuer != cfg.Issuer {
			return discoveryError(400, "issuer_mismatch", "The discovered issuer does not match the configured issuer")
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
			raw := parsed.String()
			if _, err = endpointURL(raw); err != nil {
				return err
			}
			// A discovered endpoint must sit on a trusted origin, so a
			// document cannot send the client secret elsewhere. A private
			// host outside the trusted origins answers this code too. Trust
			// uses exact TrustedOrigins entries only; another runtime also
			// honours wildcard patterns.
			if !host.ExplicitlyTrustedOrigin(raw) {
				return discoveryError(400, "discovery_untrusted_origin", fmt.Sprintf("The %s %q is not trusted by your trusted origins configuration", f.name, raw))
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
			case slices.Contains(doc.Methods, "private_key_jwt"):
				return apiError(400, "Unsupported OpenID Connect client authentication method")
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
	if err := hydrate(ctx, host, o.HTTPClient, &cfg, false); err != nil {
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
	if res.StatusCode != 200 {
		return doc, discoveryError(502, "discovery_unexpected_error", "Discovery document could not be retrieved")
	}
	const bound = 1 << 20
	data, e := io.ReadAll(io.LimitReader(res.Body, bound+1))
	if e != nil || len(data) > bound || strings.TrimSpace(string(data)) == "null" || json.Unmarshal(data, &doc) != nil {
		return doc, discoveryError(400, "discovery_invalid_json", "Invalid discovery document")
	}
	return doc, nil
}
