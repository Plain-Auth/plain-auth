package sso

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
)

func discoveryError(status int, code, msg string) error {
	return &auth.APIError{Status: status, Code: code, Message: msg}
}
func endpointURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 4096 || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") || strings.Contains(raw, "\\") {
		return nil, discoveryError(400, "discovery_invalid_url", "Invalid OpenID Connect endpoint URL")
	}
	return u, nil
}

// Additional special-purpose prefixes that netip.IsGlobalUnicast does not exclude.
var specialIPs = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2001::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}
var v6Global = netip.MustParsePrefix("2000::/3")

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
		a = a.Unmap()
		isLocal = !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() || a.Zone() != "" || a.Is6() && !v6Global.Contains(a)
		for _, prefix := range specialIPs {
			if prefix.Contains(a) {
				isLocal = true
				break
			}
		}
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
		for _, f := range []struct {
			stored   *string
			document string
		}{{&cfg.AuthorizationEndpoint, doc.Authorization}, {&cfg.TokenEndpoint, doc.Token}, {&cfg.JWKSEndpoint, doc.Keys}, {&cfg.UserInfoEndpoint, doc.UserInfo}} {
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
			if err = checkEndpoint(host, raw); err != nil {
				return err
			}
			if *f.stored == "" {
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
	if cfg.AuthorizationEndpoint == "" || cfg.TokenEndpoint == "" || cfg.JWKSEndpoint == "" {
		return discoveryError(400, "discovery_incomplete", "Supply authorization, token and JWKS endpoints")
	}
	return nil
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
	if e != nil || len(data) > bound || json.Unmarshal(data, &doc) != nil {
		return doc, discoveryError(400, "discovery_invalid_json", "Invalid discovery document")
	}
	return doc, nil
}
