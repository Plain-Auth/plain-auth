package providers

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/httporigin"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OpenIDConnect discovers an operator-configured issuer and its rotating
// signing keys. Register the result under a stable SocialProviders name.
// Its ID tokens must contain a subject, an email address and a matching nonce.
func OpenIDConnect(ctx context.Context, issuer, clientID, clientSecret string) (authn.OAuthProvider, error) {
	return OpenIDConnectWithOptions(ctx, OpenIDConnectOptions{Issuer: issuer, ClientID: clientID, ClientSecret: clientSecret})
}

// OpenIDConnectOptions configures OpenIDConnectWithOptions.
type OpenIDConnectOptions struct {
	Issuer, ClientID, ClientSecret string
	// DiscoveryHeaders are sent with the discovery request, and with signing
	// key requests to the issuer's origin, such as Epic's Epic-Client-ID.
	// Discovery follows no redirects.
	DiscoveryHeaders http.Header
	// DisableNonceBinding sends no nonce on browser sign-in and accepts an
	// ID token without one, for a provider that does not echo it. That
	// removes ID token replay protection from browser sign-in; a directly
	// submitted ID token still needs its nonce.
	DisableNonceBinding bool
}

// OpenIDConnectWithOptions is OpenIDConnect with discovery headers and
// optional nonce binding.
func OpenIDConnectWithOptions(ctx context.Context, o OpenIDConnectOptions) (authn.OAuthProvider, error) {
	var zero authn.OAuthProvider
	issuerURL, err := url.Parse(o.Issuer)
	if err != nil || !secureEndpoint(o.Issuer) || o.ClientID == "" {
		return zero, errors.New("invalid OpenID Connect issuer or client ID")
	}
	headers, err := httporigin.Headers(o.DiscoveryHeaders)
	if err != nil {
		return zero, errors.New("OpenID Connect discovery headers: " + err.Error())
	}
	client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	discovery := httporigin.WithHeaders(noRedirects(client), httporigin.Canonical(issuerURL), headers)
	discovered, err := oidc.NewProvider(oidc.ClientContext(ctx, discovery), o.Issuer)
	if err != nil {
		return zero, err
	}
	var meta struct {
		Keys   string `json:"jwks_uri"`
		Logout string `json:"end_session_endpoint"`
	}
	if err := discovered.Claims(&meta); err != nil {
		return zero, err
	}
	endpoint := discovered.Endpoint()
	if !secureEndpoint(meta.Keys) || !secureEndpoint(endpoint.AuthURL) || !secureEndpoint(endpoint.TokenURL) {
		return zero, errors.New("invalid endpoints in OpenID Connect discovery")
	}
	verifier := discovered.VerifierContext(oidc.ClientContext(context.Background(), discovery), &oidc.Config{ClientID: o.ClientID})
	provider := signedProvider(o.ClientID, o.ClientSecret, endpoint, verifier, client, idTokenRules{profile: standardProfile, optionalCodeNonce: o.DisableNonceBinding})
	provider.OmitNonce = o.DisableNonceBinding
	if secureEndpoint(meta.Logout) {
		provider.EndSessionEndpoint = meta.Logout
	}
	return provider, nil
}

// noRedirects returns a copy of c, or of a default client, that does not
// follow redirects. Discovery documents and signing keys must be served at
// their configured URL, so a provider cannot steer these server-side
// requests to another address.
func noRedirects(c *http.Client) *http.Client {
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	copied := *c
	copied.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &copied
}

func secureEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback()))
}
