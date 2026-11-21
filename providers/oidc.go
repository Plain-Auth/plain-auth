package providers

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	betterauth "github.com/nabuhadba/go-better-auth"
	"golang.org/x/oauth2"
)

// OpenIDConnect discovers an operator-configured issuer and its rotating
// signing keys. Register the result under a stable SocialProviders name.
// Its ID tokens must contain a subject, verified email and matching nonce.
func OpenIDConnect(ctx context.Context, issuer, clientID, clientSecret string) (betterauth.OAuthProvider, error) {
	var zero betterauth.OAuthProvider
	if !secureEndpoint(issuer) || clientID == "" {
		return zero, errors.New("invalid OpenID Connect issuer or client ID")
	}
	client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	discoveryCtx := oidc.ClientContext(ctx, client)
	discovered, err := oidc.NewProvider(discoveryCtx, issuer)
	if err != nil {
		return zero, err
	}
	var meta struct {
		Keys string `json:"jwks_uri"`
	}
	if err := discovered.Claims(&meta); err != nil {
		return zero, err
	}
	endpoint := discovered.Endpoint()
	if !secureEndpoint(meta.Keys) || !secureEndpoint(endpoint.AuthURL) || !secureEndpoint(endpoint.TokenURL) {
		return zero, errors.New("invalid endpoints in OpenID Connect discovery")
	}
	verifier := discovered.VerifierContext(oidc.ClientContext(context.Background(), client), &oidc.Config{ClientID: clientID})
	return oidcProvider(clientID, clientSecret, endpoint, verifier, client), nil
}

func secureEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback()))
}
