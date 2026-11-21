package providers

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	authn "github.com/FineStack/finestack-auth"
	"golang.org/x/oauth2"
)

// Apple uses the Services ID and the current developer-signed client-secret JWT
// supplied by the application. Tokens must be issued for that Services ID.
func Apple(clientID, clientSecret string) authn.OAuthProvider {
	client := &http.Client{Timeout: 15 * time.Second}
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), "https://appleid.apple.com/auth/keys")
	return appleProvider(clientID, clientSecret, keys, client)
}

func appleProvider(id, secret string, keys oidc.KeySet, client *http.Client) authn.OAuthProvider {
	const issuer = "https://appleid.apple.com"
	verifier := oidc.NewVerifier(issuer, keys, &oidc.Config{ClientID: id, SupportedSigningAlgs: []string{"RS256"}})
	p := signedProvider(id, secret, oauth2.Endpoint{AuthURL: issuer + "/auth/authorize", TokenURL: issuer + "/auth/token", AuthStyle: oauth2.AuthStyleInParams}, verifier, client, idTokenRules{allowHashedNonce: true, profile: standardProfile})
	p.Config.Scopes = []string{"email", "name"}
	p.AuthorizationParams = url.Values{"response_mode": {"form_post"}, "response_type": {"code id_token"}}
	p.AllowVerifiedEmailLink = true
	p.FormPostName = true
	return p
}
