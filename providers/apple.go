package providers

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Apple uses the Services ID and the current developer-signed client-secret JWT
// supplied by the application. Tokens must be issued for that Services ID.
func Apple(clientID, clientSecret string) authn.OAuthProvider {
	return appleWithAudiences(clientID, clientSecret, nil, nil)
}

// AppleOptions configures the audiences of directly submitted Apple ID tokens.
// Browser code exchanges always use the Services ID supplied to the constructor.
type AppleOptions struct {
	ClientID, ClientSecret string
	HTTPClient             *http.Client
	AppBundleIdentifier    string
	// NativeAudiences takes precedence over AppBundleIdentifier when nonempty.
	NativeAudiences []string
}

// AppleWithOptions supports an application whose native bundle identifier or
// accepted native audiences differ from its web Services ID.
func AppleWithOptions(opts AppleOptions) (authn.OAuthProvider, error) {
	if opts.ClientID == "" || opts.ClientSecret == "" {
		return authn.OAuthProvider{}, errors.New("apple: client ID and client secret are required")
	}
	audiences := opts.NativeAudiences
	if len(audiences) == 0 && opts.AppBundleIdentifier != "" {
		audiences = []string{opts.AppBundleIdentifier}
	}
	for _, audience := range audiences {
		if audience == "" || strings.TrimSpace(audience) != audience {
			return authn.OAuthProvider{}, errors.New("apple: invalid native audience")
		}
	}
	return appleWithAudiences(opts.ClientID, opts.ClientSecret, opts.HTTPClient, audiences), nil
}

func appleWithAudiences(clientID, clientSecret string, client *http.Client, audiences []string) authn.OAuthProvider {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), noRedirects(client)), "https://appleid.apple.com/auth/keys")
	return appleProvider(clientID, clientSecret, keys, client, audiences...)
}

func appleProvider(id, secret string, keys oidc.KeySet, client *http.Client, nativeAudiences ...string) authn.OAuthProvider {
	const issuer = "https://appleid.apple.com"
	verifier := oidc.NewVerifier(issuer, keys, &oidc.Config{ClientID: id, SupportedSigningAlgs: []string{"RS256"}})
	endpoint := oauth2.Endpoint{AuthURL: issuer + "/auth/authorize", TokenURL: issuer + "/auth/token", AuthStyle: oauth2.AuthStyleInParams}
	rules := idTokenRules{allowHashedNonce: true, profile: standardProfile}
	p := signedProvider(id, secret, endpoint, verifier, client, rules)
	if len(nativeAudiences) > 0 {
		// Verify once against Apple's keys, then require an exact configured
		// audience before exposing the profile. Keep the browser verifier above.
		nativeVerifier := oidc.NewVerifier(issuer, keys, &oidc.Config{SkipClientIDCheck: true, SupportedSigningAlgs: []string{"RS256"}})
		audiences := slices.Clone(nativeAudiences)
		p.VerifyIDToken = func(ctx context.Context, raw, nonce string) (authn.OAuthProfile, time.Time, error) {
			return resolveSignedToken(ctx, nativeVerifier, rules, audiences, raw, nonce, "")
		}
	}
	p.Config.Scopes = []string{"email", "name"}
	p.AuthorizationParams = url.Values{"response_mode": {"form_post"}, "response_type": {"code id_token"}}
	p.AllowVerifiedEmailLink = true
	p.FormPostName = true
	return p
}
