package providers

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	facebookIssuer = "https://www.facebook.com"
	facebookKeys   = "https://limited.facebook.com/.well-known/oauth/openid/jwks/"
)

// facebookAccessToken checks that token is a valid Facebook access token
// issued to one of apps, then reads the profile it names. Graph's /me
// answers for a token issued to any app, so debug_token binds it to this
// one first.
func facebookAccessToken(ctx context.Context, apps []string, secret, token, profileURL string) (auth.OAuthProfile, error) {
	client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	// The check's URL carries the app secret, which a redirect would repeat
	// as Referer.
	client = noRedirects(client)
	check, err := http.NewRequestWithContext(ctx, "GET", "https://graph.facebook.com/debug_token?"+url.Values{"input_token": {token}, "access_token": {apps[0] + "|" + secret}}.Encode(), nil)
	if err != nil {
		return auth.OAuthProfile{}, errors.New("Facebook token binding failed")
	}
	verified, err := providerJSON(client, check)
	data := verified.object("data")
	if err != nil || !data.verified("is_valid") || !slices.Contains(apps, data.text("app_id")) || data.text("user_id") == "" {
		return auth.OAuthProfile{}, errors.New("Facebook token binding failed")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", profileURL, nil)
	if err != nil {
		return auth.OAuthProfile{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	p, err := providerJSON(client, req)
	if err != nil || p.text("id") != data.text("user_id") {
		return auth.OAuthProfile{}, errors.New("Facebook account binding failed")
	}
	profile, err := mapProfile("facebook", p)
	profile.Data = p
	return profile, err
}

// limitedLoginProfile maps a Limited Login ID token. Facebook does not say
// whether its email is verified, so it is not.
func limitedLoginProfile(token *oidc.IDToken) (auth.OAuthProfile, error) {
	p, err := standardProfile(token)
	p.EmailVerified = false
	return p, err
}

// facebookLogin adds Limited Login ID tokens and access tokens to p for the
// apps it accepts.
func facebookLogin(p *auth.OAuthProvider, apps []string, secret, profileURL string, client *http.Client) {
	p.Resolve = func(ctx context.Context, t *oauth2.Token, _ string) (auth.OAuthProfile, error) {
		return facebookAccessToken(ctx, apps, secret, t.AccessToken, profileURL)
	}
	p.VerifyAccessToken = func(ctx context.Context, token string) (auth.OAuthProfile, error) {
		return facebookAccessToken(ctx, apps, secret, token, profileURL)
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), noRedirects(client)), facebookKeys)
	verifier := oidc.NewVerifier(facebookIssuer, keys, &oidc.Config{SkipClientIDCheck: true, SupportedSigningAlgs: []string{oidc.RS256}})
	p.VerifyIDToken = func(ctx context.Context, raw, nonce string) (auth.OAuthProfile, time.Time, error) {
		return resolveSignedToken(ctx, verifier, idTokenRules{profile: limitedLoginProfile}, apps, raw, nonce, "", true)
	}
}
