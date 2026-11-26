// Package providers configures supported social sign-in providers.
package providers

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// Google configures OpenID Connect sign-in with Google's OAuth endpoints and
// rotating signing keys. Identity is read only from a verified ID token.
func Google(clientID, clientSecret string) authn.OAuthProvider {
	return GoogleWithOptions(GoogleOptions{ClientID: clientID, ClientSecret: clientSecret})
}

type GoogleOptions struct {
	ClientID, ClientSecret string
	// AdditionalClientIDs are the app's other Google client IDs, such as its
	// iOS and Android ones. A directly submitted ID token or One Tap
	// credential may name any of them, or ClientID, as its audience; the code
	// exchange uses ClientID. Empty entries are ignored.
	AdditionalClientIDs []string
	HostedDomain        string
	// AccessType is sent as access_type, for example "offline" for a refresh
	// token.
	AccessType string
	// Display is sent as display: "page", "popup", "touch" or "wap".
	Display string
	// DisableIncludeGrantedScopes stops sending include_granted_scopes=true,
	// which otherwise keeps scopes the user granted earlier.
	DisableIncludeGrantedScopes bool
	DisableSignUp               bool
	HTTPClient                  *http.Client
}

// GoogleWithOptions configures audience, Workspace restriction, registration,
// and the HTTP client used for Google's rotating keys and token endpoint.
func GoogleWithOptions(o GoogleOptions) authn.OAuthProvider {
	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), noRedirects(client)), "https://www.googleapis.com/oauth2/v3/certs")
	p := google(o.ClientID, o.ClientSecret, keys, client, o.AdditionalClientIDs...)
	p.GoogleHostedDomain = o.HostedDomain
	p.DisableSignUp = o.DisableSignUp
	p.AuthorizationParams = url.Values{}
	if !o.DisableIncludeGrantedScopes {
		p.AuthorizationParams.Set("include_granted_scopes", "true")
	}
	for key, value := range map[string]string{"hd": o.HostedDomain, "access_type": o.AccessType, "display": o.Display} {
		if value != "" {
			p.AuthorizationParams.Set(key, value)
		}
	}
	return p
}

// googleIssuers are both spellings Google uses for its ID token issuer.
var googleIssuers = []string{"https://accounts.google.com", "accounts.google.com"}

func google(id, secret string, keys oidc.KeySet, client *http.Client, more ...string) authn.OAuthProvider {
	rules := idTokenRules{profile: standardProfile, issuers: googleIssuers}
	verifier := oidc.NewVerifier("https://accounts.google.com", keys, &oidc.Config{ClientID: id, SkipIssuerCheck: true, SupportedSigningAlgs: []string{"RS256"}})
	p := signedProvider(id, secret, endpoints.Google, verifier, client, rules)
	p.AllowVerifiedEmailLink = true
	if ids := clientIDs(id, more); len(ids) > 1 {
		// A directly submitted token may be issued to any of the app's client
		// IDs; the code exchange still checks ClientID only.
		direct := oidc.NewVerifier("https://accounts.google.com", keys, &oidc.Config{SkipClientIDCheck: true, SkipIssuerCheck: true, SupportedSigningAlgs: []string{"RS256"}})
		p.VerifyIDToken = func(ctx context.Context, raw, nonce string) (authn.OAuthProfile, time.Time, error) {
			return resolveSignedToken(ctx, direct, rules, ids, raw, nonce, "", true)
		}
	}
	return p
}

// clientIDs returns id and the nonempty additional IDs other than id. An
// empty audience would weaken the authorized-party check.
func clientIDs(id string, more []string) []string {
	ids := []string{id}
	for _, other := range more {
		if other != "" && other != id {
			ids = append(ids, other)
		}
	}
	return ids
}

type idTokenRules struct {
	allowHashedNonce bool
	// optionalCodeNonce skips the nonce check on the code exchange, for a
	// provider whose authorization request sends none.
	optionalCodeNonce bool
	profile           func(*oidc.IDToken) (authn.OAuthProfile, error)
	// issuers, when set, are the accepted issuers for a verifier that skips
	// its own issuer check.
	issuers []string
}

func oidcProvider(id, secret string, endpoint oauth2.Endpoint, verifier *oidc.IDTokenVerifier, client *http.Client) authn.OAuthProvider {
	return signedProvider(id, secret, endpoint, verifier, client, idTokenRules{profile: standardProfile})
}

type identityClaims struct {
	Name, Email     string
	Picture         *string
	Verified        json.RawMessage `json:"email_verified"`
	AuthorizedParty string          `json:"azp"`
}

func verifiedFlag(raw json.RawMessage) bool { return string(raw) == "true" || string(raw) == `"true"` }
func standardProfile(token *oidc.IDToken) (authn.OAuthProfile, error) {
	var c identityClaims
	if err := token.Claims(&c); err != nil {
		return authn.OAuthProfile{}, err
	}
	return authn.OAuthProfile{Subject: token.Subject, Name: c.Name, Email: c.Email, EmailVerified: verifiedFlag(c.Verified), Image: c.Picture}, nil
}

func resolveSignedToken(ctx context.Context, verifier *oidc.IDTokenVerifier, rules idTokenRules, audiences []string, raw, nonce, access string, requireNonce bool) (authn.OAuthProfile, time.Time, error) {
	var profile authn.OAuthProfile
	token, err := verifier.Verify(ctx, raw)
	if err != nil {
		return profile, time.Time{}, err
	}
	if len(rules.issuers) > 0 && !slices.Contains(rules.issuers, token.Issuer) {
		return profile, time.Time{}, errors.New("unexpected OpenID Connect issuer")
	}
	nonceOK := subtle.ConstantTimeCompare([]byte(token.Nonce), []byte(nonce)) == 1
	if !nonceOK && rules.allowHashedNonce {
		sum := sha256.Sum256([]byte(nonce))
		nonceOK = subtle.ConstantTimeCompare([]byte(token.Nonce), []byte(hex.EncodeToString(sum[:]))) == 1
	}
	if requireNonce && (nonce == "" || !nonceOK) {
		return profile, time.Time{}, errors.New("OpenID Connect nonce mismatch")
	}
	now := time.Now()
	if token.IssuedAt.IsZero() || token.IssuedAt.After(now.Add(time.Minute)) || now.Sub(token.IssuedAt) > time.Hour {
		return profile, time.Time{}, errors.New("OpenID Connect token outside allowed age")
	}
	if access != "" && token.AccessTokenHash != "" {
		if err := token.VerifyAccessToken(access); err != nil {
			return profile, time.Time{}, err
		}
	}
	var claims identityClaims
	if err := token.Claims(&claims); err != nil {
		return profile, time.Time{}, err
	}
	if !slices.ContainsFunc(token.Audience, func(aud string) bool { return slices.Contains(audiences, aud) }) {
		return profile, time.Time{}, errors.New("unexpected OpenID Connect audience")
	}
	// An authorized party, when present, must be one of the app's client
	// IDs; a token for several audiences must also name one of them.
	party, multi := claims.AuthorizedParty, len(token.Audience) > 1
	if (multi || party != "") && !slices.Contains(audiences, party) || multi && !slices.Contains(token.Audience, party) {
		return profile, time.Time{}, errors.New("unexpected authorized party")
	}
	profile, err = rules.profile(token)
	if err == nil {
		var claims map[string]any
		if err = token.Claims(&claims); err == nil {
			profile.Data = claims
		}
	}
	return profile, token.Expiry, err
}

func signedProvider(id, secret string, endpoint oauth2.Endpoint, verifier *oidc.IDTokenVerifier, client *http.Client, rules idTokenRules) authn.OAuthProvider {
	audiences := []string{id}
	return authn.OAuthProvider{
		Config:     oauth2.Config{ClientID: id, ClientSecret: secret, Endpoint: endpoint, Scopes: []string{"openid", "profile", "email"}},
		HTTPClient: client,
		Resolve: func(ctx context.Context, t *oauth2.Token, nonce string) (authn.OAuthProfile, error) {
			raw, _ := t.Extra("id_token").(string)
			profile, _, err := resolveSignedToken(ctx, verifier, rules, audiences, raw, nonce, t.AccessToken, !rules.optionalCodeNonce)
			return profile, err
		},
		VerifyIDToken: func(ctx context.Context, raw, nonce string) (authn.OAuthProfile, time.Time, error) {
			return resolveSignedToken(ctx, verifier, rules, audiences, raw, nonce, "", true)
		},
	}
}
