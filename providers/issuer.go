package providers

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// CognitoOptions identifies an Amazon Cognito user pool and hosted sign-in domain.
type CognitoOptions struct{ Domain, Region, UserPoolID, IdentityProvider string }

var awsRegion = regexp.MustCompile(`^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$`)
var poolSuffix = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

// Cognito configures a hosted Cognito login and verifies signed user-pool ID
// tokens. An access-token-only response uses the hosted userinfo endpoint.
func Cognito(id, secret string, options CognitoOptions) (auth.OAuthProvider, error) {
	domain := strings.TrimPrefix(options.Domain, "https://")
	host, err := url.Parse("https://" + domain)
	suffix, ok := strings.CutPrefix(options.UserPoolID, options.Region+"_")
	if err != nil || domain == "" || host.Hostname() != domain || host.User != nil || host.Path != "" || host.RawQuery != "" || host.Fragment != "" || !awsRegion.MatchString(options.Region) || !ok || !poolSuffix.MatchString(suffix) {
		return auth.OAuthProvider{}, errors.New("invalid Cognito domain, region or user pool ID")
	}
	issuer := "https://cognito-idp." + options.Region + ".amazonaws.com/" + options.UserPoolID
	return issuerBrowser("cognito", id, secret, issuer, host.String(), issuer+"/.well-known/jwks.json", options.IdentityProvider, nil), nil
}

// Paybin configures a Paybin issuer. An empty issuer selects the public
// service. Signing keys are discovered from the issuer on first use.
func Paybin(id, secret, issuer string) (auth.OAuthProvider, error) {
	if issuer == "" {
		issuer = "https://idp.paybin.io"
	}
	issuer = strings.TrimRight(issuer, "/")
	if !secureEndpoint(issuer) || strings.ContainsAny(issuer, "?#") {
		return auth.OAuthProvider{}, errors.New("invalid Paybin issuer")
	}
	return issuerBrowser("paybin", id, secret, issuer, issuer, "", "", nil), nil
}

const twitchIssuer = "https://id.twitch.tv/oauth2"

func Twitch(id, secret string) auth.OAuthProvider {
	return issuerBrowser("twitch", id, secret, twitchIssuer, twitchIssuer, twitchIssuer+"/keys", "", nil)
}

func issuerBrowser(name, id, secret, issuer, base, jwks, identityProvider string, keys oidc.KeySet) auth.OAuthProvider {
	client := &http.Client{Timeout: 15 * time.Second}
	if keys == nil {
		keys = &issuerKeys{issuer: issuer, uri: jwks}
	}
	verifier := oidc.NewVerifier(issuer, keys, &oidc.Config{ClientID: id, SupportedSigningAlgs: []string{"RS256"}})
	prefix := "/oauth2"
	if name == "twitch" {
		prefix = ""
	}
	endpoint := oauth2.Endpoint{AuthURL: base + prefix + "/authorize", TokenURL: base + prefix + "/token", AuthStyle: oauth2.AuthStyleInParams}
	p := signedProvider(id, secret, endpoint, verifier, client, idTokenRules{profile: func(token *oidc.IDToken) (auth.OAuthProfile, error) {
		var fields profileData
		if err := token.Claims(&fields); err != nil {
			return auth.OAuthProfile{}, err
		}
		return mapProfile(name, fields)
	}})
	p.AllowVerifiedEmailLink = true
	if name != "cognito" {
		p.VerifyIDToken = nil
	}
	switch name {
	case "paybin":
		p.Config.Scopes = []string{"openid", "email", "profile"}
	case "twitch":
		p.DisablePKCE = true
		p.Config.Scopes = []string{"user:read:email", "openid"}
		p.AuthorizationParams = url.Values{"claims": {`{"id_token":{"email":null,"email_verified":null,"preferred_username":null,"picture":null}}`}}
	case "cognito":
		if identityProvider != "" {
			p.AuthorizationParams = url.Values{"identity_provider": {identityProvider}}
		}
		p.CustomizeAuthorization = func(target *url.URL) { target.RawQuery = strings.ReplaceAll(target.RawQuery, "+", "%20") }
		resolve := p.Resolve
		p.Resolve = func(ctx context.Context, t *oauth2.Token, nonce string) (auth.OAuthProfile, error) {
			if raw, _ := t.Extra("id_token").(string); raw != "" {
				return resolve(ctx, t, nonce)
			}
			e := catalogEntry{Method: "GET", Profile: base + "/oauth2/userinfo"}
			return e.resolve(ctx, name, id, secret, t)
		}
	}
	return p
}

// Paybin installations publish their JWKS URI through issuer discovery.
type issuerKeys struct {
	uri    string
	issuer string
	mu     sync.Mutex
	keys   oidc.KeySet
}

func (k *issuerKeys) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	// A sign-in passes the provider's client, which follows no redirects;
	// without one, a client that also follows none is used.
	if client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client); client == nil {
		ctx = oidc.ClientContext(ctx, noRedirects(nil))
	}
	k.mu.Lock()
	keys := k.keys
	if keys == nil {
		uri := k.uri
		if uri == "" {
			provider, err := oidc.NewProvider(ctx, k.issuer)
			var doc struct {
				Keys string `json:"jwks_uri"`
			}
			if err == nil {
				err = provider.Claims(&doc)
			}
			if err != nil || !secureEndpoint(doc.Keys) {
				k.mu.Unlock()
				return nil, errors.New("could not discover issuer signing keys")
			}
			uri = doc.Keys
		}
		keys = oidc.NewRemoteKeySet(context.WithoutCancel(ctx), uri)
		k.keys = keys
	}
	k.mu.Unlock()
	return keys.VerifySignature(ctx, raw)
}
