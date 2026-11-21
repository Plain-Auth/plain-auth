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
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	betterauth "github.com/nabuhadba/go-better-auth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// Google configures OpenID Connect sign-in with Google's OAuth endpoints and
// rotating signing keys. Identity is read only from a verified ID token.
func Google(clientID, clientSecret string) betterauth.OAuthProvider {
	client := &http.Client{Timeout: 15 * time.Second}
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), "https://www.googleapis.com/oauth2/v3/certs")
	return google(clientID, clientSecret, keys, client)
}

func google(id, secret string, keys oidc.KeySet, client *http.Client) betterauth.OAuthProvider {
	verifier := oidc.NewVerifier("https://accounts.google.com", keys, &oidc.Config{ClientID: id, SupportedSigningAlgs: []string{"RS256"}})
	p := oidcProvider(id, secret, endpoints.Google, verifier, client)
	p.AllowVerifiedEmailLink = true
	return p
}

type idTokenRules struct {
	allowHashedNonce bool
	profile          func(*oidc.IDToken) (betterauth.OAuthProfile, error)
}

func oidcProvider(id, secret string, endpoint oauth2.Endpoint, verifier *oidc.IDTokenVerifier, client *http.Client) betterauth.OAuthProvider {
	return signedProvider(id, secret, endpoint, verifier, client, idTokenRules{profile: standardProfile})
}

type identityClaims struct {
	Name, Email     string
	Picture         *string
	Verified        json.RawMessage `json:"email_verified"`
	AuthorizedParty string          `json:"azp"`
}

func verifiedFlag(raw json.RawMessage) bool { return string(raw) == "true" || string(raw) == `"true"` }
func standardProfile(token *oidc.IDToken) (betterauth.OAuthProfile, error) {
	var c identityClaims
	if err := token.Claims(&c); err != nil {
		return betterauth.OAuthProfile{}, err
	}
	return betterauth.OAuthProfile{Subject: token.Subject, Name: c.Name, Email: c.Email, EmailVerified: verifiedFlag(c.Verified), Image: c.Picture}, nil
}

func signedProvider(id, secret string, endpoint oauth2.Endpoint, verifier *oidc.IDTokenVerifier, client *http.Client, rules idTokenRules) betterauth.OAuthProvider {
	resolve := func(ctx context.Context, raw, nonce, access string) (betterauth.OAuthProfile, time.Time, error) {
		var profile betterauth.OAuthProfile
		token, err := verifier.Verify(ctx, raw)
		if err != nil {
			return profile, time.Time{}, err
		}
		nonceOK := subtle.ConstantTimeCompare([]byte(token.Nonce), []byte(nonce)) == 1
		if !nonceOK && rules.allowHashedNonce {
			sum := sha256.Sum256([]byte(nonce))
			nonceOK = subtle.ConstantTimeCompare([]byte(token.Nonce), []byte(hex.EncodeToString(sum[:]))) == 1
		}
		if nonce == "" || !nonceOK {
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
		if (len(token.Audience) > 1 || claims.AuthorizedParty != "") && claims.AuthorizedParty != id {
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
	return betterauth.OAuthProvider{
		Config:     oauth2.Config{ClientID: id, ClientSecret: secret, Endpoint: endpoint, Scopes: []string{"openid", "profile", "email"}},
		HTTPClient: client,
		Resolve: func(ctx context.Context, t *oauth2.Token, nonce string) (betterauth.OAuthProfile, error) {
			raw, _ := t.Extra("id_token").(string)
			profile, _, err := resolve(ctx, raw, nonce, t.AccessToken)
			return profile, err
		},
		VerifyIDToken: func(ctx context.Context, raw, nonce string) (betterauth.OAuthProfile, time.Time, error) {
			return resolve(ctx, raw, nonce, "")
		},
	}
}
