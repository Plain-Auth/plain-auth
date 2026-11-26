package providers

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"golang.org/x/oauth2"
)

const lineIssuer = "https://access.line.me"
const lineAPI = "https://api.line.me/oauth2/v2.1"

// LINE signs in through a LINE Login channel. Register each channel under its own
// SocialProviders key. Each key has its own callback URL and account namespace.
// A key also accepts that channel's ID tokens for direct sign-in.
func LINE(channelID, secret string) auth.OAuthProvider {
	return auth.OAuthProvider{
		Config: oauth2.Config{
			ClientID: channelID, ClientSecret: secret, Scopes: []string{"openid", "profile", "email"},
			Endpoint: oauth2.Endpoint{AuthURL: lineIssuer + "/oauth2/v2.1/authorize", TokenURL: lineAPI + "/token", AuthStyle: oauth2.AuthStyleInParams},
		},
		Resolve: func(ctx context.Context, t *oauth2.Token, nonce string) (auth.OAuthProfile, error) {
			if t == nil {
				return auth.OAuthProfile{}, errors.New("LINE token response is empty")
			}
			if raw, _ := t.Extra("id_token").(string); raw != "" {
				profile, _, err := lineIDToken(ctx, channelID, raw, nonce)
				return profile, err
			}
			if t.AccessToken == "" {
				return auth.OAuthProfile{}, errors.New("missing LINE access token")
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, lineAPI+"/userinfo", nil)
			if err != nil {
				return auth.OAuthProfile{}, err
			}
			req.Header.Set("Authorization", "Bearer "+t.AccessToken)
			req.Header.Set("Accept", "application/json")
			claims, err := providerJSON(lineClient(ctx), req)
			if err != nil {
				return auth.OAuthProfile{}, err
			}
			return lineProfile(claims)
		},
		VerifyIDToken: func(ctx context.Context, raw, nonce string) (auth.OAuthProfile, time.Time, error) {
			return lineIDToken(ctx, channelID, raw, nonce)
		},
	}
}

// lineClient is the request's client without redirects: both LINE
// endpoints are fixed, and tokens stay at the endpoint that received them.
func lineClient(ctx context.Context) *http.Client {
	client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	return noRedirects(client)
}

// lineIDToken checks an ID token at LINE's verify endpoint for channelID,
// which covers the HS256 tokens of web channels and the ES256 tokens of the
// SDKs, then checks the claims against this sign-in.
func lineIDToken(ctx context.Context, channelID, raw, nonce string) (auth.OAuthProfile, time.Time, error) {
	if raw == "" || nonce == "" {
		return auth.OAuthProfile{}, time.Time{}, errors.New("missing LINE ID token or nonce")
	}
	form := url.Values{"client_id": {channelID}, "id_token": {raw}, "nonce": {nonce}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, lineAPI+"/verify", strings.NewReader(form.Encode()))
	if err != nil {
		return auth.OAuthProfile{}, time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	claims, err := providerJSON(lineClient(ctx), req)
	if err != nil {
		return auth.OAuthProfile{}, time.Time{}, err
	}
	now := time.Now().Unix()
	exp, errExp := strconv.ParseInt(claims.text("exp"), 10, 64)
	iat, errIat := strconv.ParseInt(claims.text("iat"), 10, 64)
	// Like other ID tokens, one at most an hour old signs in.
	if claims.text("iss") != lineIssuer || claims.text("aud") != channelID || claims.text("nonce") != nonce || errExp != nil || errIat != nil ||
		exp <= now || iat <= 0 || iat >= exp || iat > now+60 || iat < now-3600 {
		return auth.OAuthProfile{}, time.Time{}, errors.New("LINE ID token claims do not match this sign-in")
	}
	profile, err := lineProfile(claims)
	return profile, time.Unix(exp, 0), err
}

// lineProfile maps LINE's claims. A profile without an email is returned
// without one, and the sign-in answers email_not_found.
func lineProfile(claims profileData) (auth.OAuthProfile, error) {
	result := auth.OAuthProfile{Subject: claims.text("sub"), Name: claims.text("name"), Email: claims.text("email")}
	if result.Subject == "" {
		return auth.OAuthProfile{}, errors.New("LINE profile is missing a subject")
	}
	data := map[string]any{"sub": result.Subject, "email": result.Email, "name": result.Name, "emailVerified": false}
	if image := claims.text("picture"); image != "" {
		result.Image = &image
		data["image"] = image
	}
	result.Data = data
	return result, nil
}
