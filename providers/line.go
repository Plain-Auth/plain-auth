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
func LINE(channelID, secret string) auth.OAuthProvider {
	return auth.OAuthProvider{
		Config: oauth2.Config{
			ClientID: channelID, ClientSecret: secret, Scopes: []string{"openid", "profile", "email"},
			Endpoint: oauth2.Endpoint{AuthURL: lineIssuer + "/oauth2/v2.1/authorize", TokenURL: lineAPI + "/token", AuthStyle: oauth2.AuthStyleInParams},
		},
		Resolve: func(ctx context.Context, t *oauth2.Token, nonce string) (auth.OAuthProfile, error) {
			var empty auth.OAuthProfile
			if t == nil {
				return empty, errors.New("LINE token response is empty")
			}
			raw, _ := t.Extra("id_token").(string)
			var req *http.Request
			var err error
			if raw != "" {
				if nonce == "" {
					return empty, errors.New("missing LINE sign-in nonce")
				}
				form := url.Values{"client_id": {channelID}, "id_token": {raw}, "nonce": {nonce}}
				req, err = http.NewRequestWithContext(ctx, http.MethodPost, lineAPI+"/verify", strings.NewReader(form.Encode()))
				if err == nil {
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
			} else {
				if t.AccessToken == "" {
					return empty, errors.New("missing LINE access token")
				}
				req, err = http.NewRequestWithContext(ctx, http.MethodGet, lineAPI+"/userinfo", nil)
				if err == nil {
					req.Header.Set("Authorization", "Bearer "+t.AccessToken)
				}
			}
			if err != nil {
				return empty, err
			}
			req.Header.Set("Accept", "application/json")
			client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
			if client == nil {
				client = &http.Client{Timeout: 15 * time.Second}
			}
			// Both endpoints are fixed. Keep tokens at the LINE endpoint that received them.
			verifyClient := *client
			verifyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			claims, err := providerJSON(&verifyClient, req)
			if err != nil {
				return empty, err
			}
			if raw != "" {
				now := time.Now().Unix()
				exp, errExp := strconv.ParseInt(claims.text("exp"), 10, 64)
				iat, errIat := strconv.ParseInt(claims.text("iat"), 10, 64)
				if claims.text("iss") != lineIssuer || claims.text("aud") != channelID || claims.text("nonce") != nonce || errExp != nil || errIat != nil || exp <= now || iat <= 0 || iat >= exp || iat > now+60 {
					return empty, errors.New("LINE ID token claims do not match this sign-in")
				}
			}
			result := auth.OAuthProfile{Subject: claims.text("sub"), Name: claims.text("name"), Email: claims.text("email")}
			if result.Subject == "" || result.Email == "" {
				return empty, errors.New("LINE profile is missing a subject or email")
			}
			data := map[string]any{"sub": result.Subject, "email": result.Email, "name": result.Name, "emailVerified": false}
			if image := claims.text("picture"); image != "" {
				result.Image = &image
				data["image"] = image
			}
			result.Data = data
			return result, nil
		},
	}
}
