package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	auth "github.com/Plain-Auth/plain-auth"
	"golang.org/x/oauth2"
)

// The conformance IdP serves authorization, token and userinfo on loopback.
// Only the explicit mapped object supplies application fields.
func fixtureProfileProvider(issuer string) auth.OAuthProvider {
	return auth.OAuthProvider{
		Config: oauth2.Config{ClientID: "profile-app", ClientSecret: "local-secret", Scopes: []string{"profile"}, Endpoint: oauth2.Endpoint{AuthURL: issuer + "/authorize", TokenURL: issuer + "/token", AuthStyle: oauth2.AuthStyleInParams}},
		Resolve: func(ctx context.Context, token *oauth2.Token, _ string) (auth.OAuthProfile, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/userinfo", nil)
			if err != nil {
				return auth.OAuthProfile{}, err
			}
			token.SetAuthHeader(req)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return auth.OAuthProfile{}, err
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusOK {
				return auth.OAuthProfile{}, errors.New("profile fixture rejected access token")
			}
			var data map[string]any
			decoder := json.NewDecoder(res.Body)
			decoder.UseNumber()
			if err := decoder.Decode(&data); err != nil {
				return auth.OAuthProfile{}, err
			}
			subject, _ := data["id"].(string)
			name, _ := data["name"].(string)
			email, _ := data["email"].(string)
			verified, _ := data["emailVerified"].(bool)
			mapped, _ := data["mapped"].(map[string]any)
			profile := auth.OAuthProfile{Subject: subject, Name: name, Email: email, EmailVerified: verified, Data: data, AdditionalFields: mapped}
			if image, ok := data["picture"].(string); ok {
				profile.Image = &image
			}
			return profile, nil
		},
	}
}
