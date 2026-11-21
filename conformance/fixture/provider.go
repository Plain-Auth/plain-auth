package main

import (
	"context"
	"errors"

	auth "github.com/nabuhadba/go-better-auth"
	"golang.org/x/oauth2"
)

// A fixed protocol double for the differential harness. It never sends traffic.
func fixtureSocialProvider() map[string]auth.OAuthProvider {
	return map[string]auth.OAuthProvider{"github": {
		Config: oauth2.Config{ClientID: "fixture-client", Endpoint: oauth2.Endpoint{AuthURL: "https://fixture.invalid/authorize", TokenURL: "https://fixture.invalid/token"}},
		Refresh: func(_ context.Context, _ oauth2.Config, raw string) (*oauth2.Token, error) {
			if raw != "stored-refresh" {
				return nil, errors.New("unexpected fixture refresh token")
			}
			return &oauth2.Token{AccessToken: "refreshed-access", RefreshToken: "rotated-refresh"}, nil
		},
		Resolve: func(_ context.Context, t *oauth2.Token, _ string) (auth.OAuthProfile, error) {
			if t.AccessToken != "refreshed-access" {
				return auth.OAuthProfile{}, errors.New("unexpected fixture access token")
			}
			return auth.OAuthProfile{Subject: "provider-person", Name: "Fixture", Email: "owner@example.org", EmailVerified: true, Data: map[string]any{"id": "provider-person"}}, nil
		},
	}}
}
