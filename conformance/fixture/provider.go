package main

import (
	"context"
	"errors"
	"net/url"
	"os"

	auth "github.com/Stonewrit/stonewrit-auth"
	"golang.org/x/oauth2"
)

// A fixed protocol double for the differential harness. It never sends traffic.
func fixtureSocialProvider() map[string]auth.OAuthProvider {
	if os.Getenv("CONFORMANCE_EXPLICIT_SIGNUP") == "1" {
		return map[string]auth.OAuthProvider{"work": {
			Config:                oauth2.Config{ClientID: "fixture-client", Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token"}},
			DisableImplicitSignUp: true,
			ExchangeCode: func(context.Context, oauth2.Config, string, string, url.Values) (*oauth2.Token, error) {
				return &oauth2.Token{AccessToken: "local-test"}, nil
			},
			Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) {
				return auth.OAuthProfile{Subject: "sample-user", Email: "jo@example.org", Name: "Jo", EmailVerified: true}, nil
			},
		}}
	}
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
