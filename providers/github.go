package providers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	betterauth "github.com/nabuhadba/go-better-auth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// GitHub resolves the stable numeric user ID and verifies ownership of the
// chosen email address through GitHub's authenticated email API.
func GitHub(clientID, clientSecret string) betterauth.OAuthProvider {
	return betterauth.OAuthProvider{
		Config:                 oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, Endpoint: endpoints.GitHub, Scopes: []string{"read:user", "user:email"}},
		AllowVerifiedEmailLink: true, Resolve: githubProfile,
	}
}

func githubProfile(ctx context.Context, t *oauth2.Token, _ string) (betterauth.OAuthProfile, error) {
	client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	var p struct {
		ID                 int64
		Email, Login, Name string
		Avatar             *string `json:"avatar_url"`
	}
	var emails []struct {
		Email             string
		Primary, Verified bool
	}
	read := func(path string, target any) error {
		req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com"+path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Authorization", "Bearer "+t.AccessToken)
		res, err := client.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return errors.New("GitHub profile request failed")
		}
		return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(target)
	}
	var data json.RawMessage
	if err := read("/user", &data); err != nil {
		return betterauth.OAuthProfile{}, err
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return betterauth.OAuthProfile{}, err
	}
	if p.ID <= 0 {
		return betterauth.OAuthProfile{}, errors.New("missing GitHub subject")
	}
	if err := read("/user/emails", &emails); err != nil && p.Email == "" {
		return betterauth.OAuthProfile{}, err
	}
	if p.Email == "" && len(emails) > 0 {
		p.Email = emails[0].Email
		for _, e := range emails {
			if e.Primary {
				p.Email = e.Email
				break
			}
		}
	}
	if p.Name == "" {
		p.Name = p.Login
	}
	verified := false
	for _, e := range emails {
		if e.Email == p.Email {
			verified = e.Verified
			break
		}
	}
	return betterauth.OAuthProfile{Data: data, Subject: strconv.FormatInt(p.ID, 10), Email: p.Email, EmailVerified: verified, Name: p.Name, Image: p.Avatar}, nil
}
