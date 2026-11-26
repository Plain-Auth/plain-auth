package providers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// GitHub resolves the stable numeric user ID and verifies ownership of the
// chosen email address through GitHub's authenticated email API. A GitHub App
// needs the read-only "Email addresses" permission; without it only a public
// email, unverified, is available.
func GitHub(clientID, clientSecret string) authn.OAuthProvider {
	// The client secret goes in the form, so the single-use code is never
	// sent twice to find the authentication style.
	endpoint := endpoints.GitHub
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	return authn.OAuthProvider{
		Config:                 oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, Endpoint: endpoint, Scopes: []string{"read:user", "user:email"}},
		AllowVerifiedEmailLink: true, Resolve: githubProfile, OmitNonce: true,
	}
}

func githubProfile(ctx context.Context, t *oauth2.Token, _ string) (authn.OAuthProfile, error) {
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
		return authn.OAuthProfile{}, err
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return authn.OAuthProfile{}, err
	}
	if p.ID <= 0 {
		return authn.OAuthProfile{}, errors.New("missing GitHub subject")
	}
	// Without the email permission the list is refused; the public email,
	// if any, is then used unverified, and none answers email_not_found.
	if err := read("/user/emails", &emails); err != nil {
		emails = nil
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
	return authn.OAuthProfile{Data: data, Subject: strconv.FormatInt(p.ID, 10), Email: p.Email, EmailVerified: verified, Name: p.Name, Image: p.Avatar}, nil
}
