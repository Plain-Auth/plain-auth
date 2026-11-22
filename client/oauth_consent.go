package client

import (
	"context"
	"net/http"
	"net/url"

	"github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

// OAuthConsent reads one consent belonging to the signed-in user.
func (c *Client) OAuthConsent(ctx context.Context, id string) (oauthprovider.Consent, error) {
	var consent oauthprovider.Consent
	err := c.Do(ctx, http.MethodGet, "/oauth2/get-consent?id="+url.QueryEscape(id), nil, &consent)
	return consent, err
}

// OAuthConsents lists the signed-in user's grants.
func (c *Client) OAuthConsents(ctx context.Context) ([]oauthprovider.Consent, error) {
	var consents []oauthprovider.Consent
	err := c.Do(ctx, http.MethodGet, "/oauth2/get-consents", nil, &consents)
	return consents, err
}

// UpdateOAuthConsent replaces the consent's scopes. A nil or empty list clears them.
func (c *Client) UpdateOAuthConsent(ctx context.Context, id string, scopes []string) (oauthprovider.Consent, error) {
	if scopes == nil {
		scopes = []string{}
	}
	var consent oauthprovider.Consent
	err := c.Do(ctx, http.MethodPost, "/oauth2/update-consent", map[string]any{"id": id, "update": map[string]any{"scopes": scopes}}, &consent)
	return consent, err
}

// DeleteOAuthConsent removes a grant from the user's authorized applications.
func (c *Client) DeleteOAuthConsent(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodPost, "/oauth2/delete-consent", map[string]string{"id": id}, nil)
}
