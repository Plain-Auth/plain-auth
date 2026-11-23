package client

import (
	"context"
	"net/http"
	"net/url"
	"strings"

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

// DecideOAuthConsent submits the user's decision and returns the browser destination.
// Nil scopes approve the original request. An empty slice explicitly grants no scopes.
func (c *Client) DecideOAuthConsent(ctx context.Context, signedQuery string, accept bool, scopes []string) (string, error) {
	body := map[string]any{"oauth_query": signedQuery, "accept": accept}
	if scopes != nil {
		body["scope"] = strings.Join(scopes, " ")
	}
	var result struct {
		URL string `json:"url"`
	}
	err := c.Do(ctx, http.MethodPost, "/oauth2/consent", body, &result)
	return result.URL, err
}

// ContinueOAuthSignup tells the issuer that the host's account-creation step is
// complete. The signed-in user's cookie jar carries the session on this request.
func (c *Client) ContinueOAuthSignup(ctx context.Context, signedQuery string) (string, error) {
	var result struct {
		URL string `json:"url"`
	}
	err := c.Do(ctx, http.MethodPost, "/oauth2/continue", map[string]any{"created": true, "oauth_query": signedQuery}, &result)
	return result.URL, err
}
