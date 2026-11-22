package client

import (
	"context"
	"net/http"
	"net/url"

	"github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

// OAuthClient returns the registration details visible to its owner.
func (c *Client) OAuthClient(ctx context.Context, id string) (oauthprovider.ClientDetails, error) {
	var result oauthprovider.ClientDetails
	err := c.Do(ctx, http.MethodGet, "/oauth2/get-client?client_id="+url.QueryEscape(id), nil, &result)
	return result, err
}

// OAuthClients lists the registrations owned by the current account or active tenant.
func (c *Client) OAuthClients(ctx context.Context) ([]oauthprovider.ClientDetails, error) {
	var result []oauthprovider.ClientDetails
	err := c.Do(ctx, http.MethodGet, "/oauth2/get-clients", nil, &result)
	return result, err
}

// PublicOAuthClient returns display metadata for an enabled client to a signed-in user.
func (c *Client) PublicOAuthClient(ctx context.Context, id string) (oauthprovider.PublicClient, error) {
	var result oauthprovider.PublicClient
	err := c.Do(ctx, http.MethodGet, "/oauth2/public-client?client_id="+url.QueryEscape(id), nil, &result)
	return result, err
}

// RotateOAuthClientSecret replaces a shared credential and returns its new value once.
func (c *Client) RotateOAuthClientSecret(ctx context.Context, id string) (oauthprovider.RotatedClient, error) {
	var result oauthprovider.RotatedClient
	err := c.Do(ctx, http.MethodPost, "/oauth2/client/rotate-secret", map[string]string{"client_id": id}, &result)
	return result, err
}

// DeleteOAuthClient removes the owned registration and its stored grants and tokens.
func (c *Client) DeleteOAuthClient(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodPost, "/oauth2/delete-client", map[string]string{"client_id": id}, nil)
}
