package client

import (
	"context"
	"net/http"

	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

// RegisterOAuthClient registers an application on the configured auth mount.
// Use a signed-in client, WithBearerToken for an initial token, or a fresh client for open registration.
func (c *Client) RegisterOAuthClient(ctx context.Context, metadata oauthprovider.RegistrationMetadata) (oauthprovider.RegisteredClient, error) {
	var result oauthprovider.RegisteredClient
	err := c.Do(ctx, http.MethodPost, "/oauth2/register", metadata, &result)
	return result, err
}
