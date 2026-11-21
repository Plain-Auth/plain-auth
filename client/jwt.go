package client

import (
	"context"
	"net/http"

	jose "github.com/go-jose/go-jose/v4"
)

// JWT requests a signed assertion using this client's session.
func (c *Client) JWT(ctx context.Context) (string, error) {
	var result struct {
		Token string `json:"token"`
	}
	err := c.Do(ctx, http.MethodGet, "/token", nil, &result)
	return result.Token, err
}

// JWKS reads public verification keys from the configured auth mount.
// Pass an empty path for the default endpoint.
func (c *Client) JWKS(ctx context.Context, path string) (*jose.JSONWebKeySet, error) {
	if path == "" {
		path = "/jwks"
	}
	var keys jose.JSONWebKeySet
	if err := c.Do(ctx, http.MethodGet, path, nil, &keys); err != nil {
		return nil, err
	}
	return &keys, nil
}
