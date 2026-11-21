package client

import (
	"context"
	auth "github.com/FineStack/frost-auth"
	"net/http"
)

// GenerateOneTimeToken requests a short-lived transfer credential for this client's session.
func (c *Client) GenerateOneTimeToken(ctx context.Context) (string, error) {
	var result struct {
		Token string `json:"token"`
	}
	err := c.Do(ctx, http.MethodGet, "/one-time-token/generate", nil, &result)
	return result.Token, err
}

// VerifyOneTimeToken consumes a transfer credential issued by another authenticated client.
func (c *Client) VerifyOneTimeToken(ctx context.Context, token string) (*auth.SessionResult, error) {
	var result auth.SessionResult
	if err := c.Do(ctx, http.MethodPost, "/one-time-token/verify", map[string]string{"token": token}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
