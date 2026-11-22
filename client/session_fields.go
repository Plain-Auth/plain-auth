package client

import (
	"context"
	"net/http"

	auth "github.com/Plain-Auth/plain-auth"
)

// UpdateSession patches the current session's configured writable fields.
func (c *Client) UpdateSession(ctx context.Context, values map[string]any) (*auth.Session, error) {
	var result struct {
		Session auth.Session `json:"session"`
	}
	if err := c.Do(ctx, http.MethodPost, "/update-session", values, &result); err != nil {
		return nil, err
	}
	return &result.Session, nil
}
