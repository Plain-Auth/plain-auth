package client

import (
	"context"
	"net/http"

	authn "github.com/FineStack/frost-auth"
)

// ListDeviceSessions returns the accounts remembered by this client's cookie jar.
func (c *Client) ListDeviceSessions(ctx context.Context) ([]authn.SessionResult, error) {
	var out []authn.SessionResult
	err := c.Do(ctx, http.MethodGet, "/multi-session/list-device-sessions", nil, &out)
	return out, err
}

// SetActiveSession switches to a remembered account without creating a new login.
func (c *Client) SetActiveSession(ctx context.Context, token string) (*authn.SessionResult, error) {
	var out authn.SessionResult
	if err := c.Do(ctx, http.MethodPost, "/multi-session/set-active", map[string]string{"sessionToken": token}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RevokeDeviceSession removes a remembered login and activates another if needed.
func (c *Client) RevokeDeviceSession(ctx context.Context, token string) error {
	return c.Do(ctx, http.MethodPost, "/multi-session/revoke", map[string]string{"sessionToken": token}, nil)
}
