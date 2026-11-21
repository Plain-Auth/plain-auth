package client

import (
	"context"
	"net/http"

	authn "github.com/Stonewrit/stonewrit-auth"
)

// ListDeviceSessions returns the accounts remembered by this client's cookie jar.
func (c *Client) ListDeviceSessions(ctx context.Context) ([]authn.SessionResult, error) {
	return ListDeviceSessionViews[authn.SessionResult](ctx, c)
}

// ListDeviceSessionViews decodes each remembered account into T. With
// per-device projection disabled, T should describe the standard session.
func ListDeviceSessionViews[T any](ctx context.Context, c *Client) ([]T, error) {
	var views []T
	if err := c.Do(ctx, http.MethodGet, "/multi-session/list-device-sessions", nil, &views); err != nil {
		return nil, err
	}
	return views, nil
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
