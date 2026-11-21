package client

import (
	"context"
	"net/http"
	"net/url"

	auth "github.com/FineStack/frost-auth"
)

// MagicLinkRequest requests a sign-in link delivered to Email.
type MagicLinkRequest struct {
	Email              string         `json:"email"`
	Name               string         `json:"name,omitempty"`
	CallbackURL        string         `json:"callbackURL,omitempty"`
	NewUserCallbackURL string         `json:"newUserCallbackURL,omitempty"`
	ErrorCallbackURL   string         `json:"errorCallbackURL,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
}

// SignInMagicLink asks the server to deliver a sign-in link.
func (c *Client) SignInMagicLink(ctx context.Context, input MagicLinkRequest) error {
	return c.Do(ctx, http.MethodPost, "/sign-in/magic-link", input, nil)
}

type MagicLinkResult struct {
	auth.SessionResult
	Token string `json:"token"`
}

// VerifyMagicLink consumes the delivered token and authenticates this client's cookie jar.
func (c *Client) VerifyMagicLink(ctx context.Context, token string) (*MagicLinkResult, error) {
	var result MagicLinkResult
	if err := c.Do(ctx, http.MethodGet, "/magic-link/verify?"+url.Values{"token": {token}}.Encode(), nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
