package client

import (
	"context"
	"net/http"

	authn "github.com/Plain-Org/plain-auth"
)

func (c *Client) SignInAnonymous(ctx context.Context) (*authn.AuthResult, error) {
	var res authn.AuthResult
	if err := c.Do(ctx, http.MethodPost, "/sign-in/anonymous", nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
func (c *Client) DeleteAnonymousUser(ctx context.Context) error {
	return c.Do(ctx, http.MethodPost, "/delete-anonymous-user", nil, nil)
}
