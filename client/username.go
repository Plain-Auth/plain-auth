package client

import (
	"context"
	"net/http"
)

type UsernameSignInRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	RememberMe  *bool  `json:"rememberMe,omitempty"`
	CallbackURL string `json:"callbackURL,omitempty"`
}

func (c *Client) SignInUsername(ctx context.Context, request UsernameSignInRequest) (*EmailResult, error) {
	var result EmailResult
	if err := c.Do(ctx, http.MethodPost, "/sign-in/username", request, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) IsUsernameAvailable(ctx context.Context, name string) (bool, error) {
	var result struct {
		Available bool `json:"available"`
	}
	err := c.Do(ctx, http.MethodPost, "/is-username-available", map[string]string{"username": name}, &result)
	return result.Available, err
}
