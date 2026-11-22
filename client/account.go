// Account management through the mounted authentication API.
package client

import (
	"context"
	"net/http"
	"net/url"

	auth "github.com/Plain-Auth/plain-auth"
)

// UpdateUser sends only the supplied fields. ClearImage explicitly removes an image.
func (c *Client) UpdateUser(ctx context.Context, update auth.ProfileUpdate) error {
	input := map[string]any{}
	if update.ClearUsername {
		input["username"] = nil
	} else if update.Username != nil {
		input["username"] = *update.Username
	}
	if update.ClearDisplayUsername {
		input["displayUsername"] = nil
	} else if update.DisplayUsername != nil {
		input["displayUsername"] = *update.DisplayUsername
	}
	if update.Name != nil {
		input["name"] = *update.Name
	}
	if update.ClearImage {
		input["image"] = nil
	} else if update.Image != nil {
		input["image"] = *update.Image
	}
	return c.Do(ctx, http.MethodPost, "/update-user", input, nil)
}

func (c *Client) VerifyPassword(ctx context.Context, password string) error {
	return c.Do(ctx, http.MethodPost, "/verify-password", map[string]string{"password": password}, nil)
}

func (c *Client) ChangePassword(ctx context.Context, in auth.ChangePasswordInput) (*EmailResult, error) {
	input := map[string]any{"currentPassword": in.CurrentPassword, "newPassword": in.NewPassword, "revokeOtherSessions": in.RevokeOtherSessions}
	var result EmailResult
	if err := c.Do(ctx, http.MethodPost, "/change-password", input, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) RequestPasswordReset(ctx context.Context, email, redirectTo string) error {
	return c.Do(ctx, http.MethodPost, "/request-password-reset", map[string]string{"email": email, "redirectTo": redirectTo}, nil)
}

func (c *Client) ResetPassword(ctx context.Context, token, newPassword string) error {
	return c.Do(ctx, http.MethodPost, "/reset-password", map[string]string{"token": token, "newPassword": newPassword}, nil)
}

func (c *Client) SendVerificationEmail(ctx context.Context, email, callbackURL string) error {
	return c.Do(ctx, http.MethodPost, "/send-verification-email", map[string]string{"email": email, "callbackURL": callbackURL}, nil)
}

// VerifyEmail confirms the token without requesting a browser redirect.
func (c *Client) VerifyEmail(ctx context.Context, token string) error {
	return c.Do(ctx, http.MethodGet, "/verify-email?"+url.Values{"token": {token}}.Encode(), nil, nil)
}

func (c *Client) ChangeEmail(ctx context.Context, newEmail, callbackURL string) error {
	return c.Do(ctx, http.MethodPost, "/change-email", map[string]string{"newEmail": newEmail, "callbackURL": callbackURL}, nil)
}

func (c *Client) ListAccounts(ctx context.Context) ([]auth.LinkedAccount, error) {
	var accounts []auth.LinkedAccount
	err := c.Do(ctx, http.MethodGet, "/list-accounts", nil, &accounts)
	return accounts, err
}

func (c *Client) UnlinkAccount(ctx context.Context, accountID string) error {
	return c.Do(ctx, http.MethodPost, "/unlink-account", map[string]string{"accountId": accountID}, nil)
}

// DeleteAccountResult distinguishes a completed deletion from a pending email confirmation.
type DeleteAccountResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func (c *Client) DeleteAccount(ctx context.Context, in auth.DeleteUserInput) (*DeleteAccountResult, error) {
	payload := struct {
		Password    string `json:"password,omitempty"`
		Token       string `json:"token,omitempty"`
		CallbackURL string `json:"callbackURL,omitempty"`
	}{in.Password, in.Token, in.CallbackURL}
	var result DeleteAccountResult
	if err := c.Do(ctx, http.MethodPost, "/delete-user", payload, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
