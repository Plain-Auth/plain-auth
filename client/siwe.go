package client

import (
	"context"
	"net/http"

	"github.com/Plain-Auth/plain-auth/plugins/siwe"
)

// SIWENonce issues a 15-minute EIP-4361 challenge before the wallet is known.
func (c *Client) SIWENonce(ctx context.Context) (string, error) {
	var out struct {
		Nonce string `json:"nonce"`
	}
	err := c.Do(ctx, http.MethodPost, "/siwe/nonce", map[string]any{}, &out)
	return out.Nonce, err
}

// VerifySIWE submits the exact bytes authorized by the wallet and records the session cookie.
func (c *Client) VerifySIWE(ctx context.Context, message, signature string) (*siwe.Result, error) {
	var result siwe.Result
	if err := c.Do(ctx, http.MethodPost, "/siwe/verify", map[string]string{"message": message, "signature": signature}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
