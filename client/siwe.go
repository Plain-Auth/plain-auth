package client

import (
	"context"
	"net/http"

	"github.com/Plain-Org/plain-auth/plugins/siwe"
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
	return c.verifyWallet(ctx, map[string]string{"message": message, "signature": signature})
}

// VerifySIWEWithEmail supplies an unverified contact address alongside a signed wallet proof.
func (c *Client) VerifySIWEWithEmail(ctx context.Context, message, signature, email string) (*siwe.Result, error) {
	return c.verifyWallet(ctx, map[string]string{"message": message, "signature": signature, "email": email})
}

func (c *Client) verifyWallet(ctx context.Context, body map[string]string) (*siwe.Result, error) {
	var result siwe.Result
	if err := c.Do(ctx, http.MethodPost, "/siwe/verify", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
