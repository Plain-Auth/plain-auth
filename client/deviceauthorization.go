package client

import (
	"context"
	"net/http"
	"net/url"

	authn "github.com/Plain-Auth/plain-auth"
)

type DeviceCodeRequest struct {
	ClientID string `json:"client_id"`
	UserID   string `json:"user_id,omitempty"`
	Scope    string `json:"scope,omitempty"`
}
type DeviceCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}
type DeviceVerification struct {
	UserCode string `json:"user_code"`
	Status   string `json:"status"`
	ClientID string `json:"client_id,omitempty"`
	Scope    string `json:"scope,omitempty"`
}
type DeviceToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}

func (c *Client) RequestDeviceCode(ctx context.Context, in DeviceCodeRequest) (*DeviceCode, error) {
	var result DeviceCode
	if err := c.Do(ctx, http.MethodPost, "/device/code", in, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
func (c *Client) VerifyDeviceCode(ctx context.Context, code string) (*DeviceVerification, error) {
	var result DeviceVerification
	if err := c.Do(ctx, http.MethodGet, "/device?"+url.Values{"user_code": {code}}.Encode(), nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
func (c *Client) ApproveDeviceCode(ctx context.Context, code string) error {
	return c.Do(ctx, http.MethodPost, "/device/approve", map[string]string{"userCode": code}, nil)
}
func (c *Client) DenyDeviceCode(ctx context.Context, code string) error {
	return c.Do(ctx, http.MethodPost, "/device/deny", map[string]string{"userCode": code}, nil)
}

// PollDeviceToken makes one token request. On authorization_pending wait at
// least the interval before polling again. On slow_down increase the interval
// by five seconds for this and all following attempts.
func (c *Client) PollDeviceToken(ctx context.Context, clientID, deviceCode string) (*DeviceToken, error) {
	var result DeviceToken
	fields := map[string]string{"client_id": clientID, "device_code": deviceCode, "grant_type": authn.DeviceGrantType}
	if err := c.Do(ctx, http.MethodPost, "/device/token", fields, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
