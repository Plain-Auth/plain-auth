package client

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/Plain-Org/plain-auth"
)

// SendPhoneNumberOTP requests a verification code for the supplied number.
func (c *Client) SendPhoneNumberOTP(ctx context.Context, number string) error {
	return c.Do(ctx, http.MethodPost, "/phone-number/send-otp", map[string]string{"phoneNumber": number}, nil)
}

type PhoneSignInRequest struct {
	PhoneNumber string `json:"phoneNumber"`
	Password    string `json:"password"`
	RememberMe  *bool  `json:"rememberMe,omitempty"`
}
type PhoneVerificationResult struct {
	EmailResult
	Status bool `json:"status"`
}

func (c *Client) VerifyPhoneNumber(ctx context.Context, input plainauth.PhoneVerificationInput) (*PhoneVerificationResult, error) {
	var out PhoneVerificationResult
	if err := input.CheckProfileKeys(); err != nil {
		return nil, err
	}
	body, err := marshalProfileInput(input, input.AdditionalFields)
	if err != nil {
		return nil, err
	}
	if err := c.Do(ctx, http.MethodPost, "/phone-number/verify", json.RawMessage(body), &out); err != nil {
		return nil, err
	}
	return &out, nil
}
func (c *Client) SignInPhoneNumber(ctx context.Context, input PhoneSignInRequest) (*EmailResult, error) {
	var out EmailResult
	if err := c.Do(ctx, http.MethodPost, "/sign-in/phone-number", input, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
func (c *Client) RequestPhonePasswordReset(ctx context.Context, number string) error {
	return c.Do(ctx, http.MethodPost, "/phone-number/request-password-reset", map[string]string{"phoneNumber": number}, nil)
}
func (c *Client) ResetPhonePassword(ctx context.Context, number, code, password string) error {
	return c.Do(ctx, http.MethodPost, "/phone-number/reset-password", map[string]string{"phoneNumber": number, "otp": code, "newPassword": password}, nil)
}
