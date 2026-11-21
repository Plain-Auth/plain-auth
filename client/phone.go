package client

import (
	"context"
	"net/http"
)

// SendPhoneNumberOTP requests a verification code for the supplied number.
func (c *Client) SendPhoneNumberOTP(ctx context.Context, number string) error {
	return c.Do(ctx, http.MethodPost, "/phone-number/send-otp", map[string]string{"phoneNumber": number}, nil)
}
