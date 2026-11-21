package client

import (
	"context"
	"net/http"

	auth "github.com/FineStack/finestack-auth"
)

// SendEmailOTP sends a purpose-bound code to the requested mailbox.
func (c *Client) SendEmailOTP(ctx context.Context, email string, purpose auth.EmailOTPPurpose) error {
	return c.Do(ctx, http.MethodPost, "/email-otp/send-verification-otp", map[string]string{"email": email, "type": string(purpose)}, nil)
}

// CheckEmailOTP checks a code without consuming a successful proof.
func (c *Client) CheckEmailOTP(ctx context.Context, email, otp string, purpose auth.EmailOTPPurpose) error {
	return c.Do(ctx, http.MethodPost, "/email-otp/check-verification-otp", map[string]string{"email": email, "otp": otp, "type": string(purpose)}, nil)
}
func (c *Client) VerifyEmailOTP(ctx context.Context, email, otp string) (*auth.User, error) {
	var result struct{ User auth.User }
	err := c.Do(ctx, http.MethodPost, "/email-otp/verify-email", map[string]string{"email": email, "otp": otp}, &result)
	if err != nil {
		return nil, err
	}
	return &result.User, nil
}
func (c *Client) SignInEmailOTP(ctx context.Context, in auth.EmailOTPSignInInput) (*auth.AuthResult, error) {
	var result auth.AuthResult
	if err := c.Do(ctx, http.MethodPost, "/sign-in/email-otp", in, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
func (c *Client) RequestPasswordResetEmailOTP(ctx context.Context, email string) error {
	return c.Do(ctx, http.MethodPost, "/email-otp/request-password-reset", map[string]string{"email": email}, nil)
}
func (c *Client) ResetPasswordEmailOTP(ctx context.Context, email, otp, password string) error {
	return c.Do(ctx, http.MethodPost, "/email-otp/reset-password", map[string]string{"email": email, "otp": otp, "password": password}, nil)
}

// RequestEmailChangeOTP sends a confirmation code to a new address. Supply the
// current mailbox's proof when required by the host.
func (c *Client) RequestEmailChangeOTP(ctx context.Context, newEmail, currentOTP string) error {
	body := map[string]string{"newEmail": newEmail}
	if currentOTP != "" {
		body["otp"] = currentOTP
	}
	return c.Do(ctx, http.MethodPost, "/email-otp/request-email-change", body, nil)
}
func (c *Client) ChangeEmailOTP(ctx context.Context, newEmail, otp string) error {
	return c.Do(ctx, http.MethodPost, "/email-otp/change-email", map[string]string{"newEmail": newEmail, "otp": otp}, nil)
}
