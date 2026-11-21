package client

import (
	"context"
	"net/http"

	auth "github.com/FineStack/finestack-auth"
)

// TOTPEnrollment contains the provisioning URI and the user's recovery codes.
// Both are credentials and should be presented privately.
type TOTPEnrollment struct {
	URI         string   `json:"totpURI"`
	BackupCodes []string `json:"backupCodes"`
}

func (c *Client) EnableTOTP(ctx context.Context, password, issuer string) (*TOTPEnrollment, error) {
	var result TOTPEnrollment
	if err := c.Do(ctx, http.MethodPost, "/two-factor/enable", map[string]string{"password": password, "issuer": issuer}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) TOTPURI(ctx context.Context, password string) (string, error) {
	var result TOTPEnrollment
	err := c.Do(ctx, http.MethodPost, "/two-factor/get-totp-uri", map[string]string{"password": password}, &result)
	return result.URI, err
}

func (c *Client) GenerateBackupCodes(ctx context.Context, password string) ([]string, error) {
	var result TOTPEnrollment
	err := c.Do(ctx, http.MethodPost, "/two-factor/generate-backup-codes", map[string]string{"password": password}, &result)
	return result.BackupCodes, err
}

// FactorResult identifies the verified user. Token is absent when a recovery
// code was verified with disableSession enabled.
type FactorResult struct {
	User  auth.User `json:"user"`
	Token *string   `json:"token"`
}

func (c *Client) VerifyTOTP(ctx context.Context, code string) (*FactorResult, error) {
	return c.VerifyTOTPWithTrust(ctx, code, false)
}

func (c *Client) VerifyBackupCode(ctx context.Context, code string, disableSession bool) (*FactorResult, error) {
	return c.VerifyBackupCodeWithTrust(ctx, code, disableSession, false)
}

func (c *Client) DisableTOTP(ctx context.Context, password string) error {
	return c.Do(ctx, http.MethodPost, "/two-factor/disable", map[string]string{"password": password}, nil)
}

// EnableDeliveredFactor enrolls the account for the host's out-of-band sender.
func (c *Client) EnableDeliveredFactor(ctx context.Context, password string) error {
	return c.Do(ctx, http.MethodPost, "/two-factor/enable", map[string]string{"password": password, "method": "otp"}, nil)
}
func (c *Client) SendFactorOTP(ctx context.Context) error {
	return c.Do(ctx, http.MethodPost, "/two-factor/send-otp", map[string]any{}, nil)
}

// VerifyFactorOTP consumes the delivered code for this browser's session or challenge.
func (c *Client) VerifyFactorOTP(ctx context.Context, code string, trustDevice bool) (*FactorResult, error) {
	return c.verifyFactor(ctx, "/two-factor/verify-otp", map[string]any{"code": code, "trustDevice": trustDevice})
}
func (c *Client) VerifyTOTPWithTrust(ctx context.Context, code string, trustDevice bool) (*FactorResult, error) {
	return c.verifyFactor(ctx, "/two-factor/verify-totp", map[string]any{"code": code, "trustDevice": trustDevice})
}
func (c *Client) VerifyBackupCodeWithTrust(ctx context.Context, code string, disableSession, trustDevice bool) (*FactorResult, error) {
	return c.verifyFactor(ctx, "/two-factor/verify-backup-code", map[string]any{"code": code, "disableSession": disableSession, "trustDevice": trustDevice})
}
func (c *Client) verifyFactor(ctx context.Context, path string, body map[string]any) (*FactorResult, error) {
	var result FactorResult
	if err := c.Do(ctx, http.MethodPost, path, body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
