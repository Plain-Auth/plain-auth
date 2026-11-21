package stonewrit

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"strings"
)

// ImportTOTP enrolls an existing account with an externally provisioned SHA-1
// authenticator secret. The caller must authorize the import and obtain the
// seed through a trusted channel. An existing or pending factor is preserved.
func (a *Auth) ImportTOTP(ctx context.Context, userID, base32Secret string) error {
	if a.factorStore == nil || a.factorOptions.TOTP.Disabled {
		return &APIError{400, "TOTP_NOT_CONFIGURED", "TOTP is not available"}
	}
	if userID == "" {
		return ErrNotFound
	}
	raw, err := importedTOTPSecret(base32Secret)
	if err != nil {
		return err
	}
	return a.factorStore.WithTwoFactor(ctx, FactorSubject{UserID: userID, Now: a.now()}, func(st FactorState) (FactorChange, error) {
		if st.User.ID != userID {
			return FactorChange{}, ErrNotFound
		}
		if st.Enabled || st.Record != nil {
			return FactorChange{}, &APIError{409, "TWO_FACTOR_ALREADY_CONFIGURED", "The account already has a two-factor enrollment"}
		}
		secret, err := a.sealRecord("totp", raw)
		if err != nil {
			return FactorChange{}, err
		}
		backup, err := a.storeBackupCodes(ctx, []string{})
		if err != nil {
			return FactorChange{}, err
		}
		enabled := true
		record := FactorRecord{ID: rand.Text(), Secret: secret, BackupCodes: backup, Verified: true}
		return FactorChange{SaveRecord: &record, Enabled: &enabled, RevokeSessions: true}, nil
	})
}

func importedTOTPSecret(input string) ([]byte, error) {
	invalid := &APIError{400, "INVALID_TOTP_SECRET", "Expected a Base32 authenticator secret"}
	for i := range len(input) {
		if input[i] >= 128 {
			return nil, invalid
		}
	}
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	if strings.HasSuffix(input, "=") {
		encoding = base32.StdEncoding
	}
	upper := strings.ToUpper(input)
	raw, err := encoding.DecodeString(upper)
	// Re-encoding also rejects whitespace, bad padding and unused trailing bits.
	if err != nil || len(raw) == 0 || encoding.EncodeToString(raw) != upper {
		return nil, invalid
	}
	return raw, nil
}
