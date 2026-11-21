package stonewrit

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// FactorTOTPOptions configures authenticator apps. Digits accepts 6 or 8.
// Period must be a whole number of seconds.
type FactorTOTPOptions struct {
	Digits            int
	Period            time.Duration
	Disabled          bool
	AllowPasswordless *bool
}
type FactorBackupOptions struct {
	Amount, Length    int
	Generate          func(context.Context) ([]string, error)
	Store             string
	Encrypt, Decrypt  EmailOTPTransform
	AllowPasswordless *bool
}
type FactorLockoutOptions struct {
	Disabled          bool
	MaxFailedAttempts int
	Duration          time.Duration
}
type FactorOTPMessage struct {
	User User
	Code string
}
type FactorOTPOptions struct {
	Send                    func(context.Context, FactorOTPMessage) error
	Period                  time.Duration
	Digits, AllowedAttempts int
	Store                   string
	Hash, Encrypt, Decrypt  EmailOTPTransform
}

func (o *TwoFactorOptions) setDefaults() error {
	if o.TOTP.Digits == 0 {
		o.TOTP.Digits = 6
	}
	if o.TOTP.Period == 0 {
		o.TOTP.Period = 30 * time.Second
	}
	if o.Backup.Amount == 0 {
		o.Backup.Amount = 10
	}
	if o.Backup.Length == 0 {
		o.Backup.Length = 10
	}
	if o.Lockout.MaxFailedAttempts == 0 {
		o.Lockout.MaxFailedAttempts = 10
	}
	if o.Lockout.Duration == 0 {
		o.Lockout.Duration = 15 * time.Minute
	}
	if o.OTP.Digits == 0 {
		o.OTP.Digits = 6
	}
	if o.OTP.Period == 0 {
		o.OTP.Period = 3 * time.Minute
	}
	if o.OTP.AllowedAttempts == 0 {
		o.OTP.AllowedAttempts = 5
	}
	if o.TOTP.Digits != 6 && o.TOTP.Digits != 8 || o.TOTP.Period < time.Second || o.TOTP.Period%time.Second != 0 || int64(o.TOTP.Period/time.Second) > 1<<32-1 {
		return errors.New("invalid authenticator digit count or period")
	}
	if o.Backup.Amount < 1 || o.Backup.Amount > 256 || o.Backup.Length < 1 || o.Backup.Length > 256 || (o.Backup.Generate == nil && o.Backup.Length == 1 && o.Backup.Amount > 62) {
		return errors.New("invalid backup code amount or length")
	}
	if o.Lockout.MaxFailedAttempts < 1 || o.Lockout.Duration < time.Second {
		return errors.New("invalid factor lockout policy")
	}
	if o.OTP.Digits < 1 || o.OTP.Digits > 128 || o.OTP.Period < time.Second || o.OTP.AllowedAttempts < 1 {
		return errors.New("invalid delivered factor code settings")
	}
	if o.Backup.Encrypt != nil || o.Backup.Decrypt != nil {
		if o.Backup.Encrypt == nil || o.Backup.Decrypt == nil || o.Backup.Store != "" {
			return errors.New("choose one backup code cipher")
		}
		o.Backup.Store = "custom"
	} else if o.Backup.Store == "" {
		o.Backup.Store = "encrypted"
	} else if o.Backup.Store != "plain" && o.Backup.Store != "encrypted" {
		return errors.New("invalid backup code storage mode")
	}
	if o.OTP.Hash != nil {
		if o.OTP.Store != "" || o.OTP.Encrypt != nil || o.OTP.Decrypt != nil {
			return errors.New("choose one delivered code storage strategy")
		}
		o.OTP.Store = "hashed"
	} else if o.OTP.Encrypt != nil || o.OTP.Decrypt != nil {
		if o.OTP.Encrypt == nil || o.OTP.Decrypt == nil || o.OTP.Store != "" {
			return errors.New("choose a paired delivered code cipher")
		}
		o.OTP.Store = "encrypted"
	} else if o.OTP.Store == "" {
		o.OTP.Store = "plain"
	} else if o.OTP.Store != "plain" && o.OTP.Store != "encrypted" && o.OTP.Store != "hashed" {
		return errors.New("invalid delivered code storage mode")
	}
	return nil
}
func (o FactorTOTPOptions) validate() totp.ValidateOpts {
	return totp.ValidateOpts{Period: uint(o.Period / time.Second), Digits: otp.Digits(o.Digits), Algorithm: otp.AlgorithmSHA1}
}
func (o FactorTOTPOptions) uri(issuer, email string, raw []byte) string {
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	q := url.Values{"secret": {encoded}, "issuer": {issuer}, "digits": {strconv.Itoa(o.Digits)}, "period": {strconv.FormatInt(int64(o.Period/time.Second), 10)}}
	return "otpauth://totp/" + url.PathEscape(issuer) + ":" + url.PathEscape(email) + "?" + q.Encode()
}
func (o FactorTOTPOptions) step(raw []byte, code string, now time.Time) (int64, bool, error) {
	if len(code) != o.Digits || strings.Trim(code, "0123456789") != "" {
		return 0, false, nil
	}
	key := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	for _, delta := range []time.Duration{0, -o.Period, o.Period} {
		at := now.Add(delta)
		valid, err := totp.ValidateCustom(code, key, at, o.validate())
		if valid || err != nil {
			return at.Unix() / int64(o.Period/time.Second), valid, err
		}
	}
	return 0, false, nil
}

// GenerateTOTP computes the current code for a raw provisioning secret in trusted application code.
func (a *Auth) GenerateTOTP(secret string) (string, error) {
	if a.factorOptions == nil || a.factorOptions.TOTP.Disabled {
		return "", &APIError{400, "TOTP_NOT_CONFIGURED", "TOTP is not available"}
	}
	key := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(secret))
	return totp.GenerateCodeCustom(key, a.now(), a.factorOptions.TOTP.validate())
}
func (o FactorBackupOptions) generate(ctx context.Context) ([]string, error) {
	if o.Generate != nil {
		items, err := o.Generate(ctx)
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			return nil, errors.New("no backup codes generated")
		}
		seen := map[string]bool{}
		for _, v := range items {
			if v == "" || seen[v] {
				return nil, errors.New("backup codes must be nonempty and distinct")
			}
			seen[v] = true
		}
		return items, nil
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	items := make([]string, 0, o.Amount)
	seen := map[string]bool{}
	for len(items) < o.Amount {
		buf := make([]byte, o.Length)
		for i := range buf {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
			if err != nil {
				return nil, err
			}
			buf[i] = alphabet[n.Int64()]
		}
		split := min(5, len(buf))
		code := string(buf[:split]) + "-" + string(buf[split:])
		if !seen[code] {
			seen[code] = true
			items = append(items, code)
		}
	}
	return items, nil
}
func (a *Auth) storeBackupCodes(ctx context.Context, codes []string) (string, error) {
	raw, err := json.Marshal(codes)
	if err != nil {
		return "", err
	}
	o := a.factorOptions.Backup
	switch o.Store {
	case "plain":
		return string(raw), nil
	case "custom":
		return o.Encrypt(ctx, string(raw))
	default:
		return a.sealRecord("backup-codes", raw)
	}
}
func (a *Auth) readBackupCodes(ctx context.Context, data string) ([]string, error) {
	o := a.factorOptions.Backup
	var err error
	switch o.Store {
	case "plain":
	case "custom":
		data, err = o.Decrypt(ctx, data)
	default:
		var raw []byte
		raw, err = a.openRecord("backup-codes", data)
		data = string(raw)
	}
	if err != nil {
		return nil, err
	}
	var codes []string
	err = json.Unmarshal([]byte(data), &codes)
	return codes, err
}

// ViewBackupCodes reads the remaining codes for a trusted, server-supplied user ID.
// Applications must authorize the administrator or owner before calling this method.
func (a *Auth) ViewBackupCodes(ctx context.Context, userID string) ([]string, error) {
	if a.factorStore == nil {
		return nil, &APIError{400, "BACKUP_CODES_NOT_ENABLED", "Backup codes are not enabled"}
	}
	var codes []string
	err := a.factorStore.WithTwoFactor(ctx, FactorSubject{UserID: userID, Now: a.now()}, func(st FactorState) (FactorChange, error) {
		if st.Record == nil || st.Record.BackupCodes == "" {
			return FactorChange{}, &APIError{400, "BACKUP_CODES_NOT_ENABLED", "Backup codes are not enabled"}
		}
		var err error
		codes, err = a.readBackupCodes(ctx, st.Record.BackupCodes)
		return FactorChange{}, err
	})
	return codes, err
}
