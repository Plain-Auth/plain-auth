package stonewrit

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestDeliveredFactorStorageModes(t *testing.T) {
	hash := func(_ context.Context, s string) (string, error) {
		v := sha256.Sum256([]byte("fixture" + s))
		return hex.EncodeToString(v[:]), nil
	}
	encode := func(_ context.Context, s string) (string, error) {
		return base64.StdEncoding.EncodeToString([]byte(s)), nil
	}
	decode := func(_ context.Context, s string) (string, error) {
		v, e := base64.StdEncoding.DecodeString(s)
		return string(v), e
	}
	for _, item := range []struct {
		name string
		opts FactorOTPOptions
	}{
		{"plain", FactorOTPOptions{}}, {"encrypted", FactorOTPOptions{Store: "encrypted"}}, {"hashed", FactorOTPOptions{Store: "hashed"}}, {"custom hash", FactorOTPOptions{Hash: hash}}, {"custom cipher", FactorOTPOptions{Encrypt: encode, Decrypt: decode}},
	} {
		t.Run(item.name, func(t *testing.T) {
			o := TwoFactorOptions{OTP: item.opts}
			o.OTP.Send = func(context.Context, FactorOTPMessage) error { return nil }
			if err := o.setDefaults(); err != nil {
				t.Fatal(err)
			}
			a := &Auth{opts: Options{Secret: strings.Repeat("x", 32)}, factorOptions: &o}
			at := time.Now()
			op := factorRequest{auth: a, ctx: t.Context(), subject: FactorSubject{Now: at}}
			state := FactorState{Enabled: true, User: User{ID: "owner"}, Record: &FactorRecord{Verified: true}}
			ch, err := op.sendOTP(state)
			if err != nil {
				t.Fatal(err)
			}
			record := ch.SaveDelivery
			if !record.Pending || record.ID == "" || record.CreatedAt != at || record.ExpiresAt.Sub(at) != 3*time.Minute {
				t.Fatal("delivery not staged with configured lifetime")
			}
			code := op.mail.Code
			switch item.name {
			case "plain":
				if record.Stored != code {
					t.Fatal("plain storage differs")
				}
			case "encrypted":
				if !strings.HasPrefix(record.Stored, recordPrefix) {
					t.Fatal("unprotected factor code")
				}
			case "hashed":
				if record.Stored != hashEmailOTP(code) {
					t.Fatal("unexpected canonical digest")
				}
			case "custom hash":
				want, _ := hash(t.Context(), code)
				if record.Stored != want {
					t.Fatal("custom hash was ignored")
				}
			case "custom cipher":
				want, _ := encode(t.Context(), code)
				if record.Stored != want {
					t.Fatal("custom cipher was ignored")
				}
			}
			record.Pending = false
			state.Delivery = record
			var used FactorChange
			if valid, err := op.checkDelivery(state, code, &used); err != nil || !valid || !used.RemoveDelivery {
				t.Fatal("configured storage failed a valid proof", err)
			}
		})
	}
}
func TestFactorSettingsRejectInvalidCombinations(t *testing.T) {
	for _, o := range []TwoFactorOptions{{TOTP: FactorTOTPOptions{Digits: 7}}, {TOTP: FactorTOTPOptions{Period: 1500 * time.Millisecond}}, {OTP: FactorOTPOptions{Encrypt: func(context.Context, string) (string, error) { return "", nil }}}, {Backup: FactorBackupOptions{Amount: 63, Length: 1}}, {Lockout: FactorLockoutOptions{Duration: -time.Hour}}} {
		if err := o.setDefaults(); err == nil {
			t.Fatal("invalid factor configuration accepted")
		}
	}
}
