// Package twofactor adds authenticator codes and single-use backup codes to credential sign-in.
package twofactor

import auth "github.com/FineStack/finestack-auth"

type Options = auth.TwoFactorOptions
type TOTPOptions = auth.FactorTOTPOptions
type BackupOptions = auth.FactorBackupOptions
type OTPOptions = auth.FactorOTPOptions
type LockoutOptions = auth.FactorLockoutOptions
type OTPMessage = auth.FactorOTPMessage

func New(opts Options) auth.Plugin { return auth.NewTwoFactor(opts) }
