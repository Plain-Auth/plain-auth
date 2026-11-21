// Package emailotp adds single-use email verification, login and recovery codes.
package emailotp

import auth "github.com/FineStack/frost-auth"

type Options = auth.EmailOTPOptions
type Message = auth.EmailOTPMessage
type Purpose = auth.EmailOTPPurpose
type ChangeOptions = auth.EmailOTPChangeOptions
type Transform = auth.EmailOTPTransform

const (
	VerifyEmail   = auth.OTPVerifyEmail
	SignIn        = auth.OTPSignIn
	ResetPassword = auth.OTPResetPassword
	ChangeEmail   = auth.OTPChangeEmail
)

func New(options Options) (auth.Plugin, error) { return auth.NewEmailOTP(options) }
