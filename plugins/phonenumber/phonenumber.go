// Package phonenumber provides SMS verification of phone numbers.
package phonenumber

import "github.com/Plain-Auth/plain-auth"

type Options = plainauth.PhoneNumberOptions
type SignUpOptions = plainauth.PhoneSignUpOptions
type Message = plainauth.PhoneOTPMessage

func New(options Options) (plainauth.Plugin, error) { return plainauth.NewPhoneNumber(options) }
