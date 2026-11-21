// Package phonenumber provides SMS verification of phone numbers.
package phonenumber

import "github.com/Stonewrit/stonewrit-auth"

type Options = stonewrit.PhoneNumberOptions
type SignUpOptions = stonewrit.PhoneSignUpOptions
type Message = stonewrit.PhoneOTPMessage

func New(options Options) (stonewrit.Plugin, error) { return stonewrit.NewPhoneNumber(options) }
