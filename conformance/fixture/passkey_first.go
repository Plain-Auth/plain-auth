package main

import (
	auth "github.com/Plain-Org/plain-auth"
	pk "github.com/Plain-Org/plain-auth/plugins/passkey"
)

func fixturePasskeyFirst(base string) pk.Options {
	return pk.Options{RPID: "localhost", RPName: "Local registration", Origins: []string{base}, RequireUserVerification: true, Registration: pk.RegistrationOptions{
		AllowWithoutSession: true,
		ResolveUser: func(_ auth.EndpointContext, c *string) (pk.RegistrationUser, error) {
			if c == nil || *c != "local-enrollment" {
				return pk.RegistrationUser{}, &auth.APIError{Status: 403, Code: "FORBIDDEN", Message: "Unknown enrollment"}
			}
			return pk.RegistrationUser{ID: "candidate", Name: "candidate@example.test", DisplayName: "Local device"}, nil
		},
		AfterVerification: func(_ auth.EndpointContext, v pk.VerifiedRegistration) (pk.RegistrationDecision, error) {
			if v.Context == nil || *v.Context != "local-enrollment" {
				return pk.RegistrationDecision{}, nil
			}
			return pk.RegistrationDecision{UserID: "final-user", Name: "Local authenticator", NewAccount: &pk.RegistrationAccount{Email: "local@example.test", Name: "Local user"}}, nil
		},
	}}
}
