// Package onetimetoken transfers an active login between clients using a short-lived credential.
package onetimetoken

import auth "github.com/Stonewrit/stonewrit-auth"

type Options = auth.OneTimeTokenOptions

func New(options Options) (auth.Plugin, error) { return auth.NewOneTimeToken(options) }
