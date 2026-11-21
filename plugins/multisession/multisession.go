// Package multisession lets one browser remember and switch among signed-in accounts.
package multisession

import authn "github.com/Stonewrit/stonewrit-auth"

type Options = authn.MultiSessionOptions

func New(options Options) (authn.Plugin, error) { return authn.NewMultiSession(options) }
