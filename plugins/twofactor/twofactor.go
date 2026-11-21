// Package twofactor adds authenticator codes and single-use backup codes to credential sign-in.
package twofactor

import auth "github.com/FineStack/finestack-auth"

type Options = auth.TwoFactorOptions

func New(opts Options) auth.Plugin { return auth.NewTwoFactor(opts) }
