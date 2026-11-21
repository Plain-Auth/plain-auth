// Package jwt signs short-lived service assertions and publishes public verification keys.
package jwt

import auth "github.com/FineStack/finestack-auth"

type Options = auth.JWTOptions

func New(options Options) (auth.Plugin, error) { return auth.NewJWT(options) }
