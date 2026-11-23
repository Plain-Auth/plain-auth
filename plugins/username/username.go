// Package username adds optional public usernames and credential sign-in.
package username

import "github.com/Plain-Org/plain-auth"

type Options = plainauth.UsernameOptions

func New(options Options) (plainauth.Plugin, error) { return plainauth.NewUsername(options) }
