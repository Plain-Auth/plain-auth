// Package username adds optional public usernames and credential sign-in.
package username

import "github.com/Stonewrit/stonewrit-auth"

type Options = stonewrit.UsernameOptions

func New(options Options) (stonewrit.Plugin, error) { return stonewrit.NewUsername(options) }
