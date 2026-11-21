// Package anonymous creates guest sessions and transfers application data on sign-in.
package anonymous

import authn "github.com/FineStack/frost-auth"

type Options = authn.AnonymousOptions
type Link = authn.AnonymousLink

func New(o Options) (authn.Plugin, error) { return authn.NewAnonymous(o) }
