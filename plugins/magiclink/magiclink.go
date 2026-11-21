// Package magiclink adds single-use mailbox sign-in links.
package magiclink

import auth "github.com/FineStack/finestack-auth"

type Options = auth.MagicLinkOptions
type Message = auth.MagicLinkMessage

func New(options Options) (auth.Plugin, error) { return auth.NewMagicLink(options) }
