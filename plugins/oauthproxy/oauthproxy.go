// Package oauthproxy exchanges social sign-in codes at a registered production
// callback and completes the browser session on its originating preview.
package oauthproxy

import auth "github.com/Plain-Auth/plain-auth"

type Options = auth.OAuthProxyOptions

func New(options Options) (auth.Plugin, error) { return auth.NewOAuthProxy(options) }
