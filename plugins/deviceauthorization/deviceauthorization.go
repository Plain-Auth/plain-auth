// Package deviceauthorization adds RFC 8628 first-party device sign-in.
package deviceauthorization

import authn "github.com/Plain-Auth/plain-auth"

type Options = authn.DeviceAuthorizationOptions

func New(options Options) (authn.Plugin, error) { return authn.NewDeviceAuthorization(options) }
