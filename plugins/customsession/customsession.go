// Package customsession lets an application return its own authenticated session view.
package customsession

import (
	"errors"

	authn "github.com/Stonewrit/stonewrit-auth"
)

// Options controls which authenticated HTTP responses use the projection.
type Options struct{ ProjectDeviceSessions bool }

// New accepts a function that runs on authenticated HTTP session reads after
// normal validation and refresh. Return a JSON-encodable value.
func New(project func(authn.EndpointContext, authn.SessionResult) (any, error)) (authn.Plugin, error) {
	return NewWithOptions(project, Options{})
}

// NewWithOptions optionally projects each entry of the device session list.
func NewWithOptions(project authn.SessionResponseFunc, options Options) (authn.Plugin, error) {
	if project == nil {
		return authn.Plugin{}, errors.New("customsession: a response function is required")
	}
	return authn.Plugin{ID: "custom-session", SessionResponse: project, ProjectDeviceSessions: options.ProjectDeviceSessions}, nil
}
