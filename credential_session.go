package stonewrit

import (
	"context"
	"net/http"
	"time"
)

// CredentialSessionResolver authenticates an application credential for the
// request. Resolve must validate the credential before returning its principal.
type CredentialSessionResolver struct {
	Matches func(http.Header) bool
	Resolve func(context.Context, http.Header, RequestMeta, time.Duration) (*CredentialSession, error)
}
type CredentialSession struct {
	Identity SessionResult
	Allows   func(string, string) bool
	// Bind may attach a verified proof for transaction-level revalidation.
	Bind func(context.Context) context.Context
}
type credentialSessionKey struct{ host *Auth }
type credentialSessionAccess struct {
	allows func(string, string) bool
	bind   func(context.Context) context.Context
}

func (a *Auth) resolveCredentialSession(ctx context.Context, h http.Header, meta RequestMeta) (context.Context, *SessionResult, error) {
	for _, p := range a.opts.Plugins {
		resolver := p.CredentialSessions
		if resolver == nil || !resolver.Matches(h) {
			continue
		}
		if a.cookieToken(h) != "" {
			return ctx, nil, &APIError{400, "AMBIGUOUS_CREDENTIALS", "Supply one authentication credential"}
		}
		res, err := resolver.Resolve(ctx, h, meta, a.opts.SessionTTL)
		if err != nil {
			return ctx, nil, err
		}
		if res == nil || res.Identity.User.ID == "" || res.Identity.Session.UserID != res.Identity.User.ID {
			return ctx, nil, &APIError{401, "UNAUTHORIZED", "Invalid credential owner"}
		}
		if res.Bind != nil {
			ctx = res.Bind(ctx)
		}
		res.Identity.Session.CredentialType = "application"
		access := &credentialSessionAccess{allows: res.Allows, bind: res.Bind}
		res.Identity.Session.credentialAccess = access
		identity, err := a.withSessionPlugins(ctx, res.Identity.Session, res.Identity.User)
		if err != nil {
			return ctx, nil, err
		}
		identity.Session.CredentialType = "application"
		identity.Session.credentialAccess = access
		return context.WithValue(ctx, credentialSessionKey{a}, identity), identity, nil
	}
	return ctx, nil, nil
}

// HasPlugin reports whether a plugin with the given ID is installed.
func (a *Auth) HasPlugin(id string) bool {
	for _, p := range a.opts.Plugins {
		if p.ID == id {
			return true
		}
	}
	return false
}

// IsApplicationCredential identifies a per-request application-key session.
func (s Session) IsApplicationCredential() bool {
	return s.credentialAccess != nil || s.CredentialType == "application"
}

// AllowsCredentialAction reports whether this verified credential can exercise a
// specific application operation. Regular sessions use the route’s own authorization.
func (s Session) AllowsCredentialAction(resource, action string) bool {
	return !s.IsApplicationCredential() || s.credentialAccess != nil && s.credentialAccess.allows != nil && s.credentialAccess.allows(resource, action)
}
