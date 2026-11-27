package mcp

import (
	"errors"
	"net/http"
	"net/url"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

// AuthOptions configures RequireAuth. Every field is optional.
type AuthOptions struct {
	// Resource is the MCP resource URL. It defaults to the auth instance's
	// public URL, as another runtime's requireMcpAuth defaults to its base
	// URL; tokens issued for an MCP resource name that resource instead, so
	// pass the one mcp.New names.
	Resource string
	// Issuer defaults to the issuer the instance signs with.
	Issuer string
	// JWKSURL fetches the keys over HTTP. Without it they are read in
	// process, or from the jwt plugin's RemoteJWKSURL.
	JWKSURL string
	// RequiredScopes, ChallengeScopes and ScopeSatisfied are as for
	// NewProtectedHandler.
	RequiredScopes, ChallengeScopes []string
	ScopeSatisfied                  func(required string, granted map[string]bool) bool
	// DPoP's replay store defaults to store when it can hold proofs, so a
	// proof is spent once across instances.
	DPoP oauthprovider.DPoPOptions
	// OnError defaults to logging through the instance and answering 500.
	OnError func(http.ResponseWriter, *http.Request, error)
	// Transport fetches keys over HTTP.
	Transport http.RoundTripper
}

// RequireAuth protects an MCP route with the local auth instance's tokens,
// as another runtime's requireMcpAuth does: tokens must name the resource,
// come from the instance's issuer and carry azp, so a session JWT signed
// with the same keys fails. The store is passed for the replay default,
// since the instance does not expose its own. The issuer defaults to the
// one the instance signs with, where another runtime uses its base URL, so
// a custom JWT issuer needs no override; and an instance without a public
// URL fails here rather than on each request.
func RequireAuth(a *auth.Auth, store auth.Store, next http.Handler, opts AuthOptions) (http.Handler, error) {
	if a == nil {
		return nil, errors.New("mcp: RequireAuth needs an auth instance")
	}
	resource := opts.Resource
	if resource == "" {
		// Without a base URL, such as with a dynamic one, the public URL is
		// only the base path.
		resource = a.PublicURL()
		if u, err := url.Parse(resource); err != nil || u.Host == "" {
			return nil, errors.New("mcp: RequireAuth needs a public URL; for dynamic base URLs use NewProtectedHandler with explicit options")
		}
	}
	dpop := opts.DPoP
	if shared, ok := store.(oauthprovider.DPoPReplayStore); ok && dpop.ReplayStore == nil {
		dpop.ReplayStore = shared
	}
	onError := opts.OnError
	if onError == nil {
		onError = func(w http.ResponseWriter, r *http.Request, err error) {
			a.Logger().ErrorContext(r.Context(), "MCP access token verification failed", "error", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}
	return NewProtectedHandler(ProtectedHandlerOptions{
		AccessTokenVerifierOptions: oauthprovider.AccessTokenVerifierOptions{
			Auth: a, Issuer: opts.Issuer, Audience: []string{resource}, JWKSURL: opts.JWKSURL, RequiredClaims: []string{"azp"},
			ScopeSatisfied: opts.ScopeSatisfied, DPoP: dpop, Transport: opts.Transport,
		},
		RequiredScopes: opts.RequiredScopes, ChallengeScopes: opts.ChallengeScopes, OnError: onError,
	}, next)
}
