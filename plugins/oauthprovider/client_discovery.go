package oauthprovider

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/url"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/httporigin"
)

// ClientDiscovery resolves OAuth clients the provider has not registered,
// such as clients identified by a metadata document URL, as another
// runtime's client discoveries do. ID is stored on each client the discovery
// saves, so later lookups go back to it.
type ClientDiscovery struct {
	ID string
	// Matches reports whether the discovery handles a client ID.
	Matches func(clientID string) bool
	// Resolve returns the client behind an ID, registering its document
	// through req.Register, or nil when the discovery does not know it. The
	// provider reads the client from the store afterwards, so a resolved
	// client must be stored through req.Register.
	Resolve func(ctx context.Context, req DiscoveryRequest) (*DiscoveredClient, error)
	// AllowCrossOriginJWKSURI lets a client's jwks_uri live outside its
	// client ID's origin and the trusted origins. It runs outside any store
	// transaction; false or an error refuses the jwks_uri, and an error is
	// logged.
	AllowCrossOriginJWKSURI func(ctx context.Context, clientID, jwksURI string) (bool, error)
	// Metadata adds fields to the issuer's discovery documents, such as
	// client_id_metadata_document_supported. A later discovery's field wins
	// over an earlier one's; the provider's own fields always win.
	Metadata map[string]any
}

// DiscoveryRequest is what a client discovery resolves. Resolve receives the
// host and the request headers instead of an endpoint context, because
// server code also looks clients up outside a request.
type DiscoveryRequest struct {
	Auth     *auth.Auth
	Header   http.Header
	ClientID string
	// Existing is the stored row the discovery saved before, if any.
	Existing *DiscoveredClient
	// Register validates a document under the provider's registration rules
	// and stores it for the discovery.
	Register func(context.Context, ClientMetadataDocument) (ClientRegistrationResult, error)
}

// ClientRegistrationResult is a stored discovered client, the default
// resources linked to it, and whether the save created it. Document
// registration never issues a secret, so it carries none.
type ClientRegistrationResult struct {
	Client    DiscoveredClient
	Resources []string
	Created   bool
}

// registerMetadataDocument validates a client's metadata document for a
// discovery and stores it, as another runtime's
// registerClientMetadataDocument does. A document cannot name a back-channel
// logout target or a shared secret; it gets the registration scopes and the
// default resources, never its own, and no secret. The jwks_uri origin rule
// runs after the other checks, so the discovery's hook is asked only about
// an otherwise valid document.
func (opts Options) registerMetadataDocument(ctx context.Context, a *auth.Auth, store DiscoveredClientStore, d *ClientDiscovery, clientID string, existing *DiscoveredClient, doc ClientMetadataDocument) (ClientRegistrationResult, error) {
	if existing != nil && existing.DiscoveryID != d.ID {
		return ClientRegistrationResult{}, registrationProblem(400, "invalid_client", "client_id is already owned by a different registration source")
	}
	m := doc.RegistrationMetadata
	if m.BackchannelLogoutURI != nil || m.BackchannelLogoutSessionRequired != nil {
		return ClientRegistrationResult{}, metadataProblem("Client ID Metadata Documents cannot register a back-channel logout target")
	}
	if m.TokenEndpointAuthMethod == "" {
		m.TokenEndpointAuthMethod = "none"
	}
	if m.TokenEndpointAuthMethod != "none" && m.TokenEndpointAuthMethod != "private_key_jwt" {
		return ClientRegistrationResult{}, metadataProblem("Client ID Metadata Document clients cannot use a shared secret")
	}
	m.Resources = nil
	if err := opts.prepareMetadata(a, &m, metadataDocument); err != nil {
		return ClientRegistrationResult{}, err
	}
	if m.JWKSURI != nil && !a.ExplicitlyTrustedOrigin(*m.JWKSURI) && !sameOrigin(clientID, *m.JWKSURI) && !d.allowsJWKSURI(ctx, a, clientID, *m.JWKSURI) {
		return ClientRegistrationResult{}, jwksURIOriginProblem()
	}
	client, created, err := store.SaveDiscoveredClient(ctx, DiscoveredClientRecord{
		ID: rand.Text(), ClientID: clientID, DiscoveryID: d.ID, Metadata: m, Scopes: opts.Registration.AllowedScopes,
		Existing: existing, Now: time.Now().UTC().Truncate(time.Second),
	})
	if err != nil {
		return ClientRegistrationResult{}, err
	}
	return ClientRegistrationResult{Client: client, Resources: m.Resources, Created: created}, nil
}

// allowsJWKSURI asks the discovery's hook about a cross-origin jwks_uri.
func (d *ClientDiscovery) allowsJWKSURI(ctx context.Context, a *auth.Auth, clientID, jwksURI string) bool {
	if d.AllowCrossOriginJWKSURI == nil {
		return false
	}
	ok, err := d.AllowCrossOriginJWKSURI(ctx, clientID, jwksURI)
	if err != nil {
		a.Logger().ErrorContext(ctx, `oauth-provider: client discovery "`+d.ID+`" AllowCrossOriginJWKSURI failed`, "error", err)
		return false
	}
	return ok
}

// sameOrigin compares the origins of two HTTP URLs: scheme, lowercased host
// and port, with the default port dropped.
func sameOrigin(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	origin := httporigin.Canonical(ua)
	return origin != "" && origin == httporigin.Canonical(ub)
}
