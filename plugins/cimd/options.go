package cimd

import (
	"context"
	"net/http"
	"time"

	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

// Options configures client discovery from metadata documents, as another
// runtime's cimd options do.
type Options struct {
	// Transport fetches metadata documents and the resources their clients
	// publish, such as a jwks_uri. Nil uses NewTransport, which pins the
	// vetted addresses; another runtime needs the host to supply it.
	Transport http.RoundTripper
	// Profile applies a protocol profile, such as ProfileMCP20260728.
	Profile Profile
	// OriginBoundFields are the members whose URLs must share the client
	// ID's origin: nil means post_logout_redirect_uris and an empty, non-nil
	// list none.
	OriginBoundFields []string
	// AllowMetadataURL may refuse a client ID URL before it is fetched; false
	// refuses it with invalid_client and an error is returned as is. It runs
	// with the request's context, before any fetch budget is spent.
	AllowMetadataURL func(ctx context.Context, clientIDURL string) (bool, error)
	// MetadataRevalidationInterval caps how long a document is fresh and
	// stands in when its response gives no lifetime; 60 minutes by default.
	// A negative value revalidates on every resolution. Nothing refetches in
	// the background.
	MetadataRevalidationInterval time.Duration
	// FetchPolicy bounds fetches.
	FetchPolicy FetchPolicy
	// MaxCacheEntries bounds the cached documents and the fetch governor's
	// records; 1000 by default.
	MaxCacheEntries int
	// MetadataStaleIfError serves the stored client when refreshing its
	// document fails transiently, up to this long after it was last
	// validated and at most 24 hours; zero turns it off. It also keeps the
	// client's cached jwks_uri keys through transient failures.
	MetadataStaleIfError time.Duration
	// AllowCrossOriginJWKSURI lets a client's jwks_uri live off its client
	// ID's origin, as the provider's ClientDiscovery hook.
	AllowCrossOriginJWKSURI func(ctx context.Context, clientID, jwksURI string) (bool, error)
	// OnClientCreated and OnClientRefreshed run after a document is stored;
	// an error is logged and never undoes the save.
	OnClientCreated   func(context.Context, ClientCreatedEvent) error
	OnClientRefreshed func(context.Context, ClientRefreshedEvent) error
}

// ClientCreatedEvent is a client stored from its document for the first
// time.
type ClientCreatedEvent struct {
	Client   oauthprovider.DiscoveredClient
	Document oauthprovider.ClientMetadataDocument
	Header   http.Header
}

// ClientRefreshedEvent is a stored client replaced from a newer fetch of its
// document.
type ClientRefreshedEvent struct {
	Client, PreviousClient oauthprovider.DiscoveredClient
	Document               oauthprovider.ClientMetadataDocument
	Header                 http.Header
}

func (o Options) transport() http.RoundTripper {
	if o.Transport == nil {
		return NewTransport()
	}
	return o.Transport
}
