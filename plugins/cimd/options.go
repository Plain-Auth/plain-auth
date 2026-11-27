package cimd

import (
	"context"
	"net/http"
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
}

func (o Options) transport() http.RoundTripper {
	if o.Transport == nil {
		return NewTransport()
	}
	return o.Transport
}
