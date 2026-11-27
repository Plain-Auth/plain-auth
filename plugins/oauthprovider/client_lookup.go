package oauthprovider

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// resolvedKey marks the clients a discovery resolved in a request. Only this
// package sets it, so host code cannot unhide a discovered client.
type resolvedKey struct{}

// ResolvedDiscovery returns the ID of the client discovery that resolved a
// client ID in this request, or "" when none did. A store serves a client
// row a discovery owns only to a request whose context names that
// discovery, so a store that ignores this never serves discovered clients.
func ResolvedDiscovery(ctx context.Context, clientID string) string {
	resolved, _ := ctx.Value(resolvedKey{}).(map[string]string)
	return resolved[clientID]
}

func withResolvedDiscovery(ctx context.Context, clientID, discoveryID string) context.Context {
	previous, _ := ctx.Value(resolvedKey{}).(map[string]string)
	next := maps.Clone(previous)
	if next == nil {
		next = map[string]string{}
	}
	next[clientID] = discoveryID
	return context.WithValue(ctx, resolvedKey{}, next)
}

// collectDiscoveries validates the extensions' client discoveries and keeps
// copies of them in order.
func (opts *Options) collectDiscoveries() error {
	seen := map[string]bool{}
	for _, extension := range opts.Extensions {
		for _, d := range extension.ClientDiscoveries {
			switch {
			case d.ID == "":
				return errors.New("oauthprovider: client discovery ID must not be empty")
			case seen[d.ID]:
				return fmt.Errorf("oauthprovider: client discovery %q is registered more than once", d.ID)
			case d.Matches == nil || d.Resolve == nil:
				return fmt.Errorf("oauthprovider: client discovery %q needs Matches and Resolve", d.ID)
			}
			seen[d.ID] = true
			d.Metadata = maps.Clone(d.Metadata)
			d.JWKSStaleIfError = min(max(d.JWKSStaleIfError, 0), 24*time.Hour)
			opts.discoveries = append(opts.discoveries, &d)
		}
	}
	return nil
}

// discoverClient resolves a client ID through the client discoveries, as
// another runtime's getClient does. No trusted-client snapshot precedes the
// store read, where another runtime caches cachedTrustedClients; Go names
// operator-managed clients in ImmutableClientIDs instead. A local row is used as is. A row a
// discovery owns goes back to that discovery, and stays hidden when it is
// no longer configured, no longer matches or resolves nothing. An unknown
// ID goes to each matching discovery in order. A resolved client is marked
// in the returned context for the store; a Resolve error is returned.
func (opts Options) discoverClient(ctx context.Context, a *auth.Auth, store any, header http.Header, clientID string) (context.Context, error) {
	// A client resolved earlier in the request is not resolved again.
	if clientID == "" || ResolvedDiscovery(ctx, clientID) != "" || !slices.ContainsFunc(opts.discoveries, func(d *ClientDiscovery) bool { return d.Matches(clientID) }) {
		return ctx, nil
	}
	clients, ok := store.(DiscoveredClientStore)
	if !ok {
		return ctx, errors.New("oauthprovider: client discoveries require a DiscoveredClientStore")
	}
	row, err := clients.LookupDiscoveredClient(ctx, clientID)
	switch {
	case err == nil:
		// A local row has no discovery ID, which no discovery has.
		for _, d := range opts.discoveries {
			if d.ID == row.DiscoveryID && d.Matches(clientID) {
				next, _, err := opts.resolveClient(ctx, a, clients, header, d, clientID, &row)
				return next, err
			}
		}
		return ctx, nil
	case !errors.Is(err, ErrClientNotFound):
		return ctx, err
	}
	for _, d := range opts.discoveries {
		if !d.Matches(clientID) {
			continue
		}
		if next, resolved, err := opts.resolveClient(ctx, a, clients, header, d, clientID, nil); err != nil || resolved {
			return next, err
		}
	}
	return ctx, nil
}

func (opts Options) resolveClient(ctx context.Context, a *auth.Auth, store DiscoveredClientStore, header http.Header, d *ClientDiscovery, clientID string, existing *DiscoveredClient) (context.Context, bool, error) {
	client, err := d.Resolve(ctx, DiscoveryRequest{Auth: a, Header: header.Clone(), ClientID: clientID, Existing: existing,
		Register: func(ctx context.Context, doc ClientMetadataDocument) (ClientRegistrationResult, error) {
			return opts.registerMetadataDocument(ctx, a, store, d, clientID, existing, doc)
		}})
	if err != nil || client == nil {
		return ctx, false, err
	}
	return withResolvedDiscovery(ctx, clientID, d.ID), true, nil
}

// discoverRequestClient resolves a client ID named in an endpoint request
// and carries the result in the request's context.
func (opts Options) discoverRequestClient(c auth.EndpointContext, clientID string) (auth.EndpointContext, error) {
	ctx, err := opts.discoverClient(c.Request.Context(), c.Auth, c.Store(), c.Request.Header, clientID)
	if err != nil {
		return c, err
	}
	c.Request = c.Request.WithContext(ctx)
	return c, nil
}

// ErrFetchCapacity is wrapped by a discovery transport's refusal of a fetch
// at a local capacity limit, which says nothing about the resource or its
// host: cached keys keep answering such a refusal within five minutes of a
// transient failure.
var ErrFetchCapacity = errors.New("oauthprovider: fetch refused at a local capacity limit")

// UnresolvedClientError is a store's answer for a read that reached a
// client a discovery owns, through a token or a consent, that the request
// has not resolved. The provider resolves the client outside the store's
// transaction and repeats the read once; a client left unresolved is
// treated as missing, so the error matches ErrClientNotFound.
type UnresolvedClientError struct{ ClientID, DiscoveryID string }

func (e *UnresolvedClientError) Error() string {
	return "oauthprovider: client " + e.ClientID + " is owned by unresolved client discovery " + e.DiscoveryID
}

func (e *UnresolvedClientError) Is(target error) bool { return target == ErrClientNotFound }

func unresolvedClient(err error) bool {
	var unresolved *UnresolvedClientError
	return errors.As(err, &unresolved)
}

// retryResolved runs a store read and, when it reports an unresolved
// client, resolves that client and runs the read once more with the
// resolved context, which reports the client again unless its own
// discovery resolved it.
func (opts Options) retryResolved(c auth.EndpointContext, read func(context.Context) error) (auth.EndpointContext, error) {
	err := read(c.Request.Context())
	var unresolved *UnresolvedClientError
	if !errors.As(err, &unresolved) {
		return c, err
	}
	if c, err = opts.discoverRequestClient(c, unresolved.ClientID); err != nil {
		return c, err
	}
	return c, read(c.Request.Context())
}
