package cimd

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

// DiscoveryID is stored on every client a metadata document discovery
// saves.
const DiscoveryID = "cimd"

// NewClientDiscovery returns the client discovery for metadata documents,
// as another runtime's createCimdClientDiscovery does, for an OAuth
// provider extension:
//
//	oauthprovider.Extension{ClientDiscoveries: []oauthprovider.ClientDiscovery{discovery}}
//
// Each discovery owns its cache, validators and fetch budgets.
func NewClientDiscovery(opts Options) (oauthprovider.ClientDiscovery, error) {
	r, err := newResolver(opts)
	if err != nil {
		return oauthprovider.ClientDiscovery{}, err
	}
	return oauthprovider.ClientDiscovery{ID: DiscoveryID, Matches: IsClientIDURLCandidate, Resolve: r.resolve, Transport: r.opts.Transport,
		AllowCrossOriginJWKSURI: opts.AllowCrossOriginJWKSURI, Metadata: map[string]any{"client_id_metadata_document_supported": true}}, nil
}

// flight is one fetch that every concurrent resolution of a client joins.
type flight struct {
	done  chan struct{}
	doc   oauthprovider.ClientMetadataDocument
	entry *cacheEntry
	err   error
}

type resolver struct {
	opts     Options
	http     *http.Client
	governor *governor
	now      func() time.Time
	mu       sync.Mutex
	cache    *documentCache
	flights  map[string]*flight
}

func newResolver(opts Options) (*resolver, error) {
	switch {
	case opts.MaxCacheEntries < 0:
		return nil, errors.New("cimd: MaxCacheEntries must be a positive integer")
	case opts.MaxCacheEntries == 0:
		opts.MaxCacheEntries = 1000
	}
	if opts.MetadataRevalidationInterval == 0 {
		opts.MetadataRevalidationInterval = time.Hour
	}
	opts.Transport = opts.transport()
	governor, err := newGovernor(opts.FetchPolicy, opts.MaxCacheEntries)
	if err != nil {
		return nil, err
	}
	return &resolver{opts: opts, http: &http.Client{Transport: opts.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		governor: governor, now: time.Now, cache: newDocumentCache(opts.MaxCacheEntries), flights: map[string]*flight{}}, nil
}

// resolve answers a client discovery request. A fresh cached document the
// stored client already matches returns the stored client; another fresh
// one is stored; otherwise the request joins or starts the client's fetch,
// which every concurrent request shares, and stores the result with its own
// context, so no request waits for another's save.
func (r *resolver) resolve(ctx context.Context, req oauthprovider.DiscoveryRequest) (*oauthprovider.DiscoveredClient, error) {
	id := req.ClientID
	if !IsClientIDURLCandidate(id) {
		return nil, nil
	}
	logger := req.Auth.Logger()
	r.mu.Lock()
	entry := r.cache.get(id)
	if entry != nil && r.now().Before(entry.expires) {
		saved := entry.saved
		r.mu.Unlock()
		if req.Existing != nil && saved {
			return req.Existing, nil
		}
		return r.save(ctx, req, entry.doc, entry, logger)
	}
	r.mu.Unlock()
	if err := r.opts.checkURL(ctx, id); err != nil {
		return nil, err
	}
	r.mu.Lock()
	f := r.flights[id]
	if f == nil {
		release, err := r.governor.acquire(id, idOrigin(id), r.now())
		if err != nil {
			r.mu.Unlock()
			return nil, err
		}
		f = &flight{done: make(chan struct{})}
		r.flights[id] = f
		go r.fetch(context.WithoutCancel(ctx), id, f, r.cache.peek(id), release, logger)
	}
	r.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.done:
	}
	if f.err != nil {
		return nil, f.err
	}
	return r.save(ctx, req, f.doc, f.entry, logger)
}

// fetch runs one shared fetch, revalidating an expired entry with its
// validators, caches the document when its response allows, and settles the
// fetch budget.
func (r *resolver) fetch(ctx context.Context, id string, f *flight, expired *cacheEntry, release func(fetchOutcome, time.Time), logger *slog.Logger) {
	var etag, lastModified string
	if expired != nil {
		etag, lastModified = expired.headers.ETag, expired.headers.LastModified
	}
	got, err := r.opts.fetchDocument(ctx, r.http, id, etag, lastModified, logger)
	doc, headers := got.doc, got.headers
	// A 304 answers only the validators of the expired entry it revalidates,
	// which another runtime may have evicted meanwhile; here the fetch holds it.
	if err == nil && got.notModified {
		doc, headers = expired.doc, mergeHeaders(expired.headers, got.headers)
	}
	outcome := fetchSucceeded
	if kind, failed := failureKind(err); failed && kind == capacityFailure {
		outcome = fetchAtCapacity
	} else if err != nil {
		outcome = fetchFailed
	}
	now := r.now()
	release(outcome, now)
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.flights, id)
	f.doc, f.err = doc, err
	if err == nil {
		if cacheable, expires := freshness(headers, r.opts.MetadataRevalidationInterval, now); cacheable {
			f.entry = &cacheEntry{doc: doc, expires: expires, headers: headers}
			r.cache.put(id, f.entry)
		} else {
			r.cache.remove(id)
		}
	}
	close(f.done)
}

// save stores a document through the provider's registration rules and
// notifies the host. A failed save drops its entry and paces the client.
func (r *resolver) save(ctx context.Context, req oauthprovider.DiscoveryRequest, doc oauthprovider.ClientMetadataDocument, entry *cacheEntry, logger *slog.Logger) (*oauthprovider.DiscoveredClient, error) {
	result, err := req.Register(ctx, doc)
	r.mu.Lock()
	current := r.cache.peek(req.ClientID)
	if err != nil {
		if entry != nil && current == entry {
			r.cache.remove(req.ClientID)
		}
		r.mu.Unlock()
		r.governor.pace(req.ClientID, r.now())
		return nil, err
	}
	// Saves are not ordered across requests: a save of an older document
	// leaves the newer cached one to be saved again on its next hit.
	if entry != nil {
		entry.saved = true
	}
	if current != nil && current != entry {
		current.saved = false
	}
	r.mu.Unlock()
	switch {
	case result.Created && r.opts.OnClientCreated != nil:
		if err := r.opts.OnClientCreated(ctx, ClientCreatedEvent{Client: result.Client, Document: doc, Header: req.Header}); err != nil {
			logger.ErrorContext(ctx, "cimd onClientCreated notification failed", "error", err)
		}
	case !result.Created && req.Existing != nil && r.opts.OnClientRefreshed != nil:
		if err := r.opts.OnClientRefreshed(ctx, ClientRefreshedEvent{Client: result.Client, PreviousClient: *req.Existing, Document: doc, Header: req.Header}); err != nil {
			logger.ErrorContext(ctx, "cimd onClientRefreshed notification failed", "error", err)
		}
	}
	return &result.Client, nil
}

// idOrigin is a client ID URL's origin, which the fetch budgets share.
func idOrigin(id string) string {
	if u, err := url.Parse(id); err == nil {
		return origin(u)
	}
	return id
}
