package cimd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/publicnet"
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
		AllowCrossOriginJWKSURI: opts.AllowCrossOriginJWKSURI, JWKSStaleIfError: opts.MetadataStaleIfError,
		Metadata: map[string]any{"client_id_metadata_document_supported": true}}, nil
}

// flight is one fetch that every concurrent resolution of a client joins.
type flight struct {
	done  chan struct{}
	doc   oauthprovider.ClientMetadataDocument
	entry *cacheEntry
	err   error
	// waiters counts the requests sharing the fetch; stored reports one
	// whose stored client may stand in for a failure.
	waiters int
	stored  bool
}

type resolver struct {
	opts     Options
	http     *http.Client
	governor *governor
	now      func() time.Time
	mu       sync.Mutex
	cache    *documentCache
	flights  map[string]*flight
	// transients and terminals record the last failed refresh of a stored
	// client; evicting a terminal record moves the watermark, so clients
	// validated before it are not served stale.
	transients map[string]staleRecord
	terminals  map[string]time.Time
	watermark  time.Time
}

type staleRecord struct {
	at     time.Time
	reason string
}

const (
	// staleRefetch is how long the stored client answers after a transient
	// failure without a fetch.
	staleRefetch = time.Minute
	// staleRefusal is how recent a transient failure must be for the stored
	// client to answer when a fetch limit refuses the fetch.
	staleRefusal = 5 * time.Minute
)

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
	if opts.MetadataStaleIfError < 0 || opts.MetadataStaleIfError > 24*time.Hour {
		return nil, errors.New("cimd: MetadataStaleIfError must be between zero and 24 hours")
	}
	opts.Transport = opts.transport()
	governor, err := newGovernor(opts.FetchPolicy, opts.MaxCacheEntries)
	if err != nil {
		return nil, err
	}
	return &resolver{opts: opts, http: &http.Client{Transport: opts.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		governor: governor, now: time.Now, cache: newDocumentCache(opts.MaxCacheEntries), flights: map[string]*flight{},
		transients: map[string]staleRecord{}, terminals: map[string]time.Time{}}, nil
}

// resolve answers a client discovery request. A fresh cached document the
// stored client already matches returns the stored client; another fresh
// one is stored; otherwise, once the URL passes its check, the request
// joins or starts the client's fetch, which every concurrent request
// shares, and stores the result with its own context, so no request waits
// for another's save.
func (r *resolver) resolve(ctx context.Context, req oauthprovider.DiscoveryRequest) (*oauthprovider.DiscoveredClient, error) {
	id := req.ClientID
	if !IsClientIDURLCandidate(id) {
		return nil, nil
	}
	logger := req.Auth.Logger()
	// The cache is read before the URL check, which runs host code, and
	// again after it; joining a fetch shares the second lock with that
	// read, so a request never misses a fetch that settles meanwhile.
	for checked := false; ; checked = true {
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
		// After a transient failure the stored client answers for a minute
		// without another fetch.
		if record, ok := r.transients[id]; ok && r.now().Sub(record.at) < staleRefetch {
			if stored := r.storedLocked(req); stored != nil {
				r.mu.Unlock()
				return r.serveStale(ctx, logger, stored, record.reason), nil
			}
		}
		if !checked {
			r.mu.Unlock()
			if err := r.opts.checkURL(ctx, id); err != nil {
				return r.refused(ctx, req, err, logger)
			}
			continue
		}
		f := r.flights[id]
		if f == nil {
			release, err := r.governor.acquire(id, idOrigin(id), r.now())
			if err != nil {
				r.mu.Unlock()
				return r.refused(ctx, req, err, logger)
			}
			f = &flight{done: make(chan struct{})}
			r.flights[id] = f
			go r.fetch(context.WithoutCancel(ctx), id, f, r.cache.peek(id), release, logger)
		}
		f.waiters++
		f.stored = f.stored || r.storedLocked(req) != nil
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-f.done:
		}
		if f.err != nil {
			return r.refused(ctx, req, f.err, logger)
		}
		return r.save(ctx, req, f.doc, f.entry, logger)
	}
}

// refused decides whether the stored client stands in for a failed refresh:
// after a transient failure, or after a fetch limit's refusal within five
// minutes of one. A refused document or URL stops stale serving until a
// fetch succeeds; other failures leave no record.
func (r *resolver) refused(ctx context.Context, req oauthprovider.DiscoveryRequest, err error, logger *slog.Logger) (*oauthprovider.DiscoveredClient, error) {
	id := req.ClientID
	kind, fetched := failureKind(err)
	r.mu.Lock()
	stored := r.storedLocked(req)
	now := r.now()
	var policy policyError
	switch {
	case stored != nil && fetched && kind == transientFailure:
		// The fetch recorded the failure when it settled.
		r.mu.Unlock()
		return r.serveStale(ctx, logger, stored, describe(err)), nil
	case stored != nil && fetched && kind == terminalFailure:
		r.terminalLocked(id, now)
	case errors.As(err, &policy):
		// A URL policy error stops stale serving and paces the client, as
		// a refusal inside the fetch does in another runtime.
		delete(r.transients, id)
		if stored != nil {
			r.terminalLocked(id, now)
		}
		r.mu.Unlock()
		r.governor.pace(id, now)
		return nil, err
	}
	record, recent := r.transients[id]
	if stored != nil && recent && now.Sub(record.at) <= staleRefusal && (governorRefusal(err) || fetched && kind == capacityFailure) {
		r.mu.Unlock()
		return r.serveStale(ctx, logger, stored, record.reason), nil
	}
	r.mu.Unlock()
	return nil, err
}

// storedLocked returns the stored client when it may stand in for a failed
// refresh: validated within the stale bound, after the watermark, and with
// no terminal failure since.
func (r *resolver) storedLocked(req oauthprovider.DiscoveryRequest) *oauthprovider.DiscoveredClient {
	if req.Existing == nil || r.opts.MetadataStaleIfError == 0 {
		return nil
	}
	if _, terminal := r.terminals[req.ClientID]; terminal {
		return nil
	}
	validated := req.Existing.UpdatedAt
	if !validated.After(r.watermark) || r.now().Sub(validated) > r.opts.MetadataStaleIfError {
		return nil
	}
	return req.Existing
}

func (r *resolver) serveStale(ctx context.Context, logger *slog.Logger, stored *oauthprovider.DiscoveredClient, reason string) *oauthprovider.DiscoveredClient {
	logger.WarnContext(ctx, "cimd is serving the stored client "+stored.ClientID+" because its metadata document could not be refreshed: "+reason)
	return stored
}

// recordLocked sets a transient record, evicting the oldest at the bound.
func (r *resolver) recordLocked(records map[string]staleRecord, id string, record staleRecord) {
	delete(records, id)
	for len(records) >= r.opts.MaxCacheEntries {
		oldest := ""
		for key, value := range records {
			if oldest == "" || value.at.Before(records[oldest].at) {
				oldest = key
			}
		}
		delete(records, oldest)
	}
	records[id] = record
}

// terminalLocked records a terminal failure. At the bound it drops records
// past the stale bound, then the oldest, moving the watermark.
func (r *resolver) terminalLocked(id string, now time.Time) {
	delete(r.terminals, id)
	for key, at := range r.terminals {
		if len(r.terminals) < r.opts.MaxCacheEntries {
			break
		}
		if now.Sub(at) > r.opts.MetadataStaleIfError {
			delete(r.terminals, key)
		}
	}
	for len(r.terminals) >= r.opts.MaxCacheEntries {
		oldest := ""
		for key, at := range r.terminals {
			if oldest == "" || at.Before(r.terminals[oldest]) {
				oldest = key
			}
		}
		delete(r.terminals, oldest)
		r.watermark = now
	}
	r.terminals[id] = now
}

func describe(err error) string {
	var problem *auth.OAuthError
	if errors.As(err, &problem) {
		return problem.Description
	}
	return err.Error()
}

// fetch runs one shared fetch, revalidating an expired entry with its
// validators, caches the document when its response allows, records a
// transient failure for the stored client to stand in, and settles the
// fetch budget.
func (r *resolver) fetch(ctx context.Context, id string, f *flight, expired *cacheEntry, release func(fetchOutcome, time.Time), logger *slog.Logger) {
	var etag, lastModified string
	if expired != nil {
		etag, lastModified = expired.headers.ETag, expired.headers.LastModified
	}
	got, err := r.fetchGuarded(ctx, id, etag, lastModified, logger)
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
	// A success ends both failure records. A transient failure is recorded
	// before any waiter wakes, so a request arriving now finds it, but only
	// for a stored client that may stand in, so unknown client IDs cannot
	// evict others' records. Any other failure but a capacity refusal ends
	// the transient record.
	switch kind, _ := failureKind(err); {
	case err == nil:
		delete(r.transients, id)
		delete(r.terminals, id)
	case kind == transientFailure && f.stored:
		r.recordLocked(r.transients, id, staleRecord{now, describe(err)})
	case kind == terminalFailure || kind == transportFailure:
		delete(r.transients, id)
	}
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

// fetchGuarded fetches a document, turning a panic in a custom Transport
// into a transport failure, so the shared fetch always settles and the
// process survives.
func (r *resolver) fetchGuarded(ctx context.Context, id, etag, lastModified string, logger *slog.Logger) (got fetchedDocument, err error) {
	defer func() {
		if p := recover(); p != nil {
			logger.ErrorContext(ctx, "cimd metadata document transport panicked", "panic", fmt.Sprint(p))
			got, err = fetchedDocument{}, fetchFailure(transportFailure, networkFailure)
		}
	}()
	return r.opts.fetchDocument(ctx, r.http, id, etag, lastModified, logger)
}

// save stores a document through the provider's registration rules and
// notifies the host. A failed save drops its entry and paces the client.
func (r *resolver) save(ctx context.Context, req oauthprovider.DiscoveryRequest, doc oauthprovider.ClientMetadataDocument, entry *cacheEntry, logger *slog.Logger) (*oauthprovider.DiscoveredClient, error) {
	result, err := req.Register(ctx, doc)
	if err != nil && ctx.Err() != nil {
		// A request that ended mid-save says nothing about the document or
		// the store, so the entry stays cached for the next request to save.
		return nil, err
	}
	r.mu.Lock()
	current := r.cache.peek(req.ClientID)
	if err != nil {
		if entry != nil && current == entry {
			r.cache.remove(req.ClientID)
		}
		// A document the provider refuses stops stale serving; a storage
		// failure says nothing about the document.
		var problem *auth.OAuthError
		if errors.As(err, &problem) && problem.Status == http.StatusBadRequest && r.storedLocked(req) != nil {
			r.terminalLocked(req.ClientID, r.now())
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
		if o, ok := publicnet.Origin(u); ok {
			return o
		}
	}
	return id
}
