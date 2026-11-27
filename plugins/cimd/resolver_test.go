package cimd

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

// harness is a resolver over a fake transport and a fake Register.
type harness struct {
	r                 *resolver
	auth              *auth.Auth
	logs              *bytes.Buffer
	fetches, register atomic.Int32
	mu                sync.Mutex
	respond           func(*http.Request) (*http.Response, error)
	saveErr           func(int32) error
	created           bool
	stored            *oauthprovider.DiscoveredClient
}

func newHarness(t *testing.T, opts Options) *harness {
	t.Helper()
	h := &harness{logs: &bytes.Buffer{}}
	a, err := auth.New(auth.Options{Store: memory.New(), BaseURL: "https://auth.example.test", Secret: strings.Repeat("c", 40), Logger: slog.New(slog.NewTextHandler(h.logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	h.auth = a
	h.respond = func(*http.Request) (*http.Response, error) {
		return answer(200, "application/json", `{"client_id":"`+id+`","client_name":"App"}`), nil
	}
	opts.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		h.fetches.Add(1)
		h.mu.Lock()
		respond := h.respond
		h.mu.Unlock()
		return respond(r)
	})
	h.r, err = newResolver(opts)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) resolve(ctx context.Context, existing *oauthprovider.DiscoveredClient) (*oauthprovider.DiscoveredClient, error) {
	return h.r.resolve(ctx, oauthprovider.DiscoveryRequest{Auth: h.auth, ClientID: id, Existing: existing, Header: http.Header{"X-Request": {"1"}},
		Register: func(ctx context.Context, doc oauthprovider.ClientMetadataDocument) (oauthprovider.ClientRegistrationResult, error) {
			n := h.register.Add(1)
			if h.saveErr != nil {
				if err := h.saveErr(n); err != nil {
					return oauthprovider.ClientRegistrationResult{}, err
				}
			}
			client := oauthprovider.DiscoveredClient{RowID: "row", DiscoveryID: DiscoveryID}
			client.ClientID, client.Name = doc.ClientID, doc.Name
			return oauthprovider.ClientRegistrationResult{Client: client, Created: h.created}, nil
		}})
}

// Concurrent resolutions of one client share one fetch and each saves; one
// failed save does not fail the others, drops the entry and paces the
// client.
func TestResolverSharesFetches(t *testing.T) {
	h := newHarness(t, Options{})
	release := make(chan struct{})
	h.respond = func(*http.Request) (*http.Response, error) {
		<-release
		return answer(200, "application/json", `{"client_id":"`+id+`","client_name":"App"}`), nil
	}
	h.saveErr = func(n int32) error {
		if n == 1 {
			return errors.New("store down")
		}
		return nil
	}
	var wg sync.WaitGroup
	errs := make([]error, 5)
	for i := range 5 {
		wg.Go(func() { _, errs[i] = h.resolve(t.Context(), nil) })
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	failed := 0
	for _, err := range errs {
		if err != nil {
			failed++
		}
	}
	if h.fetches.Load() != 1 || h.register.Load() != 5 || failed != 1 {
		t.Fatal("concurrent resolutions did not share one fetch and save each", h.fetches.Load(), h.register.Load(), failed)
	}
	// The failed save dropped the entry and paced the client.
	if h.r.cache.peek(id) != nil {
		t.Fatal("a failed save left its entry cached")
	}
	if _, err := h.resolve(t.Context(), nil); !governorRefusal(err) {
		t.Fatal("a failed save did not pace the client", err)
	}
}

// A fresh entry the stored client matches returns the stored client without
// saving; the gate and the budget run once per fetch; an expired entry is
// refetched only when resolved again, conditionally.
func TestResolverCache(t *testing.T) {
	var gate atomic.Int32
	h := newHarness(t, Options{AllowMetadataURL: func(context.Context, string) (bool, error) { gate.Add(1); return true, nil }})
	var sent atomic.Value
	h.respond = func(r *http.Request) (*http.Response, error) {
		sent.Store(r.Header.Get("If-None-Match"))
		if r.Header.Get("If-None-Match") == `"v1"` {
			res := answer(304, "", "")
			res.Header.Set("Cache-Control", "max-age=60")
			return res, nil
		}
		res := answer(200, "application/json", `{"client_id":"`+id+`","client_name":"App"}`)
		res.Header.Set("ETag", `"v1"`)
		res.Header.Set("Cache-Control", "max-age=60")
		return res, nil
	}
	stored, err := h.resolve(t.Context(), nil)
	if err != nil || stored.ClientID != id {
		t.Fatal(err)
	}
	existing := *stored
	if got, err := h.resolve(t.Context(), &existing); err != nil || got != &existing || h.register.Load() != 1 || h.fetches.Load() != 1 || gate.Load() != 1 {
		t.Fatal("a saved fresh entry was saved or fetched again", err, h.register.Load(), h.fetches.Load(), gate.Load())
	}
	if _, err := h.resolve(t.Context(), nil); err != nil || h.register.Load() != 2 || h.fetches.Load() != 1 {
		t.Fatal("a fresh entry without a stored client was not saved", err)
	}
	// Expiry alone fetches nothing; the next resolution revalidates.
	h.r.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	time.Sleep(10 * time.Millisecond)
	if h.fetches.Load() != 1 {
		t.Fatal("an expired entry was refetched in the background")
	}
	if got, err := h.resolve(t.Context(), &existing); err != nil || got.ClientID != id || h.fetches.Load() != 2 || sent.Load() != `"v1"` || gate.Load() != 2 {
		t.Fatal("an expired entry was not revalidated", err, h.fetches.Load(), sent.Load())
	}
	// A 304 with nothing cached is refused.
	h.r.cache.remove(id)
	h.respond = func(*http.Request) (*http.Response, error) { return answer(304, "", ""), nil }
	h.r.now = func() time.Time { return time.Now().Add(time.Hour) }
	var problem *auth.OAuthError
	if _, err := h.resolve(t.Context(), nil); !errors.As(err, &problem) || problem.Description != "Metadata document returned 304 without a conditional validator" {
		t.Fatal("an unconditional 304 was accepted", err)
	}
	// Uncacheable documents are fetched each time.
	nostore := newHarness(t, Options{})
	var conditional atomic.Bool
	nostore.respond = func(r *http.Request) (*http.Response, error) {
		conditional.Store(conditional.Load() || r.Header.Get("If-None-Match") != "")
		res := answer(200, "application/json", `{"client_id":"`+id+`"}`)
		res.Header.Set("Cache-Control", "no-store")
		res.Header.Set("ETag", `"x"`)
		return res, nil
	}
	for range 2 {
		if _, err := nostore.resolve(t.Context(), nil); err != nil {
			t.Fatal(err)
		}
	}
	if nostore.fetches.Load() != 2 || conditional.Load() {
		t.Fatal("an uncacheable document was cached", nostore.fetches.Load(), conditional.Load())
	}
	if _, err := nostore.r.resolve(t.Context(), oauthprovider.DiscoveryRequest{Auth: nostore.auth, ClientID: "urn:not-a-url"}); err != nil {
		t.Fatal("a non-candidate ID was not left alone", err)
	}
}

// A conditional 304 reuses the expired entry's document with the merged
// caching headers.
func TestResolverNotModified(t *testing.T) {
	h := newHarness(t, Options{})
	h.respond = func(*http.Request) (*http.Response, error) {
		res := answer(304, "", "")
		res.Header.Set("Cache-Control", "max-age=30")
		return res, nil
	}
	name := "Kept"
	expired := &cacheEntry{headers: cacheHeaders{ETag: `"v"`, CacheControl: "max-age=1"}}
	expired.doc.ClientID, expired.doc.Name = id, &name
	f := &flight{done: make(chan struct{})}
	h.r.fetch(t.Context(), id, f, expired, func(fetchOutcome, time.Time) {}, slog.Default())
	if f.err != nil || *f.doc.Name != "Kept" || f.entry.headers.ETag != `"v"` || f.entry.headers.CacheControl != "max-age=30" {
		t.Fatal("a conditional 304 did not reuse the expired document", f.err, f.entry)
	}
}

// Creation and refresh notify the host after the save; a callback error is
// logged and the client still returned.
func TestResolverNotifications(t *testing.T) {
	var created []ClientCreatedEvent
	var refreshed []ClientRefreshedEvent
	h := newHarness(t, Options{MetadataRevalidationInterval: -1,
		OnClientCreated: func(_ context.Context, e ClientCreatedEvent) error {
			created = append(created, e)
			return errors.New("hook down")
		},
		OnClientRefreshed: func(_ context.Context, e ClientRefreshedEvent) error {
			refreshed = append(refreshed, e)
			return nil
		}})
	h.created = true
	got, err := h.resolve(t.Context(), nil)
	if err != nil || got == nil || len(created) != 1 || created[0].Client.ClientID != id || created[0].Document.ClientID != id || created[0].Header.Get("X-Request") != "1" {
		t.Fatal("the created event was wrong", err, created)
	}
	if !strings.Contains(h.logs.String(), "cimd onClientCreated notification failed") {
		t.Fatal("a callback error was not logged", h.logs.String())
	}
	h.created = false
	previous := oauthprovider.DiscoveredClient{RowID: "old"}
	if _, err := h.resolve(t.Context(), &previous); err != nil || len(refreshed) != 1 || refreshed[0].PreviousClient.RowID != "old" || refreshed[0].Client.RowID != "row" {
		t.Fatal("the refreshed event was wrong", err, refreshed)
	}
	// A refused resolution notifies nobody.
	h.respond = func(*http.Request) (*http.Response, error) { return answer(404, "application/json", ""), nil }
	h.r.governor.policy.MinimumFetchInterval = -1
	if _, err := h.resolve(t.Context(), &previous); err == nil || len(refreshed) != 1 {
		t.Fatal("a refused resolution notified", err)
	}
	// Bad options.
	if _, err := NewClientDiscovery(Options{MaxCacheEntries: -1}); err == nil {
		t.Fatal("a negative cache size was accepted")
	}
	if _, err := NewClientDiscovery(Options{FetchPolicy: FetchPolicy{MaxConcurrentFetches: -1}}); err == nil {
		t.Fatal("a negative fetch limit was accepted")
	}
	d, err := NewClientDiscovery(Options{})
	if err != nil || d.ID != "cimd" || d.Metadata["client_id_metadata_document_supported"] != true || d.Transport == nil || !d.Matches(id) || d.Matches("urn:x") {
		t.Fatal("the discovery was wrong", err, d)
	}
}
