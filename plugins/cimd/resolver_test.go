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

// waitFor waits until a number of requests share the client's fetch.
func (h *harness) waitFor(t *testing.T, waiters int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.r.mu.Lock()
		n := 0
		if f := h.r.flights[id]; f != nil {
			n = f.waiters
		}
		h.r.mu.Unlock()
		if n >= waiters {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the requests did not share one fetch", n)
		}
		time.Sleep(time.Millisecond)
	}
}

// Concurrent resolutions of one client share one fetch, which spends the
// budget and asks the URL policy once, and each saves; a fresh hit spends
// none.
func TestResolverSharesFetches(t *testing.T) {
	var asked atomic.Int32
	h := newHarness(t, Options{AllowMetadataURL: func(context.Context, string) (bool, error) { asked.Add(1); return true, nil }})
	clock := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	h.r.now = func() time.Time { return clock }
	release := make(chan struct{})
	h.respond = func(*http.Request) (*http.Response, error) {
		<-release
		return answer(200, "application/json", `{"client_id":"`+id+`","client_name":"App"}`), nil
	}
	var wg sync.WaitGroup
	errs := make([]error, 5)
	for i := range 5 {
		wg.Go(func() { _, errs[i] = h.resolve(t.Context(), nil) })
	}
	h.waitFor(t, 5)
	close(release)
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	h.r.mu.Lock()
	starts, active := len(h.r.governor.starts), h.r.governor.active
	h.r.mu.Unlock()
	if h.fetches.Load() != 1 || h.register.Load() != 5 || starts != 1 || active != 0 || asked.Load() != 1 {
		t.Fatal("concurrent resolutions did not share one fetch and save each", h.fetches.Load(), h.register.Load(), starts, active, asked.Load())
	}
	if _, err := h.resolve(t.Context(), nil); err != nil || len(h.r.governor.starts) != 1 || h.fetches.Load() != 1 {
		t.Fatal("a fresh hit spent the budget", err, len(h.r.governor.starts))
	}
}

// A failed save drops the entry and paces the client, and one waiter's
// failed save does not fail another's.
func TestResolverSaveFailure(t *testing.T) {
	h := newHarness(t, Options{})
	clock := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	h.r.now = func() time.Time { return clock }
	h.saveErr = func(int32) error { return errors.New("store down") }
	if _, err := h.resolve(t.Context(), nil); err == nil {
		t.Fatal("a failed save was accepted")
	}
	if h.r.cache.peek(id) != nil {
		t.Fatal("a failed save left its entry cached")
	}
	if _, err := h.resolve(t.Context(), nil); !governorRefusal(err) {
		t.Fatal("a failed save did not pace the client", err)
	}
	both := newHarness(t, Options{})
	both.saveErr = func(n int32) error {
		if n == 1 {
			return errors.New("store down")
		}
		return nil
	}
	release := make(chan struct{})
	both.respond = func(*http.Request) (*http.Response, error) {
		<-release
		return answer(200, "application/json", `{"client_id":"`+id+`"}`), nil
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range 2 {
		wg.Go(func() { _, errs[i] = both.resolve(t.Context(), nil) })
	}
	both.waitFor(t, 2)
	close(release)
	wg.Wait()
	if (errs[0] == nil) == (errs[1] == nil) || both.fetches.Load() != 1 {
		t.Fatal("one failed save decided another waiter's answer", errs, both.fetches.Load())
	}
	// A request that ends mid-save keeps the entry cached and paces nothing.
	ended := newHarness(t, Options{})
	ctx, cancel := context.WithCancel(t.Context())
	ended.saveErr = func(n int32) error {
		if n == 1 {
			cancel()
			return context.Canceled
		}
		return nil
	}
	if _, err := ended.resolve(ctx, nil); !errors.Is(err, context.Canceled) || ended.r.cache.peek(id) == nil {
		t.Fatal("an ended request's save dropped the cached document", err)
	}
	if _, err := ended.resolve(t.Context(), nil); err != nil || ended.fetches.Load() != 1 {
		t.Fatal("an ended request's save paced the client or spent a fetch", err, ended.fetches.Load())
	}
}

// The host's URL policy runs inside the shared fetch, as another runtime's
// does: a refusal or an error makes no request, spends one fetch start,
// paces the client and answers every request sharing the fetch; it sees the
// starting request's context values but not its cancellation.
func TestResolverURLPolicy(t *testing.T) {
	type key struct{}
	for name, tc := range map[string]struct {
		allowed bool
		err     error
	}{"refused": {false, nil}, "error": {true, errors.New("policy down")}} {
		var asked atomic.Int32
		release := make(chan struct{})
		var h *harness
		h = newHarness(t, Options{AllowMetadataURL: func(ctx context.Context, url string) (bool, error) {
			asked.Add(1)
			if ctx.Value(key{}) != "starter" || url != id {
				t.Error("the policy did not see the starting request", ctx.Value(key{}), url)
			}
			<-release
			return tc.allowed, tc.err
		}})
		var wg sync.WaitGroup
		errs := make([]error, 2)
		wg.Go(func() { _, errs[0] = h.resolve(context.WithValue(t.Context(), key{}, "starter"), nil) })
		h.waitFor(t, 1)
		wg.Go(func() { _, errs[1] = h.resolve(t.Context(), nil) })
		h.waitFor(t, 2)
		close(release)
		wg.Wait()
		for _, err := range errs {
			if err == nil || tc.err != nil && !errors.Is(err, tc.err) || tc.err == nil && !strings.Contains(err.Error(), "not permitted by the server's fetch policy") {
				t.Fatal("a refused URL was not refused for every sharing request", name, errs)
			}
		}
		h.r.mu.Lock()
		starts, active := len(h.r.governor.starts), h.r.governor.active
		h.r.mu.Unlock()
		if asked.Load() != 1 || h.fetches.Load() != 0 || starts != 1 || active != 0 {
			t.Fatal("a refused URL made a request or spent the budget more than once", name, asked.Load(), h.fetches.Load(), starts)
		}
		if _, err := h.resolve(t.Context(), nil); !governorRefusal(err) {
			t.Fatal("a refused URL did not pace the client", name, err)
		}
	}
	// An invalid URL is refused before the policy, a fetch or the budget.
	invalid := newHarness(t, Options{AllowMetadataURL: func(context.Context, string) (bool, error) {
		t.Error("the policy was asked about an invalid URL")
		return true, nil
	}})
	var problem *auth.OAuthError
	_, err := invalid.r.resolve(t.Context(), oauthprovider.DiscoveryRequest{Auth: invalid.auth, ClientID: "https://user@app.example.test/client.json"})
	if !errors.As(err, &problem) || problem.Description != ValidateClientIDURL("https://user@app.example.test/client.json").Error() || invalid.fetches.Load() != 0 || len(invalid.r.governor.starts) != 0 {
		t.Fatal("an invalid URL was not refused before any fetch", err)
	}
	// A request cancelled while the policy runs does not cancel the policy
	// or the fetch, whose document a later request finds cached.
	var cancelled atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	h := newHarness(t, Options{AllowMetadataURL: func(ctx context.Context, _ string) (bool, error) {
		close(entered)
		<-release
		cancelled.Store(ctx.Err() != nil)
		return true, nil
	}})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error)
	go func() { _, err := h.resolve(ctx, nil); done <- err }()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("a cancelled request did not end", err)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for h.fetches.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got, err := h.resolve(t.Context(), nil); err != nil || got.ClientID != id || cancelled.Load() || h.fetches.Load() != 1 {
		t.Fatal("a cancelled request cancelled its shared fetch", err, cancelled.Load(), h.fetches.Load())
	}
}

// The defaults, and the options the provider's discovery and the fetch
// receive.
func TestResolverOptions(t *testing.T) {
	r, err := newResolver(Options{})
	if err != nil || r.opts.MetadataRevalidationInterval != time.Hour || r.cache.max != 1000 || r.governor.entries != 1000 {
		t.Fatal("wrong defaults", err, r.opts.MetadataRevalidationInterval, r.cache.max, r.governor.entries)
	}
	var asked []string
	d, err := NewClientDiscovery(Options{AllowCrossOriginJWKSURI: func(_ context.Context, clientID, jwksURI string) (bool, error) {
		asked = append(asked, clientID+" "+jwksURI)
		return true, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := d.AllowCrossOriginJWKSURI(t.Context(), id, "https://keys.example.test/jwks"); !ok || err != nil || len(asked) != 1 || asked[0] != id+" https://keys.example.test/jwks" {
		t.Fatal("the cross-origin hook did not reach the discovery", ok, err, asked)
	}
	bound := newHarness(t, Options{OriginBoundFields: []string{"client_uri"}})
	bound.respond = func(*http.Request) (*http.Response, error) {
		return answer(200, "application/json", `{"client_id":"`+id+`","client_uri":"https://www.example.test/"}`), nil
	}
	if _, err := bound.resolve(t.Context(), nil); err == nil || !strings.Contains(err.Error(), "client_uri value") {
		t.Fatal("the origin-bound fields did not reach the fetch", err)
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
	var h *harness
	h = newHarness(t, Options{MetadataRevalidationInterval: -1,
		OnClientCreated: func(_ context.Context, e ClientCreatedEvent) error {
			// Notifications run after the save.
			if h.register.Load() == 0 {
				return errors.New("notified before the save")
			}
			created = append(created, e)
			return errors.New("hook down")
		},
		OnClientRefreshed: func(_ context.Context, e ClientRefreshedEvent) error {
			refreshed = append(refreshed, e)
			return errors.New("refresh hook down")
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
	saves := h.register.Load()
	if _, err := h.resolve(t.Context(), &previous); err != nil || len(refreshed) != 1 || refreshed[0].PreviousClient.RowID != "old" || refreshed[0].Client.RowID != "row" ||
		refreshed[0].Document.ClientID != id || refreshed[0].Header.Get("X-Request") != "1" || h.register.Load() != saves+1 {
		t.Fatal("the refreshed event was wrong", err, refreshed)
	}
	if !strings.Contains(h.logs.String(), "cimd onClientRefreshed notification failed") {
		t.Fatal("a refresh callback error was not logged", h.logs.String())
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
