package cimd

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

// staleHarness is a resolver with a stale bound, a movable clock and a
// stored client validated at the clock's start.
func staleHarness(t *testing.T, bound time.Duration, entries int) (*harness, *time.Time, *oauthprovider.DiscoveredClient, *int) {
	t.Helper()
	h := newHarness(t, Options{MetadataStaleIfError: bound, MaxCacheEntries: entries, FetchPolicy: FetchPolicy{MinimumFetchInterval: -1}})
	clock := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	h.r.now = func() time.Time { return clock }
	status := 503
	h.respond = func(*http.Request) (*http.Response, error) {
		if status == 200 {
			res := answer(200, "application/json", `{"client_id":"`+id+`"}`)
			res.Header.Set("Cache-Control", "no-store")
			return res, nil
		}
		return answer(status, "application/json", ""), nil
	}
	stored := &oauthprovider.DiscoveredClient{RowID: "row", DiscoveryID: DiscoveryID, UpdatedAt: clock}
	stored.ClientID = id
	return h, &clock, stored, &status
}

// The stored client answers a transient refresh failure within the stale
// bound, with a warning, and nothing else.
func TestStaleServing(t *testing.T) {
	off := newHarness(t, Options{})
	off.respond = func(*http.Request) (*http.Response, error) { return answer(503, "application/json", ""), nil }
	stored := &oauthprovider.DiscoveredClient{UpdatedAt: time.Now()}
	if _, err := off.resolve(t.Context(), stored); err == nil {
		t.Fatal("a failure was served stale without the option")
	}
	h, clock, stored, status := staleHarness(t, time.Hour, 100)
	*clock = clock.Add(10 * time.Minute)
	got, err := h.resolve(t.Context(), stored)
	if err != nil || got != stored || !strings.Contains(h.logs.String(), "cimd is serving the stored client "+id+" because its metadata document could not be refreshed: Metadata document fetch returned HTTP 503") {
		t.Fatal("a transient failure was not served stale", err, h.logs.String())
	}
	// Within a minute the stored client answers without a fetch.
	fetches := h.fetches.Load()
	if got, err := h.resolve(t.Context(), stored); err != nil || got != stored || h.fetches.Load() != fetches {
		t.Fatal("a stale client was refetched within the minute", err, h.fetches.Load()-fetches)
	}
	*clock = clock.Add(2 * time.Minute)
	if _, err := h.resolve(t.Context(), stored); err != nil || h.fetches.Load() != fetches+1 {
		t.Fatal("a stale client was not refetched after the minute", err)
	}
	// Beyond the bound the failure is the answer.
	*clock = clock.Add(time.Hour)
	if _, err := h.resolve(t.Context(), stored); err == nil {
		t.Fatal("a stored client beyond the bound was served")
	}
	// A terminal failure stops stale serving until a success.
	h, clock, stored, status = staleHarness(t, time.Hour, 100)
	*status = 404
	if _, err := h.resolve(t.Context(), stored); err == nil {
		t.Fatal("a terminal failure was served stale")
	}
	*status = 503
	if _, err := h.resolve(t.Context(), stored); err == nil {
		t.Fatal("stale serving resumed after a terminal failure")
	}
	*status = 200
	if _, err := h.resolve(t.Context(), stored); err != nil {
		t.Fatal(err)
	}
	*status = 503
	if got, err := h.resolve(t.Context(), stored); err != nil || got != stored {
		t.Fatal("a success did not clear the terminal record", err)
	}
	// A document the provider refuses is terminal; a storage failure is not.
	for name, tc := range map[string]struct {
		err      error
		terminal bool
	}{"refused": {&auth.OAuthError{Status: 400, Code: "invalid_client_metadata", Description: "bad"}, true}, "storage": {errors.New("database down"), false},
		"server": {&auth.OAuthError{Status: 500, Code: "server_error", Description: "down"}, false}} {
		h, _, stored, status := staleHarness(t, time.Hour, 100)
		*status = 200
		h.saveErr = func(int32) error { return tc.err }
		if _, err := h.resolve(t.Context(), stored); err == nil {
			t.Fatal("a failed save was accepted", name)
		}
		h.saveErr = nil
		*status = 503
		if _, err := h.resolve(t.Context(), stored); (err != nil) != tc.terminal {
			t.Fatal("wrong stale serving after a failed save", name, err)
		}
	}
	// A transport failure that retrieved nothing leaves no record.
	h, _, stored, _ = staleHarness(t, time.Hour, 100)
	h.respond = func(*http.Request) (*http.Response, error) { return nil, errPrivate }
	if _, err := h.resolve(t.Context(), stored); err == nil {
		t.Fatal("a transport failure was served stale")
	}
	if _, terminal := h.r.terminals[id]; terminal {
		t.Fatal("a transport failure was recorded as terminal")
	}
}

// A fetch limit's refusal serves the stored client only within five minutes
// of a transient failure.
func TestStaleRefusals(t *testing.T) {
	h, clock, stored, _ := staleHarness(t, time.Hour, 100)
	h.r.governor.policy.MaxFetchesPerOriginPerMinute = 1
	refuse := func() error {
		_, err := h.resolve(t.Context(), stored)
		return err
	}
	if err := refuse(); err != nil {
		t.Fatal(err)
	}
	// The minute-long answer from the record covers the next resolution;
	// after it, the origin budget refuses and the record answers again.
	*clock = clock.Add(70 * time.Second)
	h.r.governor.policy.MaxFetchesPerOriginPerMinute = 0
	if got, err := h.resolve(t.Context(), stored); err != nil || got != stored {
		t.Fatal("a refusal within five minutes of a transient failure was not served stale", err)
	}
	*clock = clock.Add(5 * time.Minute)
	var problem *auth.OAuthError
	if err := refuse(); !errors.As(err, &problem) || problem.Code != "temporarily_unavailable" {
		t.Fatal("a refusal long after a transient failure was served stale", err)
	}
	// A transport failure after a transient one ends the transient record,
	// so a later refusal is the answer.
	moved, movedClock, movedStored, _ := staleHarness(t, time.Hour, 100)
	if got, err := moved.resolve(t.Context(), movedStored); err != nil || got != movedStored {
		t.Fatal(err)
	}
	*movedClock = movedClock.Add(70 * time.Second)
	moved.respond = func(*http.Request) (*http.Response, error) { return nil, errPrivate }
	if _, err := moved.resolve(t.Context(), movedStored); err == nil {
		t.Fatal("a transport failure was served stale")
	}
	moved.r.governor.policy.MaxFetchesPerOriginPerMinute = 0
	if _, err := moved.resolve(t.Context(), movedStored); !governorRefusal(err) {
		t.Fatal("a refusal after a transport failure was served stale", err)
	}
	fresh, _, other, _ := staleHarness(t, time.Hour, 100)
	fresh.r.governor.policy.MaxFetchesPerOriginPerMinute = 0
	if _, err := fresh.resolve(t.Context(), other); !governorRefusal(err) {
		t.Fatal("a refusal without a transient failure was served stale", err)
	}
}

// Evicting a terminal record moves the watermark, so clients validated
// before it are not served stale; clients without a stored row leave no
// records.
func TestStaleWatermark(t *testing.T) {
	h, clock, stored, status := staleHarness(t, time.Hour, 1)
	*status = 404
	*clock = clock.Add(time.Minute)
	for _, other := range []string{"https://app.example.test/one", "https://app.example.test/two"} {
		client := &oauthprovider.DiscoveredClient{UpdatedAt: *clock}
		client.ClientID = other
		h.r.resolve(t.Context(), oauthprovider.DiscoveryRequest{Auth: h.auth, ClientID: other, Existing: client,
			Register: func(context.Context, oauthprovider.ClientMetadataDocument) (oauthprovider.ClientRegistrationResult, error) {
				return oauthprovider.ClientRegistrationResult{}, nil
			}})
	}
	if !h.r.watermark.Equal(*clock) {
		t.Fatal("evicting a terminal record did not move the watermark", h.r.watermark)
	}
	*status = 503
	if _, err := h.resolve(t.Context(), stored); err == nil {
		t.Fatal("a client validated before the watermark was served stale")
	}
	// Failures of clients without a stored row leave no record.
	bare, _, _, _ := staleHarness(t, time.Hour, 100)
	if _, err := bare.resolve(t.Context(), nil); err == nil || len(bare.r.transients) != 0 || len(bare.r.terminals) != 0 {
		t.Fatal("a client without a stored row left records", err)
	}
	if _, err := newResolver(Options{MetadataStaleIfError: 25 * time.Hour}); err == nil {
		t.Fatal("a stale bound beyond a day was accepted")
	}
	if d, err := NewClientDiscovery(Options{MetadataStaleIfError: time.Hour}); err != nil || d.JWKSStaleIfError != time.Hour {
		t.Fatal("the stale bound did not reach the key cache", err)
	}
}

// A transport's capacity refusal serves the stored client within five
// minutes of a transient failure, keeps the transient record and paces
// nothing; a URL policy error stops stale serving and paces the client.
func TestStaleCapacityAndPolicy(t *testing.T) {
	h, clock, stored, _ := staleHarness(t, time.Hour, 100)
	h.r.governor.policy.MinimumFetchInterval = time.Second
	if got, err := h.resolve(t.Context(), stored); err != nil || got != stored {
		t.Fatal(err)
	}
	*clock = clock.Add(70 * time.Second)
	h.respond = func(*http.Request) (*http.Response, error) { return nil, errLookupLimit }
	if got, err := h.resolve(t.Context(), stored); err != nil || got != stored {
		t.Fatal("a capacity refusal after a transient failure was not served stale", err)
	}
	if _, paced := h.r.governor.paced[id]; paced {
		t.Fatal("a capacity refusal paced the client")
	}
	if _, kept := h.r.transients[id]; !kept {
		t.Fatal("a capacity refusal dropped the transient record")
	}
	*clock = clock.Add(5 * time.Minute)
	var problem *auth.OAuthError
	if _, err := h.resolve(t.Context(), stored); !errors.As(err, &problem) || problem.Status != 429 {
		t.Fatal("a capacity refusal long after a transient failure was served stale", err)
	}
	policy, _, policyStored, _ := staleHarness(t, time.Hour, 100)
	policy.r.governor.policy.MinimumFetchInterval = time.Second
	hookErr := errors.New("policy down")
	policy.r.opts.AllowMetadataURL = func(context.Context, string) (bool, error) { return false, hookErr }
	if _, err := policy.resolve(t.Context(), policyStored); !errors.Is(err, hookErr) {
		t.Fatal("a policy error was not the answer", err)
	}
	if _, terminal := policy.r.terminals[id]; !terminal {
		t.Fatal("a policy error did not stop stale serving")
	}
	if _, paced := policy.r.governor.paced[id]; !paced {
		t.Fatal("a policy error did not pace the client")
	}
}
