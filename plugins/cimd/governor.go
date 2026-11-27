package cimd

import (
	"errors"
	"fmt"
	"sync"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// FetchPolicy bounds metadata document fetches, which are refused at once
// rather than queued. Zero means the default.
type FetchPolicy struct {
	// MinimumFetchInterval is how long a client ID waits after a failed
	// fetch, one second by default; a negative value turns the wait off,
	// where another runtime uses 0, since a zero Duration means unset.
	MinimumFetchInterval time.Duration
	// MaxConcurrentFetches and MaxConcurrentFetchesPerOrigin bound fetches
	// in flight, 16 and 4 by default. MaxFetchesPerMinute and
	// MaxFetchesPerOriginPerMinute bound fetch starts in a rolling minute,
	// 120 and 30 by default.
	MaxConcurrentFetches, MaxConcurrentFetchesPerOrigin, MaxFetchesPerMinute, MaxFetchesPerOriginPerMinute int
}

func (p FetchPolicy) normalized() (FetchPolicy, error) {
	for _, f := range []struct {
		name  string
		value *int
		def   int
	}{{"MaxConcurrentFetches", &p.MaxConcurrentFetches, 16}, {"MaxConcurrentFetchesPerOrigin", &p.MaxConcurrentFetchesPerOrigin, 4},
		{"MaxFetchesPerMinute", &p.MaxFetchesPerMinute, 120}, {"MaxFetchesPerOriginPerMinute", &p.MaxFetchesPerOriginPerMinute, 30}} {
		switch {
		case *f.value < 0:
			return p, fmt.Errorf("cimd: FetchPolicy.%s must be a positive integer", f.name)
		case *f.value == 0:
			*f.value = f.def
		}
	}
	if p.MinimumFetchInterval == 0 {
		p.MinimumFetchInterval = time.Second
	}
	return p, nil
}

// fetchRefusal is the governor's refusal: 429 temporarily_unavailable.
type fetchRefusal struct{ *auth.OAuthError }

func (e fetchRefusal) Unwrap() error { return e.OAuthError }

func refuseFetch(description string) error {
	return fetchRefusal{&auth.OAuthError{Status: 429, Code: "temporarily_unavailable", Description: description}}
}

func governorRefusal(err error) bool {
	var refusal fetchRefusal
	return errors.As(err, &refusal)
}

type fetchOutcome int

const (
	fetchSucceeded fetchOutcome = iota
	fetchFailed
	// fetchAtCapacity is a transport refusal at a local limit, which leaves
	// no pacing behind.
	fetchAtCapacity
)

type originState struct {
	active int
	starts []time.Time
}

// governor admits metadata fetches under a FetchPolicy. Its client and
// origin records are bounded by entries; only records past their interval
// or window are evicted.
type governor struct {
	mu      sync.Mutex
	policy  FetchPolicy
	entries int
	paced   map[string]time.Time
	origins map[string]*originState
	active  int
	starts  []time.Time
}

func newGovernor(policy FetchPolicy, entries int) (*governor, error) {
	policy, err := policy.normalized()
	if err != nil {
		return nil, err
	}
	return &governor{policy: policy, entries: entries, paced: map[string]time.Time{}, origins: map[string]*originState{}}, nil
}

// recent drops start times older than a minute.
func recent(starts []time.Time, now time.Time) []time.Time {
	i := 0
	for i < len(starts) && !starts[i].After(now.Add(-time.Minute)) {
		i++
	}
	return starts[i:]
}

// acquire admits one fetch for a client ID and its origin, or refuses it.
// release settles it, pacing the client after a failure.
func (g *governor) acquire(clientID, origin string, now time.Time) (func(fetchOutcome, time.Time), error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if until, ok := g.paced[clientID]; ok {
		if now.Before(until) {
			return nil, refuseFetch("metadata document fetch is within the per-client minimum interval")
		}
		delete(g.paced, clientID)
	}
	if len(g.paced) >= g.entries && !g.evictPaced(now) {
		return nil, refuseFetch("metadata fetch client state is at capacity")
	}
	state := g.origins[origin]
	if state == nil {
		if len(g.origins) >= g.entries && !g.evictOrigin(now) {
			return nil, refuseFetch("metadata fetch origin state is at capacity")
		}
		state = &originState{}
		g.origins[origin] = state
	}
	g.starts, state.starts = recent(g.starts, now), recent(state.starts, now)
	switch {
	case g.active >= g.policy.MaxConcurrentFetches:
		return nil, refuseFetch("global metadata fetch concurrency limit exceeded")
	case state.active >= g.policy.MaxConcurrentFetchesPerOrigin:
		return nil, refuseFetch("metadata fetch concurrency limit exceeded for client origin")
	case len(g.starts) >= g.policy.MaxFetchesPerMinute:
		return nil, refuseFetch("global metadata fetch rate limit exceeded")
	case len(state.starts) >= g.policy.MaxFetchesPerOriginPerMinute:
		return nil, refuseFetch("metadata fetch rate limit exceeded for client origin")
	}
	g.active++
	state.active++
	g.starts, state.starts = append(g.starts, now), append(state.starts, now)
	var once sync.Once
	return func(outcome fetchOutcome, settled time.Time) {
		once.Do(func() { g.settle(clientID, state, outcome, settled) })
	}, nil
}

func (g *governor) settle(clientID string, state *originState, outcome fetchOutcome, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.active--
	state.active--
	// A failure paces the client from when it settles; a success clears a
	// pace another request's refusal wrote meanwhile, as another runtime
	// clears it on success.
	switch outcome {
	case fetchFailed:
		g.paceLocked(clientID, now)
	case fetchSucceeded:
		delete(g.paced, clientID)
	}
}

// pace makes a client wait the interval, as after a failed fetch.
func (g *governor) pace(clientID string, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.paceLocked(clientID, now)
}

func (g *governor) paceLocked(clientID string, now time.Time) {
	if g.policy.MinimumFetchInterval <= 0 {
		return
	}
	if _, ok := g.paced[clientID]; ok || len(g.paced) < g.entries || g.evictPaced(now) {
		g.paced[clientID] = now.Add(g.policy.MinimumFetchInterval)
	}
}

// evictPaced drops client records whose interval has passed.
func (g *governor) evictPaced(now time.Time) bool {
	evicted := false
	for id, until := range g.paced {
		if !now.Before(until) {
			delete(g.paced, id)
			evicted = true
		}
	}
	return evicted
}

// evictOrigin drops origin records with no fetch in flight or in the window.
func (g *governor) evictOrigin(now time.Time) bool {
	evicted := false
	for origin, state := range g.origins {
		if state.active == 0 && len(recent(state.starts, now)) == 0 {
			delete(g.origins, origin)
			evicted = true
		}
	}
	return evicted
}
