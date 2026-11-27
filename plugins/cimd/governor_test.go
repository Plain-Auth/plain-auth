package cimd

import (
	"errors"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

func refusedWith(t *testing.T, err error, description string) {
	t.Helper()
	var problem *auth.OAuthError
	if !governorRefusal(err) || !errors.As(err, &problem) || problem.Status != 429 || problem.Code != "temporarily_unavailable" || problem.Description != description {
		t.Fatal("wanted a governor refusal", description, err)
	}
}

// The policy defaults and refuses negative limits; a failure paces its
// client for the interval from when it settles, a success clears it, and a
// negative interval turns pacing off.
func TestGovernorPacing(t *testing.T) {
	if _, err := newGovernor(FetchPolicy{MaxFetchesPerMinute: -1}, 10); err == nil || err.Error() != "cimd: FetchPolicy.MaxFetchesPerMinute must be a positive integer" {
		t.Fatal("a negative limit was accepted", err)
	}
	g, err := newGovernor(FetchPolicy{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if p := g.policy; p.MinimumFetchInterval != time.Second || p.MaxConcurrentFetches != 16 || p.MaxConcurrentFetchesPerOrigin != 4 || p.MaxFetchesPerMinute != 120 || p.MaxFetchesPerOriginPerMinute != 30 {
		t.Fatal("wrong defaults", p)
	}
	now := time.Unix(1_000_000, 0)
	release, err := g.acquire("a", "https://a.test", now)
	if err != nil {
		t.Fatal(err)
	}
	release(fetchFailed, now.Add(3*time.Second))
	if _, err := g.acquire("a", "https://a.test", now.Add(3*time.Second+999*time.Millisecond)); err == nil {
		t.Fatal("a failed client was fetched again within the interval")
	} else {
		refusedWith(t, err, "metadata document fetch is within the per-client minimum interval")
	}
	release, err = g.acquire("a", "https://a.test", now.Add(4*time.Second))
	if err != nil {
		t.Fatal("pacing outlived the interval", err)
	}
	release(fetchSucceeded, now.Add(4*time.Second))
	if release, err := g.acquire("a", "https://a.test", now.Add(4*time.Second)); err != nil {
		t.Fatal("a success left pacing behind", err)
	} else {
		release(fetchAtCapacity, now.Add(4*time.Second))
	}
	if release, err := g.acquire("a", "https://a.test", now.Add(4*time.Second)); err != nil {
		t.Fatal("a capacity refusal left pacing behind", err)
	} else {
		release(fetchSucceeded, now.Add(4*time.Second))
	}
	off, _ := newGovernor(FetchPolicy{MinimumFetchInterval: -1}, 10)
	release, _ = off.acquire("a", "https://a.test", now)
	release(fetchFailed, now)
	if _, err := off.acquire("a", "https://a.test", now); err != nil {
		t.Fatal("pacing ran with a negative interval", err)
	}
}

// Concurrency and minute limits, globally and per origin, are refused at
// once and freed by a settled fetch or a rolled window.
func TestGovernorLimits(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	g, _ := newGovernor(FetchPolicy{}, 1000)
	var held []func(fetchOutcome, time.Time)
	for range 4 {
		release, err := g.acquire("c", "https://one.test", now)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, release)
	}
	_, err := g.acquire("c", "https://one.test", now)
	refusedWith(t, err, "metadata fetch concurrency limit exceeded for client origin")
	held[0](fetchSucceeded, now)
	if release, err := g.acquire("c", "https://one.test", now); err != nil {
		t.Fatal("a settled fetch did not free its origin slot", err)
	} else {
		held[0] = release
	}
	for i := range 12 {
		release, err := g.acquire("c", "https://other"+string(rune('a'+i))+".test", now)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, release)
	}
	_, err = g.acquire("x", "https://late.test", now)
	refusedWith(t, err, "global metadata fetch concurrency limit exceeded")
	held[5](fetchFailed, now)
	if _, err := g.acquire("x", "https://late.test", now); err != nil {
		t.Fatal("a failed fetch did not free its global slot", err)
	}
	// Minute windows.
	rate, _ := newGovernor(FetchPolicy{MaxConcurrentFetches: 1000, MaxConcurrentFetchesPerOrigin: 1000}, 1000)
	for i := range 30 {
		release, err := rate.acquire("c", "https://busy.test", now.Add(time.Duration(i)*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		release(fetchSucceeded, now)
	}
	_, err = rate.acquire("c", "https://busy.test", now.Add(time.Second))
	refusedWith(t, err, "metadata fetch rate limit exceeded for client origin")
	for i := range 90 {
		release, err := rate.acquire("c", "https://o"+string(rune('a'+i%26))+string(rune('a'+i/26))+".test", now.Add(time.Second))
		if err != nil {
			t.Fatal(i, err)
		}
		release(fetchSucceeded, now)
	}
	_, err = rate.acquire("c", "https://fresh.test", now.Add(time.Second))
	refusedWith(t, err, "global metadata fetch rate limit exceeded")
	if _, err := rate.acquire("c", "https://busy.test", now.Add(time.Minute+time.Second)); err != nil {
		t.Fatal("the window did not roll", err)
	}
}

// At capacity, live client intervals and live origin budgets are kept and
// refuse newcomers; expired records are evicted.
func TestGovernorCapacity(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	g, _ := newGovernor(FetchPolicy{MinimumFetchInterval: time.Minute}, 2)
	for _, id := range []string{"a", "b"} {
		release, err := g.acquire(id, "https://"+id+".test", now)
		if err != nil {
			t.Fatal(err)
		}
		release(fetchFailed, now)
	}
	_, err := g.acquire("c", "https://a.test", now)
	refusedWith(t, err, "metadata fetch client state is at capacity")
	// A failure settling into a full map of live intervals is not recorded.
	full, _ := newGovernor(FetchPolicy{MinimumFetchInterval: time.Minute}, 2)
	late, err := full.acquire("late", "https://same.test", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b"} {
		release, err := full.acquire(id, "https://same.test", now)
		if err != nil {
			t.Fatal(err)
		}
		release(fetchFailed, now)
	}
	late(fetchFailed, now)
	if len(full.paced) != 2 {
		t.Fatal("the client map outgrew its bound", len(full.paced))
	}
	release, err := g.acquire("c", "https://a.test", now.Add(2*time.Minute))
	if err != nil {
		t.Fatal("an expired client record was not evicted", err)
	}
	release(fetchSucceeded, now.Add(2*time.Minute))
	// Origins with fetches in the window are kept.
	o, _ := newGovernor(FetchPolicy{}, 2)
	for _, origin := range []string{"https://one.test", "https://two.test"} {
		release, err := o.acquire("x", origin, now)
		if err != nil {
			t.Fatal(err)
		}
		release(fetchSucceeded, now)
	}
	_, err = o.acquire("x", "https://three.test", now.Add(time.Second))
	refusedWith(t, err, "metadata fetch origin state is at capacity")
	if _, err := o.acquire("x", "https://three.test", now.Add(2*time.Minute)); err != nil {
		t.Fatal("an idle origin record was not evicted", err)
	}
}
