package oauthprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// The access-token key cache windows another runtime uses: a set is trusted
// for five minutes, a set lacking a token's key is refetched at most every
// 30 seconds, a fetch is awaited for at most five seconds, and an expired
// set serves for up to ten minutes when a refetch fails.
const (
	resourceKeysTTL      = 5 * time.Minute
	resourceKeysCooldown = 30 * time.Second
	resourceKeysMaxStale = 2 * resourceKeysTTL
)

// resourceKeysTimeout bounds one wait for a key fetch; tests shorten it.
var resourceKeysTimeout = 5 * time.Second

var (
	// errInvalidKey means no usable key in the set verifies the token.
	errInvalidKey = errors.New("oauthprovider: no usable key verifies the access token")
	// errKeysUnavailable means the issuer's keys could not be read.
	errKeysUnavailable = errors.New("oauthprovider: the issuer's signing keys are unavailable")
)

// resourceKeySet is one fetched set; a pointer names one fetch.
type resourceKeySet struct {
	keys assertionKeys
	kids []string
}

type resourceKeyFetch struct {
	started time.Time
	done    chan struct{}
	set     *resourceKeySet
	err     error
}

// resourceKeys caches one issuer's signing keys for a verifier, as another
// runtime caches a JWKS source, scoped to the verifier rather than the
// process.
type resourceKeys struct {
	load func(context.Context) (*resourceKeySet, error)
	now  func() time.Time

	mu                     sync.Mutex
	set                    *resourceKeySet
	fetchedAt, refetchedAt time.Time
	pending                *resourceKeyFetch
}

// newResourceKeys reads keys from a JWKS URL, or from source when it is set.
func newResourceKeys(uri string, source func(context.Context) (jose.JSONWebKeySet, error), transport http.RoundTripper) *resourceKeys {
	k := &resourceKeys{now: time.Now}
	if source != nil {
		k.load = func(ctx context.Context) (*resourceKeySet, error) {
			set, err := source(ctx)
			if err != nil {
				return nil, err
			}
			raw, err := json.Marshal(set)
			if err != nil {
				return nil, err
			}
			return decodeResourceKeys(raw)
		}
		return k
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	client := &http.Client{Transport: transport, Timeout: resourceKeysTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	k.load = func(ctx context.Context) (*resourceKeySet, error) {
		raw, _, err := fetchKeySet(ctx, client, uri)
		if err != nil {
			return nil, err
		}
		return decodeResourceKeys(raw)
	}
	return k
}

// decodeResourceKeys reads a JWKS. A set without a keys array, or with a
// member carrying private parameters, is invalid; members that are not
// usable public signing keys are skipped, as another runtime's key filter
// skips them.
func decodeResourceKeys(raw []byte) (*resourceKeySet, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if json.Unmarshal(raw, &doc) != nil || doc.Keys == nil {
		return nil, errors.New("oauthprovider: invalid JWKS")
	}
	set := &resourceKeySet{}
	for _, member := range doc.Keys {
		var fields map[string]json.RawMessage
		if json.Unmarshal(member, &fields) != nil || fields == nil {
			return nil, errors.New("oauthprovider: invalid JWKS")
		}
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, ok := fields[private]; ok {
				return nil, errors.New("oauthprovider: JWKS member carries private parameters")
			}
		}
		var kid string
		if json.Unmarshal(fields["kid"], &kid) == nil && kid != "" {
			set.kids = append(set.kids, kid)
		}
		// A member of an unknown type does not decode, and match skips
		// keys that cannot verify.
		var jwk jose.JSONWebKey
		var operations struct {
			Ops []string `json:"key_ops"`
		}
		if json.Unmarshal(member, &jwk) == nil && json.Unmarshal(member, &operations) == nil {
			set.keys = append(set.keys, assertionKey{jwk, operations.Ops})
		}
	}
	return set, nil
}

// verify checks a token's signature with exactly one usable key.
func (set *resourceKeySet) verify(signed *jose.JSONWebSignature) ([]byte, error) {
	key, count := set.keys.match(signed.Signatures[0].Protected)
	switch {
	case count == 0:
		return nil, errInvalidKey
	case count > 1:
		return nil, errKeysUnavailable
	}
	payload, err := signed.Verify(key.Key)
	if err != nil {
		return nil, errInvalidKey
	}
	return payload, nil
}

// verify returns a token's verified payload. A token without kid whose key
// is missing, or whose signature fails, is retried against a newer set at
// most twice.
func (k *resourceKeys) verify(ctx context.Context, signed *jose.JSONWebSignature) ([]byte, error) {
	kid := signed.Signatures[0].Protected.KeyID
	set, refresh, err := k.resolve(ctx, kid)
	if err != nil {
		return nil, err
	}
	for refreshes := 0; ; refreshes++ {
		payload, err := set.verify(signed)
		if err == nil || !errors.Is(err, errInvalidKey) || kid != "" || refresh == nil || refreshes == 2 {
			return payload, err
		}
		next, rerr := refresh(set)
		if rerr != nil {
			return nil, rerr
		}
		if next == nil {
			return nil, err
		}
		set = next
	}
}

// resolve finds the set to verify a token with, and how to refresh it when
// it fails, as another runtime resolves a cached JWKS.
func (k *resourceKeys) resolve(ctx context.Context, kid string) (*resourceKeySet, func(*resourceKeySet) (*resourceKeySet, error), error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	refresh := func(failed *resourceKeySet) (*resourceKeySet, error) {
		k.mu.Lock()
		defer k.mu.Unlock()
		return k.refresh(ctx, failed)
	}
	// While a stale set serves, a failed refresh leaves the token its own
	// verification error.
	refreshStale := func(failed *resourceKeySet) (*resourceKeySet, error) {
		set, err := refresh(failed)
		if err != nil {
			return nil, nil
		}
		return set, nil
	}
	cached := func(set *resourceKeySet) (*resourceKeySet, func(*resourceKeySet) (*resourceKeySet, error), error) {
		if kid == "" || slices.Contains(set.kids, kid) {
			return set, refresh, nil
		}
		next, err := k.refresh(ctx, set)
		if err != nil {
			return nil, nil, err
		}
		if next == nil {
			next = set
		}
		return next, nil, nil
	}
	// stale is the expired set within the stale window at at, and whether
	// it names the token's key.
	stale := func(at time.Time) (*resourceKeySet, bool) {
		if k.set == nil || at.Sub(k.fetchedAt) >= resourceKeysMaxStale {
			return nil, false
		}
		return k.set, kid == "" || slices.Contains(k.set.kids, kid)
	}
	now := k.now()
	if k.set != nil && now.Sub(k.fetchedAt) < resourceKeysTTL {
		return cached(k.set)
	}
	if set, usable := stale(now); set != nil && now.Sub(k.refetchedAt) < resourceKeysCooldown {
		if usable {
			return set, refreshStale, nil
		}
		// The refetch that could show the key missing failed, so this is
		// an outage; a refetch in flight settles it.
		if !k.fetching(now) {
			return nil, nil, errKeysUnavailable
		}
	}
	set, err := k.fetch(ctx)
	if err == nil {
		return set, nil, nil
	}
	failedAt := k.now()
	k.refetchedAt = failedAt
	// An earlier fetch may have landed meanwhile; each set is judged by
	// the time of its own fetch.
	if k.set != nil && failedAt.Sub(k.fetchedAt) < resourceKeysTTL {
		return cached(k.set)
	}
	if set, usable := stale(failedAt); usable {
		return set, refreshStale, nil
	}
	return nil, nil, errKeysUnavailable
}

// refresh refetches a fresh set that failed a token: it uses a set fetched
// since, or joins a fetch in flight, or else fetches unless a refetch
// started within the cooldown, and returns nil then. The caller holds mu.
func (k *resourceKeys) refresh(ctx context.Context, failed *resourceKeySet) (*resourceKeySet, error) {
	if k.set != failed {
		return k.set, nil
	}
	now := k.now()
	if !k.fetching(now) {
		if now.Sub(k.refetchedAt) < resourceKeysCooldown {
			return nil, nil
		}
		k.refetchedAt = now
	}
	return k.fetch(ctx)
}

// fetching reports a fetch in flight that has not outlived its timeout.
func (k *resourceKeys) fetching(now time.Time) bool {
	return k.pending != nil && now.Sub(k.pending.started) < resourceKeysTimeout
}

// fetch starts a fetch, or joins one in flight, and waits for it until its
// timeout or ctx ends. A landed set replaces the cached one only when its
// fetch started no earlier. The caller holds mu, which fetch releases while
// it waits.
func (k *resourceKeys) fetch(ctx context.Context) (*resourceKeySet, error) {
	now := k.now()
	if !k.fetching(now) {
		f := &resourceKeyFetch{started: now, done: make(chan struct{})}
		k.pending = f
		go func() {
			set, err := k.load(context.WithoutCancel(ctx))
			k.mu.Lock()
			f.set, f.err = set, err
			if err == nil && !f.started.Before(k.fetchedAt) {
				k.set, k.fetchedAt = set, f.started
			}
			if k.pending == f {
				k.pending = nil
			}
			k.mu.Unlock()
			close(f.done)
		}()
	}
	f := k.pending
	k.mu.Unlock()
	defer k.mu.Lock()
	timer := time.NewTimer(f.started.Add(resourceKeysTimeout).Sub(now))
	defer timer.Stop()
	select {
	case <-f.done:
		if f.err != nil {
			return nil, errKeysUnavailable
		}
		return f.set, nil
	case <-timer.C:
		return nil, errKeysUnavailable
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
