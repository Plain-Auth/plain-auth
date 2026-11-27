package oauthprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/publicnet"
	jose "github.com/go-jose/go-jose/v4"
)

type assertionKey struct {
	jwk        jose.JSONWebKey
	operations []string
}

type assertionKeys []assertionKey

func decodeAssertionKeys(raw []byte) (assertionKeys, error) {
	if err := ValidatePublicClientJWKS(raw); err != nil {
		return nil, err
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, err
	}
	keys := make(assertionKeys, 0, len(set.Keys))
	for _, raw := range set.Keys {
		var jwk jose.JSONWebKey
		var operations struct {
			Ops []string `json:"key_ops"`
		}
		if json.Unmarshal(raw, &jwk) != nil || !jwk.IsPublic() || !jwk.Valid() || json.Unmarshal(raw, &operations) != nil {
			return nil, errors.New("invalid assertion verification key")
		}
		keys = append(keys, assertionKey{jwk, operations.Ops})
	}
	return keys, nil
}

func (keys assertionKeys) match(h jose.Header) (*jose.JSONWebKey, int) {
	var match *jose.JSONWebKey
	count := 0
	for i := range keys {
		entry := &keys[i]
		key := &entry.jwk
		if (h.KeyID != "" && key.KeyID != h.KeyID) || !allowsVerificationKey(key, h.Algorithm, entry.operations) {
			continue
		}

		match = key
		count++
	}
	return match, count
}

func allowsVerificationKey(key *jose.JSONWebKey, alg string, operations []string) bool {
	if (key.Algorithm != "" && key.Algorithm != alg) || (key.Use != "" && key.Use != "sig") || (operations != nil && !slices.Contains(operations, "verify")) {
		return false
	}
	switch v := key.Key.(type) {
	case *rsa.PublicKey:
		if v.N.BitLen() < 2048 || (!strings.HasPrefix(alg, "RS") && !strings.HasPrefix(alg, "PS")) {
			return false
		}
	case *ecdsa.PublicKey:
		if map[int]string{256: "ES256", 384: "ES384", 521: "ES512"}[v.Params().BitSize] != alg {
			return false
		}
	case ed25519.PublicKey:
		if alg != "EdDSA" {
			return false
		}
	default:
		return false
	}
	return true
}

const (
	clientKeysTTL     = 5 * time.Minute
	maxClientKeySets  = 500
	maxClientKeyBytes = 64 << 10
)

var errFetchKeys = errors.New("failed to fetch client JWKS")

// keyFetchTimeout bounds a key set fetch, headers and body; tests shorten it.
var keyFetchTimeout = 5 * time.Second

type cachedClientKeys struct {
	keys    assertionKeys
	fetched time.Time
	// retry paces refetches while the set answers after a failed refresh.
	retry time.Time
	// When the last transient failure happened, and whether a refused
	// response stopped a discovery's stale answers until a fetch succeeds.
	transient time.Time
	terminal  bool
}

// keyFailure classifies a failed key fetch: a transient failure may pass on
// retry, a transport failure retrieved nothing, a capacity refusal says
// nothing about the keys, and a terminal one retrieved a response and
// refused it.
type keyFailure int

const (
	keyTerminal keyFailure = iota
	keyTransient
	keyTransport
	keyCapacity
)

// keySource is where a client's remote keys come from: the cache key, which
// separates a discovery's clients from managed ones, the fetching client,
// and how long a discovery's keys may answer through transient failures.
type keySource struct {
	key, uri, clientID string
	http               *http.Client
	stale              time.Duration
	logger             *slog.Logger
}

type keyFetch struct {
	started time.Time
	done    chan struct{}
	value   *cachedClientKeys
	err     error
}

type clientKeyCache struct {
	http        *http.Client
	discoveries map[string]*ClientDiscovery
	mu          sync.Mutex
	sets        map[string]*cachedClientKeys
	pending     map[string]*keyFetch
}

// keyClient fetches key sets without following redirects; fetchKeySet
// bounds each fetch with a context deadline, which a custom transport must
// honour.
func keyClient(transport http.RoundTripper) *http.Client {
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func newClientKeyCache(transport http.RoundTripper, discoveries []*ClientDiscovery) *clientKeyCache {
	if transport == nil {
		transport = publicnet.Transport(errFetchKeys)
	}
	cache := &clientKeyCache{http: keyClient(transport), discoveries: map[string]*ClientDiscovery{},
		sets: make(map[string]*cachedClientKeys), pending: make(map[string]*keyFetch)}
	for _, d := range discoveries {
		cache.discoveries[d.ID] = d
	}
	return cache
}

func (cache *clientKeyCache) verificationKey(c auth.EndpointContext, client MachineClient, h jose.Header) (*jose.JSONWebKey, error) {
	if client.JWKS != "" {
		keys, err := decodeAssertionKeys([]byte(client.JWKS))
		if err == nil {
			if key, count := keys.match(h); count == 1 {
				return key, nil
			}
		}
		return nil, failedAssertion()
	}
	uri := client.JWKSURI
	if uri == "" {
		return nil, invalidClient("client has no JWKS configured")
	}
	ctx := c.Request.Context()
	src := keySource{key: "managed:" + uri, uri: uri, clientID: client.ClientID, http: cache.http, logger: c.Auth.Logger()}
	if id := ResolvedDiscovery(ctx, client.ClientID); id == "" {
		if validateServerURI("jwks_uri", uri, c.Auth) != nil {
			return nil, invalidClient("client jwks_uri is not trusted")
		}
	} else {
		// A discovered client's keys may live on its client ID's origin or
		// where its discovery allows, and are fetched through the discovery.
		d := cache.discoveries[id]
		if d == nil || publicServerURI("jwks_uri", uri, c.Auth) != nil ||
			!c.Auth.ExplicitlyTrustedOrigin(uri) && !sameOrigin(client.ClientID, uri) && !d.allowsJWKSURI(ctx, c.Auth, client.ClientID, uri) {
			return nil, invalidClient("client jwks_uri is not trusted")
		}
		if d.Transport == nil {
			return nil, invalidClient("client discovery does not provide a metadata resource transport")
		}
		src.key, src.http, src.stale = id+":"+uri, keyClient(d.Transport), d.JWKSStaleIfError
	}
	arrival := time.Now()
	set, err := cache.load(ctx, src, nil, time.Time{})
	if err != nil {
		return nil, invalidClient(errFetchKeys.Error())
	}
	key, count := set.keys.match(h)
	if count == 0 {
		if refreshed, err := cache.load(ctx, src, set, arrival); err == nil {
			key, count = refreshed.keys.match(h)
		}
	}
	if count != 1 {
		return nil, failedAssertion()
	}
	return key, nil
}

// previous requests a refresh only if another caller has not already replaced that set.
func (cache *clientKeyCache) load(ctx context.Context, src keySource, previous *cachedClientKeys, after time.Time) (*cachedClientKeys, error) {
	for {
		cache.mu.Lock()
		cached := cache.sets[src.key]
		if cached != nil && cached != previous && !cached.fetched.Before(after) && (time.Since(cached.fetched) < clientKeysTTL || time.Now().Before(cached.retry)) {
			cache.mu.Unlock()
			return cached, nil
		}
		f := cache.pending[src.key]
		if f == nil {
			if len(cache.pending) >= maxClientKeySets {
				cache.mu.Unlock()
				return nil, errFetchKeys
			}
			f = &keyFetch{started: time.Now(), done: make(chan struct{})}
			cache.pending[src.key] = f
			go cache.refresh(context.WithoutCancel(ctx), src, f)
		}
		cache.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-f.done:
			// A fetch that predates a missing key may have missed its publication.
			if !f.started.Before(after) {
				return f.value, f.err
			}
		}
	}
}

// refresh replaces a set. A failure leaves the set answering for twice its
// lifetime unless the response was an invalid key set; while it answers,
// refetches wait a minute. A discovery's keys also answer up to its
// JWKSStaleIfError after the last success through a transient failure, and
// through a capacity refusal within five minutes of one, unless a refused
// response came since, as in another runtime. A refused response past twice
// the lifetime, or an invalid key set, drops the set; any other failure
// keeps it for a later fetch.
func (cache *clientKeyCache) refresh(ctx context.Context, src keySource, f *keyFetch) {
	keys, kind, invalid, err := cache.fetch(ctx, src)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	defer close(f.done)
	delete(cache.pending, src.key)
	old := cache.sets[src.key]
	if err != nil && old != nil {
		now := time.Now()
		// Each outcome is recorded, as another runtime records it for a
		// discovery: a transient failure's time, a refused response that
		// ends stale answers until a fetch succeeds, and a transport failure
		// that ends the transient record; a capacity refusal records
		// nothing.
		switch kind {
		case keyTransient:
			old.transient = now
		case keyTransport:
			old.transient = time.Time{}
		case keyTerminal:
			old.terminal = true
		}
		age := now.Sub(old.fetched)
		stale := !old.terminal && age < src.stale
		switch {
		case !invalid && age < 2*clientKeysTTL:
		case stale && kind == keyTransient, stale && kind == keyCapacity && now.Sub(old.transient) <= 5*time.Minute:
			src.logger.WarnContext(ctx, "oauth-provider is verifying client "+src.clientID+" with cached keys from "+src.uri+" because refreshing them failed: "+err.Error())
		default:
			if kind == keyTerminal {
				delete(cache.sets, src.key)
			}
			f.err = err
			return
		}
		old.retry = now.Add(time.Minute)
		f.value = old
		return
	}
	if err != nil {
		f.err = err
		return
	}
	if old == nil && len(cache.sets) >= maxClientKeySets {
		var oldest string
		for key, v := range cache.sets {
			if oldest == "" || v.fetched.Before(cache.sets[oldest].fetched) {
				oldest = key
			}
		}
		delete(cache.sets, oldest)
	}
	f.value = &cachedClientKeys{keys: keys, fetched: f.started}
	cache.sets[src.key] = f.value
}

// fetch reads a key set and classifies a failure, reporting whether the
// response was an invalid key set.
func (cache *clientKeyCache) fetch(ctx context.Context, src keySource) (assertionKeys, keyFailure, bool, error) {
	raw, kind, err := fetchKeySet(ctx, src.http, src.uri)
	if err != nil {
		return nil, kind, false, err
	}
	keys, err := decodeAssertionKeys(raw)
	if err != nil {
		return nil, keyTerminal, true, fmt.Errorf("%w: invalid key set", errFetchKeys)
	}
	return keys, 0, false, nil
}

// fetchKeySet reads a JWKS document in five seconds: status 200, a JSON
// media type and at most 64 KiB. A failure is transient for a 500, 502, 503
// or 504 answer, a timeout or a connection failure, a capacity refusal when
// the transport wraps ErrFetchCapacity, a transport failure for another one
// that retrieved nothing, such as a lookup the deadline ended, and terminal
// for a response it refuses.
func fetchKeySet(ctx context.Context, client *http.Client, uri string) ([]byte, keyFailure, error) {
	ctx, cancel := context.WithTimeout(ctx, keyFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, keyTerminal, errFetchKeys
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	classify := func(err error) keyFailure {
		switch {
		case errors.Is(err, ErrFetchCapacity):
			return keyCapacity
		case publicnet.Transient(err):
			return keyTransient
		}
		return keyTransport
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, classify(err), fmt.Errorf("%w: %w", errFetchKeys, err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		kind := keyTerminal
		if res.StatusCode == 500 || res.StatusCode == 502 || res.StatusCode == 503 || res.StatusCode == 504 {
			kind = keyTransient
		}
		return nil, kind, fmt.Errorf("%w: status %d", errFetchKeys, res.StatusCode)
	}
	media, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || (media != "application/json" && !(strings.HasPrefix(media, "application/") && strings.HasSuffix(media, "+json"))) {
		return nil, keyTerminal, fmt.Errorf("%w: media type %q", errFetchKeys, res.Header.Get("Content-Type"))
	}
	if res.ContentLength > maxClientKeyBytes {
		return nil, keyTerminal, fmt.Errorf("%w: too large", errFetchKeys)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxClientKeyBytes+1))
	if err != nil {
		return nil, classify(err), fmt.Errorf("%w: %w", errFetchKeys, err)
	}
	if len(raw) > maxClientKeyBytes {
		return nil, keyTerminal, fmt.Errorf("%w: too large", errFetchKeys)
	}
	return raw, 0, nil
}
