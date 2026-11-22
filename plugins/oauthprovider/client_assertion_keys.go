package oauthprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/publicnet"
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

type cachedClientKeys struct {
	keys    assertionKeys
	fetched time.Time
}

type keyFetch struct {
	started time.Time
	done    chan struct{}
	value   *cachedClientKeys
	err     error
}

type clientKeyCache struct {
	http    *http.Client
	mu      sync.Mutex
	sets    map[string]*cachedClientKeys
	pending map[string]*keyFetch
}

func newClientKeyCache(transport http.RoundTripper) *clientKeyCache {
	if transport == nil {
		transport = publicnet.Transport(errFetchKeys)
	}
	return &clientKeyCache{
		http: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		sets: make(map[string]*cachedClientKeys), pending: make(map[string]*keyFetch),
	}
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
	if validateServerURI("jwks_uri", uri, c.Auth) != nil {
		return nil, invalidClient("client jwks_uri is not trusted")
	}
	ctx := c.Request.Context()
	arrival := time.Now()
	set, err := cache.load(ctx, uri, nil, time.Time{})
	if err != nil {
		return nil, invalidClient(errFetchKeys.Error())
	}
	key, count := set.keys.match(h)
	if count == 0 {
		if refreshed, err := cache.load(ctx, uri, set, arrival); err == nil {
			key, count = refreshed.keys.match(h)
		}
	}
	if count != 1 {
		return nil, failedAssertion()
	}
	return key, nil
}

// previous requests a refresh only if another caller has not already replaced that set.
func (cache *clientKeyCache) load(ctx context.Context, uri string, previous *cachedClientKeys, after time.Time) (*cachedClientKeys, error) {
	for {
		cache.mu.Lock()
		cached := cache.sets[uri]
		if cached != nil && cached != previous && !cached.fetched.Before(after) && time.Since(cached.fetched) < clientKeysTTL {
			cache.mu.Unlock()
			return cached, nil
		}
		f := cache.pending[uri]
		if f == nil {
			if len(cache.pending) >= maxClientKeySets {
				cache.mu.Unlock()
				return nil, errFetchKeys
			}
			f = &keyFetch{started: time.Now(), done: make(chan struct{})}
			cache.pending[uri] = f
			go cache.refresh(context.WithoutCancel(ctx), uri, f)
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

func (cache *clientKeyCache) refresh(ctx context.Context, uri string, f *keyFetch) {
	keys, transient, err := cache.fetch(ctx, uri)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	defer close(f.done)
	delete(cache.pending, uri)
	old := cache.sets[uri]
	if err != nil {
		if transient && old != nil && time.Since(old.fetched) < 2*clientKeysTTL {
			f.value = old
			return
		}
		delete(cache.sets, uri)
		f.err = err
		return
	}
	if old == nil && len(cache.sets) >= maxClientKeySets {
		var oldest string
		for uri, v := range cache.sets {
			if oldest == "" || v.fetched.Before(cache.sets[oldest].fetched) {
				oldest = uri
			}
		}
		delete(cache.sets, oldest)
	}
	f.value = &cachedClientKeys{keys, f.started}
	cache.sets[uri] = f.value
}

func (cache *clientKeyCache) fetch(ctx context.Context, uri string) (assertionKeys, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, false, errFetchKeys
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	res, err := cache.http.Do(req)
	if err != nil {
		var netErr net.Error
		transient := errors.As(err, &netErr) && netErr.Timeout()
		var op *net.OpError
		transient = transient || errors.As(err, &op)
		return nil, transient, errFetchKeys
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, res.StatusCode == 408 || res.StatusCode == 429 || res.StatusCode >= 500 && res.StatusCode < 600, errFetchKeys
	}
	media, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || (media != "application/json" && !(strings.HasPrefix(media, "application/") && strings.HasSuffix(media, "+json"))) || res.ContentLength > maxClientKeyBytes {
		return nil, false, errFetchKeys
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxClientKeyBytes+1))
	if err != nil {
		var netErr net.Error
		return nil, errors.As(err, &netErr) && netErr.Timeout(), errFetchKeys
	}
	if len(raw) > maxClientKeyBytes {
		return nil, false, errFetchKeys
	}
	keys, err := decodeAssertionKeys(raw)
	return keys, false, err
}
