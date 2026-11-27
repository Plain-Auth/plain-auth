package oauthprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// issuerKeys serves a JWKS whose keys, status and delay a test changes.
type issuerKeys struct {
	t       *testing.T
	mu      sync.Mutex
	keys    []jose.JSONWebKey
	status  int
	body    string
	hold    chan struct{}
	fetches atomic.Int32
	server  *httptest.Server
}

func newIssuerKeys(t *testing.T) *issuerKeys {
	k := &issuerKeys{t: t, status: 200}
	k.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k.fetches.Add(1)
		k.mu.Lock()
		status, body, hold := k.status, k.body, k.hold
		if body == "" {
			raw, _ := json.Marshal(jose.JSONWebKeySet{Keys: k.keys})
			body = string(raw)
		}
		k.mu.Unlock()
		if hold != nil {
			<-hold
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(k.server.Close)
	return k
}

// publish replaces the served keys with fresh ES256 keys under kids and
// returns their signers.
func (k *issuerKeys) publish(kids ...string) map[string]*ecdsa.PrivateKey {
	signers := map[string]*ecdsa.PrivateKey{}
	var keys []jose.JSONWebKey
	for _, kid := range kids {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			k.t.Fatal(err)
		}
		signers[kid] = key
		keys = append(keys, jose.JSONWebKey{Key: &key.PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"})
	}
	k.mu.Lock()
	k.keys = keys
	k.mu.Unlock()
	return signers
}

func (k *issuerKeys) set(status int, body string) {
	k.mu.Lock()
	k.status, k.body = status, body
	k.mu.Unlock()
}

// signed signs a token with key, naming kid unless it is empty.
func signed(t *testing.T, key *ecdsa.PrivateKey, kid string) *jose.JSONWebSignature {
	t.Helper()
	options := new(jose.SignerOptions)
	if kid != "" {
		options = options.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, options)
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign([]byte(`{"sub":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jose.ParseSigned(compact, assertionAlgorithms)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// The key cache fetches once within its lifetime and again after it;
// refetches a set lacking a token's kid at most once per cooldown, so a
// newly published key verifies after the cooldown; shares one refetch among
// concurrent tokens; and serves an expired set for up to ten minutes when
// a refetch fails, for a known kid or a token without one.
func TestResourceKeyCache(t *testing.T) {
	issuer := newIssuerKeys(t)
	signers := issuer.publish("one")
	keys := newResourceKeys(issuer.server.URL, nil, issuer.server.Client().Transport)
	clock := time.Now()
	var clockMu sync.Mutex
	keys.now = func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return clock }
	advance := func(d time.Duration) { clockMu.Lock(); clock = clock.Add(d); clockMu.Unlock() }
	ctx := t.Context()
	verify := func(key *ecdsa.PrivateKey, kid string) error {
		t.Helper()
		_, err := keys.verify(ctx, signed(t, key, kid))
		return err
	}
	fetches := func(want int32) {
		t.Helper()
		if got := issuer.fetches.Load(); got != want {
			t.Fatalf("wanted %d fetches, got %d", want, got)
		}
	}
	if err := verify(signers["one"], "one"); err != nil {
		t.Fatal(err)
	}
	if err := verify(signers["one"], "one"); err != nil {
		t.Fatal(err)
	}
	fetches(1)
	advance(resourceKeysTTL)
	if err := verify(signers["one"], "one"); err != nil {
		t.Fatal(err)
	}
	fetches(2)
	// Made-up kids refetch at most once per cooldown.
	stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for range 3 {
		if err := verify(stranger, "made-up"); !errors.Is(err, errInvalidKey) {
			t.Fatal("a made-up kid was not refused", err)
		}
	}
	fetches(3)
	// A newly published key verifies after the cooldown.
	rotated := issuer.publish("one", "two")
	if err := verify(rotated["two"], "two"); !errors.Is(err, errInvalidKey) {
		t.Fatal("a new kid verified inside the cooldown", err)
	}
	fetches(3)
	advance(resourceKeysCooldown)
	if err := verify(rotated["two"], "two"); err != nil {
		t.Fatal("a newly published kid did not verify after the cooldown", err)
	}
	fetches(4)
	// Concurrent tokens with a new key share one refetch.
	advance(resourceKeysCooldown)
	issuer.mu.Lock()
	issuer.hold = make(chan struct{})
	issuer.mu.Unlock()
	third := issuer.publish("one", "two", "three")
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Go(func() { errs <- verify(third["three"], "three") })
	}
	for issuer.fetches.Load() < 5 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	issuer.mu.Lock()
	close(issuer.hold)
	issuer.hold = nil
	issuer.mu.Unlock()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal("a concurrent token failed", err)
		}
	}
	fetches(5)
	// A token without kid is retried against a refetched set. With several
	// keys it would match each, which is an outage, as in another runtime.
	issuer = newIssuerKeys(t)
	issuer.publish("old")
	keys = newResourceKeys(issuer.server.URL, nil, issuer.server.Client().Transport)
	keys.now = func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return clock }
	if err := verify(issuer.publish("old")["old"], ""); err != nil {
		t.Fatal(err)
	}
	fourth := issuer.publish("four")
	advance(resourceKeysCooldown)
	if err := verify(fourth["four"], ""); err != nil {
		t.Fatal("a kid-less token was not retried against a new set", err)
	}
	fetches(2)
	// An expired set serves for ten minutes when refetches fail.
	issuer.set(503, "")
	advance(resourceKeysTTL)
	if err := verify(fourth["four"], "four"); err != nil {
		t.Fatal("a stale set did not serve a known kid", err)
	}
	if err := verify(fourth["four"], ""); err != nil {
		t.Fatal("a stale set did not serve a token without kid", err)
	}
	if err := verify(stranger, "unknown"); !errors.Is(err, errKeysUnavailable) {
		t.Fatal("an unknown kid during an outage was not an outage", err)
	}
	advance(resourceKeysMaxStale)
	if err := verify(fourth["four"], "four"); !errors.Is(err, errKeysUnavailable) {
		t.Fatal("a set older than ten minutes served", err)
	}
}

// A cold start or hung fetch fails as an outage; redirects, oversized,
// non-JSON and private sets are refused; encryption keys are skipped; two
// keys matching one token are an outage; and an in-process source is cached
// under the same rules.
func TestResourceKeySources(t *testing.T) {
	ctx := t.Context()
	issuer := newIssuerKeys(t)
	signers := issuer.publish("one")
	issuer.set(500, "")
	keys := newResourceKeys(issuer.server.URL, nil, issuer.server.Client().Transport)
	if _, err := keys.verify(ctx, signed(t, signers["one"], "one")); !errors.Is(err, errKeysUnavailable) {
		t.Fatal("a cold-start failure was not an outage", err)
	}
	// A hung fetch returns after the timeout.
	saved := resourceKeysTimeout
	resourceKeysTimeout = 50 * time.Millisecond
	t.Cleanup(func() { resourceKeysTimeout = saved })
	issuer.set(200, "")
	issuer.mu.Lock()
	issuer.hold = make(chan struct{})
	issuer.mu.Unlock()
	keys = newResourceKeys(issuer.server.URL, nil, issuer.server.Client().Transport)
	started := time.Now()
	if _, err := keys.verify(ctx, signed(t, signers["one"], "one")); !errors.Is(err, errKeysUnavailable) || time.Since(started) > 2*time.Second {
		t.Fatal("a hung fetch did not time out", err)
	}
	issuer.mu.Lock()
	close(issuer.hold)
	issuer.hold = nil
	issuer.mu.Unlock()
	resourceKeysTimeout = saved
	// Refused documents.
	public, _ := json.Marshal(jose.JSONWebKey{Key: &signers["one"].PublicKey, KeyID: "one", Algorithm: "ES256"})
	private, _ := json.Marshal(jose.JSONWebKey{Key: signers["one"], KeyID: "one", Algorithm: "ES256"})
	for name, body := range map[string]string{
		"no keys":  `{"other":[]}`,
		"private":  `{"keys":[` + string(private) + `]}`,
		"oversize": `{"keys":[` + string(public) + `],"pad":"` + strings.Repeat("x", maxClientKeyBytes) + `"}`,
	} {
		issuer.set(200, body)
		keys = newResourceKeys(issuer.server.URL, nil, issuer.server.Client().Transport)
		if _, err := keys.verify(ctx, signed(t, signers["one"], "one")); !errors.Is(err, errKeysUnavailable) {
			t.Error("a refused key set was used", name, err)
		}
	}
	redirect := httptest.NewTLSServer(http.RedirectHandler(issuer.server.URL, http.StatusFound))
	t.Cleanup(redirect.Close)
	issuer.set(200, "")
	keys = newResourceKeys(redirect.URL, nil, redirect.Client().Transport)
	if _, err := keys.verify(ctx, signed(t, signers["one"], "one")); !errors.Is(err, errKeysUnavailable) {
		t.Fatal("a redirect was followed", err)
	}
	// An encryption key is skipped, and two matching keys are an outage.
	encryption, _ := json.Marshal(jose.JSONWebKey{Key: &signers["one"].PublicKey, KeyID: "one", Algorithm: "ES256", Use: "enc"})
	issuer.set(200, `{"keys":[`+string(encryption)+`]}`)
	keys = newResourceKeys(issuer.server.URL, nil, issuer.server.Client().Transport)
	if _, err := keys.verify(ctx, signed(t, signers["one"], "one")); !errors.Is(err, errInvalidKey) {
		t.Fatal("an encryption key verified", err)
	}
	issuer.set(200, `{"keys":[`+string(public)+`,`+string(public)+`]}`)
	keys = newResourceKeys(issuer.server.URL, nil, issuer.server.Client().Transport)
	if _, err := keys.verify(ctx, signed(t, signers["one"], "one")); !errors.Is(err, errKeysUnavailable) {
		t.Fatal("two matching keys were not an outage", err)
	}
	// An in-process source is cached.
	var loads atomic.Int32
	keys = newResourceKeys("", func(context.Context) (jose.JSONWebKeySet, error) {
		loads.Add(1)
		return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &signers["one"].PublicKey, KeyID: "one", Algorithm: "ES256"}}}, nil
	}, nil)
	for range 3 {
		if _, err := keys.verify(ctx, signed(t, signers["one"], "one")); err != nil {
			t.Fatal(err)
		}
	}
	if loads.Load() != 1 {
		t.Fatal("an in-process source was not cached", loads.Load())
	}
}

// A hung in-process source times out; a fetch that lands after a newer one
// does not replace its set; and a refresh of a set already replaced uses
// the newer set without fetching, even inside the cooldown.
func TestResourceKeyFetchOrder(t *testing.T) {
	ctx := t.Context()
	issuer := newIssuerKeys(t)
	first := issuer.publish("one")["one"]
	second := issuer.publish("two")["two"]
	set := func(kid string, key *ecdsa.PrivateKey) jose.JSONWebKeySet {
		return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: kid, Algorithm: "ES256"}}}
	}
	saved := resourceKeysTimeout
	resourceKeysTimeout = 50 * time.Millisecond
	t.Cleanup(func() { resourceKeysTimeout = saved })
	release := make(chan struct{})
	var calls atomic.Int32
	keys := newResourceKeys("", func(context.Context) (jose.JSONWebKeySet, error) {
		if calls.Add(1) == 1 {
			<-release // the first fetch hangs, then lands last
			return set("one", first), nil
		}
		return set("two", second), nil
	}, nil)
	started := time.Now()
	if _, err := keys.verify(ctx, signed(t, first, "one")); !errors.Is(err, errKeysUnavailable) || time.Since(started) > 2*time.Second {
		t.Fatal("a hung source did not time out", err)
	}
	time.Sleep(resourceKeysTimeout)
	if _, err := keys.verify(ctx, signed(t, second, "two")); err != nil {
		t.Fatal("a fetch after a dead one failed", err)
	}
	close(release)
	for {
		keys.mu.Lock()
		done := keys.pending == nil
		keys.mu.Unlock()
		if done {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := keys.verify(ctx, signed(t, second, "two")); err != nil {
		t.Fatal("a late fetch replaced a newer set", err)
	}
	// A refresh of a replaced set uses the newer one without fetching.
	keys.mu.Lock()
	old := keys.set
	newer := &resourceKeySet{kids: []string{"three"}}
	keys.set, keys.refetchedAt = newer, keys.now()
	got, err := keys.refresh(ctx, old)
	keys.mu.Unlock()
	if err != nil || got != newer {
		t.Fatal("a refresh of a replaced set did not use the newer one", got, err)
	}
}
