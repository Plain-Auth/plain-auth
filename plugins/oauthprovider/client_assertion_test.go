package oauthprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	jose "github.com/go-jose/go-jose/v4"
)

func TestAssertionLifetimeAndClockTolerance(t *testing.T) {
	const base = int64(1800000000)
	now := time.Unix(base, 0)
	check := func(opts AssertionOptions, overrides map[string]any) (time.Time, error) {
		t.Helper()
		if err := opts.defaults(); err != nil {
			t.Fatal(err)
		}
		claims := map[string]any{"iss": "id", "sub": "id", "aud": "endpoint", "jti": "unique", "exp": base + 1}
		for k, v := range overrides {
			claims[k] = v
		}
		raw, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		_, expiry, err := opts.checkClaims(raw, "id", now, "endpoint", "issuer")
		return expiry, err
	}
	for _, tc := range []struct {
		opts   AssertionOptions
		claims map[string]any
		status int
	}{
		{AssertionOptions{}, map[string]any{"exp": base + 300, "iat": base - 300, "nbf": base}, 0},
		{AssertionOptions{}, map[string]any{"exp": base + 301}, 400},
		{AssertionOptions{}, map[string]any{"iat": base - 301}, 400},
		{AssertionOptions{}, map[string]any{"nbf": base + 1}, 401},
		{AssertionOptions{}, map[string]any{"exp": base}, 401},
		{AssertionOptions{}, map[string]any{"exp": "today"}, 401},
		{AssertionOptions{}, map[string]any{"iat": nil}, 401},
		{AssertionOptions{}, map[string]any{"jti": 2}, 400},
		{AssertionOptions{MaxLifetime: 20 * time.Second, ClockTolerance: 5 * time.Second}, map[string]any{"exp": base + 25, "iat": base - 25, "nbf": base + 5}, 0},
		{AssertionOptions{MaxLifetime: 20 * time.Second, ClockTolerance: 5 * time.Second}, map[string]any{"exp": base + 26}, 400},
		{AssertionOptions{MaxLifetime: 20 * time.Second, ClockTolerance: 5 * time.Second}, map[string]any{"iat": base - 26}, 400},
		{AssertionOptions{ClockTolerance: -time.Minute}, map[string]any{"exp": base}, 401},
		{AssertionOptions{ClockTolerance: 2 * time.Minute}, map[string]any{"nbf": base + 61}, 401},
		{AssertionOptions{ClockTolerance: 2 * time.Minute}, map[string]any{"nbf": base + 60, "exp": base - 59}, 0},
		{AssertionOptions{ClockTolerance: 2 * time.Minute}, map[string]any{"exp": base - 60}, 401},
	} {
		_, err := check(tc.opts, tc.claims)
		var oe *auth.OAuthError
		if (err != nil) != (tc.status != 0) || err != nil && (!errors.As(err, &oe) || oe.Status != tc.status) {
			t.Fatalf("claims=%v got %v, want %d", tc.claims, err, tc.status)
		}
	}
	expiry, err := check(AssertionOptions{ClockTolerance: 10 * time.Second}, map[string]any{"exp": float64(base) + 0.5})
	if err != nil || !expiry.Equal(now.Add(10500*time.Millisecond)) {
		t.Fatal("fractional replay expiry including tolerance", expiry, err)
	}
	if _, err := New(Options{Assertions: AssertionOptions{MaxLifetime: -time.Second}}); err == nil {
		t.Fatal("accepted negative assertion lifetime")
	}
}

func TestClientAssertionSigningAlgorithms(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range assertionAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			var key any = rsaKey
			switch algorithm {
			case jose.EdDSA:
				key = edKey
			case jose.ES256, jose.ES384, jose.ES512:
				curve := map[jose.SignatureAlgorithm]elliptic.Curve{jose.ES256: elliptic.P256(), jose.ES384: elliptic.P384(), jose.ES512: elliptic.P521()}[algorithm]
				ec, err := ecdsa.GenerateKey(curve, rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				key = ec
			}
			public := (&jose.JSONWebKey{Key: key, Use: "sig", KeyID: "local"}).Public()
			raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{public}})
			if err != nil {
				t.Fatal(err)
			}
			keys, err := decodeAssertionKeys(raw)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: key}, nil)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := signer.Sign([]byte(`{"sub":"id"}`))
			if err != nil {
				t.Fatal(err)
			}
			compact, err := signed.CompactSerialize()
			if err != nil {
				t.Fatal(err)
			}
			in, err := parseClientAssertion(ClientAssertionType, compact, "id")
			if err != nil {
				t.Fatal(err)
			}
			h := in.token.Signatures[0].Protected
			selected, count := keys.match(h)
			if count != 1 {
				t.Fatal("expected one compatible key")
			}
			if _, err := in.token.Verify(selected.Key); err != nil {
				t.Fatal(err)
			}
			if _, n := append(keys, keys...).match(h); n != 2 {
				t.Fatal("ambiguous signature key accepted")
			}
			for _, edit := range []func(*assertionKey){
				func(k *assertionKey) { k.operations = []string{"sign"} },
				func(k *assertionKey) { k.jwk.Use = "enc" },
				func(k *assertionKey) { k.jwk.Algorithm = "unregistered" },
			} {
				copy := keys[0]
				edit(&copy)
				if _, n := (assertionKeys{copy}).match(h); n != 0 {
					t.Fatal("key restrictions ignored")
				}
			}
			h.KeyID = "missing"
			if _, n := keys.match(h); n != 0 {
				t.Fatal("kid ignored")
			}
		})
	}
}

type assertionTransport func(*http.Request) (*http.Response, error)

func (fn assertionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func TestRemoteAssertionKeyRotation(t *testing.T) {
	const uri = "https://keys.example.test/jwks"
	host, err := auth.New(auth.Options{Store: memory.New(), BaseURL: "https://auth.example.test", Secret: strings.Repeat("s", 40), TrustedOrigins: []string{"https://keys.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	c := auth.EndpointContext{Auth: host, Request: httptest.NewRequest(http.MethodPost, "https://auth.example.test/api/auth/oauth2/token", nil)}
	body := func(kid string) string {
		t.Helper()
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		v, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, KeyID: kid, Algorithm: "EdDSA"}}})
		if err != nil {
			t.Fatal(err)
		}
		return string(v)
	}
	old, newSet := body("old"), body("new")
	status, media, document := 200, "application/jwk-set+json", old
	var calls atomic.Int32
	cache := newClientKeyCache(assertionTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.String() != uri || r.Method != "GET" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			return nil, errors.New("unexpected outbound request")
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {media}}, Body: io.NopCloser(strings.NewReader(document)), ContentLength: -1}, nil
	}), nil)
	key := func(uri, kid string) error {
		_, err := cache.verificationKey(c, MachineClient{JWKSURI: uri}, jose.Header{KeyID: kid, Algorithm: "EdDSA"})
		return err
	}
	if err := key(uri, "old"); err != nil {
		t.Fatal(err)
	}
	if err := key(uri, "old"); err != nil || calls.Load() != 1 {
		t.Fatal("cached lookup", err, calls.Load())
	}
	document = newSet
	if err := key(uri, "new"); err != nil || calls.Load() != 2 {
		t.Fatal("new kid refresh", err, calls.Load())
	}
	for _, raw := range []string{"http://keys.example.test/jwks", "https://other.example.test/key", "https://127.0.0.1/jwks", uri + "#fragment"} {
		if err := key(raw, "new"); err == nil {
			t.Fatal("accepted untrusted URI", raw)
		}
	}
	if calls.Load() != 2 {
		t.Fatal("fetched an untrusted URI")
	}
	age := func(d time.Duration) {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		cache.sets["managed:"+uri].fetched = time.Now().Add(-d)
		cache.sets["managed:"+uri].retry = time.Time{}
	}
	age(6 * time.Minute)
	status = 503
	if err := key(uri, "new"); err != nil {
		t.Fatal("cached key on transient failure", err)
	}
	// While the set answers after a failure, refetches wait a minute.
	before := calls.Load()
	if err := key(uri, "new"); err != nil || calls.Load() != before {
		t.Fatal("a failed refresh was retried at once", err, calls.Load()-before)
	}
	age(11 * time.Minute)
	if err := key(uri, "new"); err == nil {
		t.Fatal("used a key beyond the stale limit")
	}
	// Within twice the lifetime, any failure but an invalid key set leaves
	// the cached set answering.
	for _, tc := range []struct {
		status      int
		media, data string
		invalid     bool
	}{
		{410, "application/json", old, false}, {302, "application/json", old, false}, {200, "text/plain", old, false},
		{200, "application/json", `{"keys":[]}`, true}, {200, "application/json", strings.Repeat(" ", 70<<10) + old, false},
	} {
		cache.mu.Lock()
		delete(cache.sets, "managed:"+uri)
		cache.mu.Unlock()
		status, media, document = 200, "application/json", old
		if err := key(uri, "old"); err != nil {
			t.Fatal(err)
		}
		age(6 * time.Minute)
		status, media, document = tc.status, tc.media, tc.data
		if err := key(uri, "old"); (err == nil) == tc.invalid {
			t.Fatal("the cached set answered wrongly after a failed refresh", tc.status, tc.media, tc.invalid, err)
		}
		if !tc.invalid {
			// Beyond twice the lifetime only a discovery's stale bound keeps it.
			age(11 * time.Minute)
			if err := key(uri, "old"); err == nil {
				t.Fatal("served keys beyond twice their lifetime", tc.status)
			}
		}
		status = 503
		if err := key(uri, "old"); err == nil {
			t.Fatal("resurrected discarded keys")
		}
	}
}

// A discovered client's keys are cached apart from a managed client's at the
// same URI and fetched through its discovery's transport; they may live on
// the client ID's origin or where the discovery allows; a discovery without
// a transport refuses; and its JWKSStaleIfError keeps cached keys through
// transient failures beyond twice their lifetime, with a warning, until a
// terminal failure.
func TestDiscoveredClientKeys(t *testing.T) {
	const id = "https://app.example.test/client.json"
	const uri = "https://app.example.test/jwks"
	var logs strings.Builder
	host, err := auth.New(auth.Options{Store: memory.New(), BaseURL: "https://auth.example.test", Secret: strings.Repeat("s", 40), TrustedOrigins: []string{"https://trusted.example.test"},
		Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, KeyID: "k", Algorithm: "EdDSA"}}})
	if err != nil {
		t.Fatal(err)
	}
	status := 200
	var managed, discovered atomic.Int32
	serve := func(counter *atomic.Int32) assertionTransport {
		return func(r *http.Request) (*http.Response, error) {
			counter.Add(1)
			return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
		}
	}
	allow := map[string]bool{"https://cdn.example.test/allowed": true, "https://10.0.0.1/allowed": true}
	d := &ClientDiscovery{ID: "cimd", Transport: serve(&discovered), JWKSStaleIfError: time.Hour, AllowCrossOriginJWKSURI: func(_ context.Context, _, jwksURI string) (bool, error) {
		if strings.Contains(jwksURI, "broken") {
			return false, errors.New("hook down")
		}
		return allow[jwksURI], nil
	}}
	bare := &ClientDiscovery{ID: "bare"}
	cache := newClientKeyCache(serve(&managed), []*ClientDiscovery{d, bare})
	request := func(discovery string) auth.EndpointContext {
		r := httptest.NewRequest(http.MethodPost, "https://auth.example.test/api/auth/oauth2/token", nil)
		if discovery != "" {
			r = r.WithContext(withResolvedDiscovery(r.Context(), id, discovery))
		}
		return auth.EndpointContext{Auth: host, Request: r}
	}
	key := func(discovery, jwksURI string) error {
		_, err := cache.verificationKey(request(discovery), MachineClient{ClientID: id, JWKSURI: jwksURI}, jose.Header{KeyID: "k", Algorithm: "EdDSA"})
		return err
	}
	const trusted = "https://trusted.example.test/jwks"
	if err := key("cimd", trusted); err != nil || discovered.Load() != 1 || managed.Load() != 0 {
		t.Fatal("a discovered client's keys were not fetched through its discovery", err, discovered.Load(), managed.Load())
	}
	if err := key("", trusted); err != nil || managed.Load() != 1 {
		t.Fatal("a managed client shared the discovered client's keys", err, managed.Load())
	}
	// On its client ID's origin, a discovered client's jwks_uri needs no trust.
	if err := key("cimd", uri); err != nil || discovered.Load() != 2 {
		t.Fatal("a same-origin jwks_uri was refused", err)
	}
	if err := key("", uri); err == nil {
		t.Fatal("a managed client's untrusted jwks_uri was accepted")
	}
	// The jwks_uri rule.
	if err := key("cimd", "https://cdn.example.test/allowed"); err != nil {
		t.Fatal("an allowed cross-origin jwks_uri was refused", err)
	}
	for _, refused := range []string{"https://cdn.example.test/denied", "https://cdn.example.test/broken", "https://10.0.0.1/allowed"} {
		var oauthErr *auth.OAuthError
		if err := key("cimd", refused); !errors.As(err, &oauthErr) || oauthErr.Description != "client jwks_uri is not trusted" {
			t.Fatal("an untrusted jwks_uri was accepted", refused, err)
		}
	}
	if !strings.Contains(logs.String(), "AllowCrossOriginJWKSURI failed") {
		t.Fatal("the hook failure was not logged", logs.String())
	}
	var oauthErr *auth.OAuthError
	if err := key("bare", uri); !errors.As(err, &oauthErr) || oauthErr.Description != "client discovery does not provide a metadata resource transport" {
		t.Fatal("a discovery without a transport fetched keys", err)
	}
	// Beyond twice the lifetime, a transient failure within the stale bound
	// keeps the keys, with a warning; a terminal one drops them.
	age := func(d time.Duration) {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		cache.sets["cimd:"+uri].fetched = time.Now().Add(-d)
		cache.sets["cimd:"+uri].retry = time.Time{}
	}
	for _, transient := range []int{500, 502, 504, 503} {
		age(30 * time.Minute)
		status = transient
		if err := key("cimd", uri); err != nil || !strings.Contains(logs.String(), "is verifying client "+id+" with cached keys from "+uri+" because refreshing them failed") {
			t.Fatal("a discovery's stale bound did not keep the keys", transient, err, logs.String())
		}
	}
	fetches := discovered.Load()
	if err := key("cimd", uri); err != nil || discovered.Load() != fetches {
		t.Fatal("stale keys were refetched within a minute", err)
	}
	age(2 * time.Hour)
	if err := key("cimd", uri); err == nil {
		t.Fatal("keys were served beyond the stale bound")
	}
	status = 200
	if err := key("cimd", uri); err != nil {
		t.Fatal(err)
	}
	for _, terminal := range []int{404, 501} {
		status = 200
		if err := key("cimd", uri); err != nil {
			t.Fatal(err)
		}
		age(30 * time.Minute)
		status = terminal
		if err := key("cimd", uri); err == nil {
			t.Fatal("a terminal failure served stale keys", terminal)
		}
		status = 503
		if err := key("cimd", uri); err == nil {
			t.Fatal("stale keys returned after a terminal failure", terminal)
		}
	}
	// The stale bound is never negative and at most a day.
	never := func(string) bool { return false }
	resolve := func(context.Context, DiscoveryRequest) (*DiscoveredClient, error) { return nil, nil }
	bounded := Options{Extensions: []Extension{{ClientDiscoveries: []ClientDiscovery{{ID: "low", Matches: never, Resolve: resolve, JWKSStaleIfError: -time.Hour},
		{ID: "high", Matches: never, Resolve: resolve, JWKSStaleIfError: 48 * time.Hour}}}}}
	if err := bounded.collectDiscoveries(); err != nil || bounded.discoveries[0].JWKSStaleIfError != 0 || bounded.discoveries[1].JWKSStaleIfError != 24*time.Hour {
		t.Fatal("the stale bound was not clamped", err)
	}
}

func TestClientKeyFetchSharesRequestsAndRespectsCancellation(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub}}})
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	cache := newClientKeyCache(assertionTransport(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	}), nil)
	const uri = "https://keys.example.test/public"
	src := keySource{key: uri, uri: uri, http: cache.http, logger: slog.Default()}
	ctx, cancel := context.WithCancel(t.Context())
	first := make(chan error, 1)
	go func() { _, err := cache.load(ctx, src, nil, time.Time{}); first <- err }()
	<-started
	results := make(chan error, 8)
	for range 8 {
		go func() { _, err := cache.load(t.Context(), src, nil, time.Time{}); results <- err }()
	}
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatal("canceled waiter", err)
	}
	close(release)
	for range 8 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("duplicate remote fetches", calls.Load())
	}
}

// reservedDigests is a ClientAssertionReplayStore in memory.
type reservedDigests map[string]time.Time

func (r reservedDigests) ReserveOAuthClientAssertion(_ context.Context, digest string, expires time.Time) error {
	if _, ok := r[digest]; ok {
		return ErrAssertionReplay
	}
	r[digest] = expires
	return nil
}

// ConsumeClientAssertion refuses a wrong audience, a missing, expired or
// distant exp, an old iat, a future nbf, a missing jti and an empty
// namespace; it spends a jti once per namespace, and private_key_jwt's
// digest is the one for namespace "private_key_jwt:<client>".
func TestConsumeClientAssertion(t *testing.T) {
	const audience = "https://issuer.example.test/api/auth/oauth2/token"
	limits := AssertionOptions{ClockTolerance: 30 * time.Second}
	if err := limits.defaults(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	payload := func(overrides map[string]any) []byte {
		claims := map[string]any{"aud": audience, "exp": now + 60, "iat": now, "jti": "one"}
		for k, v := range overrides {
			if v == nil {
				delete(claims, k)
			} else {
				claims[k] = v
			}
		}
		data, _ := json.Marshal(claims)
		return data
	}
	store := reservedDigests{}
	in := ClientAuthenticationInput{ExpectedAudience: audience, limits: limits, replay: store}
	described := func(err error) string {
		var problem *auth.OAuthError
		if !errors.As(err, &problem) || problem.Status != 400 || problem.Code != "invalid_client" {
			t.Fatalf("wanted 400 invalid_client, got %v", err)
		}
		return problem.Description
	}
	for description, claims := range map[string][]byte{
		"client assertion aud does not match the endpoint":          payload(map[string]any{"aud": []any{"https://other.example.test", 7}}),
		"client assertion must include exp claim":                   payload(map[string]any{"exp": "soon"}),
		"client assertion has expired":                              payload(map[string]any{"exp": now - 61}),
		"client assertion exp is too far in the future (max 300s)":  payload(map[string]any{"exp": now + 400}),
		"client assertion iat is too far in the past (max 300s)":    payload(map[string]any{"iat": now - 400}),
		"client assertion is not yet valid":                         payload(map[string]any{"nbf": now + 120}),
		"client assertion must include jti claim":                   payload(map[string]any{"jti": nil}),
		"client assertion exp is too far in the future (max 300s) ": []byte(`{"aud":"` + audience + `","exp":1e400,"jti":"one"}`),
		"client assertion has expired ":                             []byte(`{"aud":"` + audience + `","exp":-1e400,"jti":"one"}`),
		"client assertion iat is too far in the past (max 300s) ":   []byte(`{"aud":"` + audience + `","exp":` + strconv.FormatInt(now+60, 10) + `,"iat":-1e400,"jti":"one"}`),
		"client assertion must include exp claim ":                  []byte(`{"aud":"` + audience + `","exp":"` + strconv.FormatInt(now+60, 10) + `","jti":"one"}`),
	} {
		// A trailing space only keeps the map keys apart.
		if got := described(in.ConsumeClientAssertion(t.Context(), "urn:test", claims)); got != strings.TrimSpace(description) {
			t.Errorf("wanted %q, got %q", description, got)
		}
	}
	if err := in.ConsumeClientAssertion(t.Context(), "", payload(nil)); err == nil {
		t.Fatal("an empty namespace was accepted")
	}
	if len(store) != 0 {
		t.Fatal("a refused assertion was spent", store)
	}
	// An audience array, then a replay, then the same jti elsewhere.
	if err := in.ConsumeClientAssertion(t.Context(), "urn:test", payload(map[string]any{"aud": []any{"x", audience}})); err != nil {
		t.Fatal(err)
	}
	if got := described(in.ConsumeClientAssertion(t.Context(), "urn:test", payload(nil))); got != "client assertion jti has already been used" {
		t.Fatal("a replay was not refused", got)
	}
	if err := in.ConsumeClientAssertion(t.Context(), "urn:other", payload(nil)); err != nil {
		t.Fatal("the same jti under another namespace was refused", err)
	}
	if expires := store[assertionDigest("urn:test", "one")]; !expires.Equal(time.Unix(now+60+30, 0)) {
		t.Fatal("the spend did not last until exp plus the tolerance", expires)
	}
	// The clock tolerance admits a just-expired exp and an old iat.
	if err := in.ConsumeClientAssertion(t.Context(), "urn:tolerance", payload(map[string]any{"exp": now - 5, "iat": now - 310})); err != nil {
		t.Fatal("the clock tolerance was not applied", err)
	}
	if expires := store[assertionDigest("urn:tolerance", "one")]; !expires.Equal(time.Unix(now+25, 0)) {
		t.Fatal("a tolerated spend did not last until exp plus the tolerance", expires)
	}
	if err := in.ConsumeClientAssertion(t.Context(), "private_key_jwt:app", payload(nil)); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("private_key_jwt:app:one"))
	if _, ok := store[base64.RawURLEncoding.EncodeToString(sum[:24])]; !ok {
		t.Fatal("the namespaced digest is not private_key_jwt's")
	}
	// Without a replay store, the call is refused after the claim checks.
	in.replay = nil
	var api *auth.APIError
	if err := in.ConsumeClientAssertion(t.Context(), "urn:test", payload(map[string]any{"jti": "two"})); !errors.As(err, &api) || api.Status != 501 {
		t.Fatal("a store without assertion replay support was not 501", err)
	}
}
