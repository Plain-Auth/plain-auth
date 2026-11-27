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
	}))
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
		cache.sets[uri].fetched = time.Now().Add(-d)
	}
	age(6 * time.Minute)
	status = 503
	if err := key(uri, "new"); err != nil {
		t.Fatal("cached key on transient failure", err)
	}
	age(11 * time.Minute)
	if err := key(uri, "new"); err == nil {
		t.Fatal("used a key beyond the stale limit")
	}
	for _, tc := range []struct {
		status      int
		media, data string
	}{
		{410, "application/json", old}, {302, "application/json", old}, {200, "text/plain", old},
		{200, "application/json", `{"keys":[]}`}, {200, "application/json", strings.Repeat(" ", maxClientKeyBytes) + old},
	} {
		status, media, document = 200, "application/json", old
		if err := key(uri, "old"); err != nil {
			t.Fatal(err)
		}
		age(6 * time.Minute)
		status, media, document = tc.status, tc.media, tc.data
		if err := key(uri, "old"); err == nil {
			t.Fatal("served keys after a terminal or malformed response")
		}
		status = 503
		if err := key(uri, "old"); err == nil {
			t.Fatal("resurrected discarded keys")
		}
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
	}))
	const uri = "https://keys.example.test/public"
	ctx, cancel := context.WithCancel(t.Context())
	first := make(chan error, 1)
	go func() { _, err := cache.load(ctx, uri, nil, time.Time{}); first <- err }()
	<-started
	results := make(chan error, 8)
	for range 8 {
		go func() { _, err := cache.load(t.Context(), uri, nil, time.Time{}); results <- err }()
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
