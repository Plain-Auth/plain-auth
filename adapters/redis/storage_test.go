package redisstore_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	redisstore "github.com/Plain-Org/plain-auth/adapters/redis"
	"github.com/redis/go-redis/v9"
)

var _ auth.RateLimitStorage = (*redisstore.Store)(nil)

func serverOptions(t *testing.T) *redis.Options {
	t.Helper()
	if raw := os.Getenv("AUTH_TEST_REDIS_URL"); raw != "" {
		opts, err := redis.ParseURL(raw)
		if err != nil {
			t.Fatal("invalid AUTH_TEST_REDIS_URL")
		}
		opts.ContextTimeoutEnabled = true
		opts.MaxRetries = -1
		return opts
	}
	server := os.Getenv("AUTH_TEST_REDIS_SERVER")
	if server == "" {
		for _, name := range []string{"valkey-server", "redis-server"} {
			if loc, err := exec.LookPath(name); err == nil {
				server = loc
				break
			}
		}
	}
	if server == "" {
		t.Skip("set AUTH_TEST_REDIS_URL or install valkey-server or redis-server")
	}
	// Short private paths also fit the macOS Unix socket path limit.
	dir, err := os.MkdirTemp("", "swrd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "r.sock")
	cmd := exec.Command(server, "--port", "0", "--unixsocket", socket, "--unixsocketperm", "700", "--save", "", "--appendonly", "no", "--dir", dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	opts := &redis.Options{Network: "unix", Addr: socket, MaxRetries: -1, ContextTimeoutEnabled: true}
	probe := redis.NewClient(opts)
	defer probe.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for probe.Ping(ctx).Err() != nil {
		select {
		case <-ctx.Done():
			t.Fatal("disposable Redis startup timed out")
		case <-time.After(20 * time.Millisecond):
		}
	}
	return opts
}

func connection(t *testing.T, opts *redis.Options) *redis.Client {
	t.Helper()
	c := redis.NewClient(opts)
	t.Cleanup(func() { c.Close() })
	if err := c.Ping(t.Context()).Err(); err != nil {
		t.Fatal("disposable Redis is unreachable", err)
	}
	return c
}

func storage(t *testing.T, c *redis.Client, ns string) *redisstore.Store {
	t.Helper()
	s, err := redisstore.New(c, ns)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Clear(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return s
}

func TestSecondaryValuesAndTTL(t *testing.T) {
	c := connection(t, serverOptions(t))
	ctx := t.Context()
	prefix := "sw:" + rand.Text() + ":"
	s := storage(t, c, prefix)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.Set(ctx, "empty", "", 0))
	value, found, err := s.Get(ctx, "empty")
	if err != nil || !found || value != "" {
		t.Fatal("empty string confused with missing key")
	}
	must(s.Set(ctx, "empty", "value", 2*time.Second))
	if c.PTTL(ctx, prefix+"empty").Val() <= 0 {
		t.Fatal("set did not apply TTL")
	}
	must(s.Set(ctx, "empty", "persistent", -1))
	if c.PTTL(ctx, prefix+"empty").Val() != -1 {
		t.Fatal("overwriting a key did not clear the old expiry")
	}
	must(s.Delete(ctx, "empty"))
	must(s.Delete(ctx, "empty"))
	if _, ok, err := s.Get(ctx, "empty"); ok || err != nil {
		t.Fatal("deleted key returned a value")
	}
	if _, err := s.Increment(ctx, "count", time.Millisecond); err == nil {
		t.Fatal("invalid increment TTL mutated the key")
	}
	if _, err := s.Increment(ctx, "count", 0); err == nil {
		t.Fatal("nonpositive increment TTL accepted")
	}
	if n, err := s.Increment(ctx, "count", 2*time.Second); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	if n, err := s.Increment(ctx, "count", time.Hour); n != 2 || err != nil {
		t.Fatal(n, err)
	}
	if ttl := c.PTTL(ctx, prefix+"count").Val(); ttl <= 0 || ttl > 2*time.Second {
		t.Fatal("increment extended the fixed creation window", ttl)
	}
	must(s.Set(ctx, "existing", "0", 0))
	if n, err := s.Increment(ctx, "existing", time.Hour); n != 1 || err != nil || c.PTTL(ctx, prefix+"existing").Val() != -1 {
		t.Fatal("existing zero counter gained a new expiration")
	}
	must(s.Set(ctx, "large", "9007199254740993", 0))
	if n, err := s.Increment(ctx, "large", time.Second); n != 9007199254740994 || err != nil {
		t.Fatal("int64 counter lost precision", n, err)
	}
	must(s.Set(ctx, "bad", "text", 0))
	if _, err := s.Increment(ctx, "bad", time.Second); err == nil {
		t.Fatal("invalid stored counter was silently replaced")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.Set(cancelled, "cancelled", "value", 0); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled set", err)
	}
	if _, ok, err := s.Get(ctx, "cancelled"); ok || err != nil {
		t.Fatal("cancelled set committed")
	}
}

type processHook func(redis.ProcessHook) redis.ProcessHook

func (p processHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (p processHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (p processHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook { return p(next) }

func TestAtomicTakeAndFallback(t *testing.T) {
	opts := serverOptions(t)
	prefix := "sw:" + rand.Text() + ":"
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint("legacy_", legacy), func(t *testing.T) {
			c1, c2 := connection(t, opts), connection(t, opts)
			var attempts atomic.Int32
			for _, c := range []*redis.Client{c1, c2} {
				c.AddHook(processHook(func(next redis.ProcessHook) redis.ProcessHook {
					return func(ctx context.Context, cmd redis.Cmder) error {
						if cmd.Name() == "getdel" {
							attempts.Add(1)
							if legacy {
								return next(ctx, redis.NewCmd(ctx, "UNAVAILABLE-FIXTURE-COMMAND"))
							}
						}
						return next(ctx, cmd)
					}
				}))
			}
			s1, s2 := storage(t, c1, prefix), storage(t, c2, prefix)
			for _, s := range []*redisstore.Store{s1, s2} {
				if _, ok, err := s.GetAndDelete(t.Context(), "empty"); err != nil || ok {
					t.Fatal("absent claim", err)
				}
			}
			if err := s1.Set(t.Context(), "proof", "verified", time.Minute); err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			var winners atomic.Int32
			for i := range 24 {
				s := []*redisstore.Store{s1, s2}[i%2]
				wg.Go(func() {
					v, ok, err := s.GetAndDelete(t.Context(), "proof")
					if err != nil || (ok && v != "verified") {
						t.Errorf("take result %q %v %v", v, ok, err)
					}
					if ok {
						winners.Add(1)
					}
				})
			}
			wg.Wait()
			if winners.Load() != 1 {
				t.Fatal("concurrent get-and-delete returned more or fewer than one proof")
			}
			if legacy && attempts.Load() != 2 {
				t.Fatal("unsupported GETDEL was repeatedly probed")
			}
		})
	}
}

func TestScopedScanAndClear(t *testing.T) {
	c := connection(t, serverOptions(t))
	ctx := t.Context()
	base := "sw:" + rand.Text() + ":"
	prefix := base + `a[1]*?\:`
	s := storage(t, c, prefix)
	foreign := base + "a1outside:"
	if err := c.Set(ctx, foreign, "other application", 0).Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Del(context.Background(), foreign) })
	var fail, duplicate atomic.Bool
	var pages atomic.Int32
	failure := errors.New("interrupted clear")
	c.AddHook(processHook(func(next redis.ProcessHook) redis.ProcessHook {
		return func(ctx context.Context, cmd redis.Cmder) error {
			switch cmd.Name() {
			case "flushdb", "flushall", "keys":
				return errors.New("global operation is not allowed")
			case "del":
				if fail.Load() && pages.Add(1) == 2 {
					return failure
				}
			}
			if err := next(ctx, cmd); err != nil {
				return err
			}
			if scan, ok := cmd.(*redis.ScanCmd); ok && duplicate.Load() {
				keys, cursor := scan.Val()
				if len(keys) > 0 {
					scan.SetVal(append(keys, keys[0]), cursor)
				}
			}
			return nil
		}
	}))
	keys := make([]string, 400)
	pipe := c.Pipeline()
	for i := range keys {
		keys[i] = fmt.Sprintf("key-%04d", i)
		pipe.Set(ctx, prefix+keys[i], "v", 0)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		t.Fatal(err)
	}
	duplicate.Store(true)
	got, err := s.ListKeys(ctx)
	if err != nil || !slices.Equal(got, keys) {
		t.Fatalf("literal prefix list did not return 400 unique relative keys: %d %v", len(got), err)
	}
	fail.Store(true)
	if err := s.Clear(ctx); !errors.Is(err, failure) {
		t.Fatal("mid-scan failure was hidden", err)
	}
	fail.Store(false)
	remaining, err := s.ListKeys(ctx)
	if err != nil || len(remaining) == 0 || len(remaining) >= len(keys) {
		t.Fatal("failed clear did not expose partial progress", len(remaining), err)
	}
	for range 2 {
		if err := s.Clear(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := s.ListKeys(ctx); err != nil || len(got) != 0 || c.Get(ctx, foreign).Val() != "other application" {
		t.Fatal("clear crossed its literal namespace or left keys behind")
	}
}

func TestDistributedHTTPRateLimit(t *testing.T) {
	opts := serverOptions(t)
	prefix := "sw:" + rand.Text() + ":"
	window := 3 * time.Second
	newServer := func() *httptest.Server {
		s := storage(t, connection(t, opts), prefix)
		on := true
		a, err := auth.New(auth.Options{Store: memory.New(), Secret: strings.Repeat("s", 32), BaseURL: "http://localhost", RateLimit: &on, RateLimitStorage: s, RateLimitRules: map[string]*auth.RateLimitRule{"/ok": {Max: 6, Window: window}}})
		if err != nil {
			t.Fatal(err)
		}
		app := httptest.NewServer(a)
		t.Cleanup(app.Close)
		return app
	}
	apps := []*httptest.Server{newServer(), newServer()}
	var allowed, denied atomic.Int32
	var wg sync.WaitGroup
	for i := range 28 {
		app := apps[i%2]
		wg.Go(func() {
			res, err := app.Client().Get(app.URL + "/api/auth/ok")
			if err != nil {
				t.Error(err)
				return
			}
			defer res.Body.Close()
			switch res.StatusCode {
			case http.StatusOK:
				allowed.Add(1)
			case http.StatusTooManyRequests:
				denied.Add(1)
				if res.Header.Get("X-Retry-After") != "3" {
					t.Error("incorrect retry window")
				}
			default:
				t.Errorf("unexpected handler status %d", res.StatusCode)
			}
		})
	}
	wg.Wait()
	if allowed.Load() != 6 || denied.Load() != 22 {
		t.Fatal("replicas did not share one HTTP request budget", allowed.Load(), denied.Load())
	}
	// Polling over budget must not prolong the original three-second window.
	deadline := time.Now().Add(window + 2*time.Second)
	for {
		res, err := apps[1].Client().Get(apps[1].URL + "/api/auth/ok")
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode == 200 {
			break
		}
		if res.StatusCode != 429 || time.Now().After(deadline) {
			t.Fatal("Redis did not reopen the expired HTTP window", res.StatusCode)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestDefaultNamespaceAndBackendFailure(t *testing.T) {
	opts := serverOptions(t)
	c := connection(t, opts)
	s, err := redisstore.New(c, "")
	if err != nil {
		t.Fatal(err)
	}
	key := rand.Text()
	if err := s.Set(t.Context(), key, "original", 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Del(context.Background(), redisstore.DefaultPrefix+key) })
	if c.Get(t.Context(), redisstore.DefaultPrefix+key).Val() != "original" {
		t.Fatal("missing default application prefix")
	}
	failure := errors.New("connection lost")
	c.AddHook(processHook(func(next redis.ProcessHook) redis.ProcessHook {
		return func(ctx context.Context, cmd redis.Cmder) error {
			if cmd.Name() == "getdel" {
				return failure
			}
			return next(ctx, cmd)
		}
	}))
	if _, _, err := s.GetAndDelete(t.Context(), key); !errors.Is(err, failure) {
		t.Fatal("non-command failure triggered a destructive fallback")
	}
	if value, ok, err := s.Get(t.Context(), key); !ok || value != "original" || err != nil {
		t.Fatal("proof removed after failed claim")
	}
}

func TestStringExpiryAndUnavailableLimiter(t *testing.T) {
	c := connection(t, serverOptions(t))
	s := storage(t, c, "sw:"+rand.Text()+":")
	if err := s.Set(t.Context(), "short", "value", time.Second); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, ok, err := s.Get(t.Context(), "short")
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("string value survived its expiry")
		}
		time.Sleep(25 * time.Millisecond)
	}
	c.AddHook(processHook(func(next redis.ProcessHook) redis.ProcessHook {
		return func(ctx context.Context, cmd redis.Cmder) error {
			if cmd.Name() == "evalsha" || cmd.Name() == "eval" {
				return errors.New("fixture backend unavailable")
			}
			return next(ctx, cmd)
		}
	}))
	on := true
	called := false
	probe := auth.Plugin{ID: "probe", Endpoints: []auth.Endpoint{{Method: http.MethodGet, Path: "/probe", Handler: func(auth.EndpointContext) (any, error) { called = true; return true, nil }}}}
	a, err := auth.New(auth.Options{Store: memory.New(), Secret: strings.Repeat("s", 32), BaseURL: "http://localhost", RateLimit: &on, RateLimitStorage: s, Plugins: []auth.Plugin{probe}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://localhost/api/auth/probe", nil))
	if called || w.Code != 500 || strings.Contains(w.Body.String(), "fixture") {
		t.Fatal("Redis failure admitted the protected endpoint or exposed backend details")
	}
}

func TestDPoPReplayReservationAcrossClients(t *testing.T) {
	opts := serverOptions(t)
	ns := "proof:" + rand.Text() + ":"
	first := connection(t, opts)
	stores := []*redisstore.Store{storage(t, first, ns), storage(t, connection(t, opts), ns)}
	now := time.Now().UTC()
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Go(func() {
			ok, err := stores[i%2].ReserveDPoPProof(t.Context(), "digest", now, now.Add(10*time.Second))
			if err != nil {
				t.Errorf("reserve: %v", err)
			} else if ok {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d proof reservations won", wins.Load())
	}
	ctx := t.Context()
	if ok, err := stores[0].ReserveDPoPProof(ctx, "digest", now, now.Add(time.Hour)); ok || err != nil {
		t.Fatal("duplicate", ok, err)
	}
	ttl, err := first.PTTL(ctx, ns+"dpop-proof:digest").Result()
	if err != nil || ttl <= 0 || ttl > 10*time.Second {
		t.Fatal("replay changed original TTL", ttl, err)
	}
	if ok, err := stores[0].ReserveDPoPProof(ctx, "brief", now, now.Add(25*time.Millisecond)); !ok || err != nil {
		t.Fatal(ok, err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		ok, err := stores[1].ReserveDPoPProof(ctx, "brief", now, now.Add(time.Second))
		if err != nil || time.Now().After(deadline) {
			t.Fatal("could not reuse expired proof ID", ok, err)
		}
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ok, err := stores[0].ReserveDPoPProof(ctx, "digest", now, now); ok || err == nil {
		t.Fatal("zero TTL", ok, err)
	}
}
