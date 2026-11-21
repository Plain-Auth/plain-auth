package sqlstore

import (
	"crypto/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/nabuhadba/go-better-auth"
	"github.com/nabuhadba/go-better-auth/schema"
)

func TestSharedRateLimit(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			dsn := filepath.Join(t.TempDir(), "limits.db")
			if dialect != "sqlite" {
				dsn = os.Getenv("BETTERAUTH_TEST_" + strings.ToUpper(dialect) + "_DSN")
				if dsn == "" {
					t.Skip("disposable database DSN not set")
				}
			}
			ctx := t.Context()
			ddl, err := schema.Generate(dialect, []string{"rate-limit"})
			if err != nil {
				t.Fatal(err)
			}
			var stores [2]*Store
			var instances [2]*auth.Auth
			route := "/probe-" + strings.ToLower(rand.Text())
			on := true
			for i := range stores {
				stores[i], err = OpenWithSchema(ctx, dialect, dsn, ddl)
				if err != nil {
					t.Fatal(err)
				}
				defer stores[i].Close()
				instances[i], err = auth.New(auth.Options{
					Store: stores[i], BaseURL: "http://localhost", Secret: strings.Repeat("x", 32),
					RateLimit: &on, RateLimitStorage: stores[i],
					Plugins: []auth.Plugin{{ID: "probe", Endpoints: []auth.Endpoint{{
						Method: "GET", Path: route, Handler: func(auth.EndpointContext) (any, error) { return true, nil },
					}}}},
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			// The two pools must race over the same unused counter.
			key := "192.0.2.1|" + route
			defer stores[0].db.Exec(stores[0].bind(`DELETE FROM "rateLimit" WHERE "key"=?`), key)
			now := time.Now().UTC().Truncate(time.Millisecond)
			start := make(chan struct{})
			var allowed atomic.Int32
			var wg sync.WaitGroup
			for i := range 16 {
				wg.Go(func() {
					<-start
					wait, err := stores[i%2].ConsumeRateLimit(ctx, key, 3, time.Minute, now)
					if err != nil {
						t.Error(err)
					} else if wait == 0 {
						allowed.Add(1)
					} else if wait != time.Minute {
						t.Errorf("unexpected retry delay %v", wait)
					}
				})
			}
			close(start)
			wg.Wait()
			if allowed.Load() != 3 {
				t.Fatalf("admitted %d concurrent requests", allowed.Load())
			}
			// A denied request must not move the window's expiration.
			if delay, err := stores[1].ConsumeRateLimit(ctx, key, 3, time.Minute, now.Add(59000*time.Millisecond)); err != nil || delay != time.Second {
				t.Fatal(delay, err)
			}
			if delay, err := stores[0].ConsumeRateLimit(ctx, key, 3, time.Minute, now.Add(time.Minute)); err != nil || delay != 0 {
				t.Fatal(delay, err)
			}

			// A configured handler must actually consult the shared counter.
			if _, err := stores[0].db.Exec(stores[0].bind(`UPDATE "rateLimit" SET "count"=99,"lastRequest"=? WHERE "key"=?`), time.Now().UnixMilli(), key); err != nil {
				t.Fatal(err)
			}
			for i, expected := range []int{200, 429} {
				request := httptest.NewRequest("GET", "/api/auth"+route, nil)
				request.RemoteAddr = "192.0.2.1:12345"
				w := httptest.NewRecorder()
				instances[i].ServeHTTP(w, request)
				if w.Code != expected || (expected == 429 && w.Header().Get("X-Retry-After") == "") {
					t.Fatalf("replica %d: %d %s", i, w.Code, w.Body)
				}
			}
		})
	}
}
