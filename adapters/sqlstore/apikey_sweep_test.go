package sqlstore

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	plainauth "github.com/Plain-Org/plain-auth"
	ak "github.com/Plain-Org/plain-auth/plugins/apikey"
	"github.com/Plain-Org/plain-auth/schema"
)

// Key operations purge the expired keys of every configuration at most
// once every ten seconds per service; DeleteAllExpired purges them all at
// once and DeleteExpired keeps to its own configuration.
func TestAPIKeyExpiredSweep(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"api-key"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			owner := testUser("sweep-owner")
			must(store.CreateUser(ctx, owner, "", nil))
			service := func(config string) *ak.Service {
				t.Helper()
				s, err := ak.New(ak.Options{Store: store, ConfigID: config})
				must(err)
				return s
			}
			creator := service("other")
			expire := func(id string) {
				t.Helper()
				_, err := store.db.ExecContext(ctx, store.bind(`UPDATE "apikey" SET "expiresAt"=? WHERE "id"=?`), store.date(time.Now().Add(-time.Minute)), id)
				must(err)
			}
			present := func(id string) bool {
				t.Helper()
				var n int
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT count(*) FROM "apikey" WHERE "id"=?`), id).Scan(&n))
				return n == 1
			}
			name := "Renamed"
			for _, op := range []string{"create", "get", "update", "delete", "list"} {
				fresh := service("default")
				own, err := fresh.Create(ctx, owner.ID, ak.CreateInput{})
				must(err)
				x, err := creator.Create(ctx, owner.ID, ak.CreateInput{})
				must(err)
				expire(x.ID)
				// fresh swept at its first create, before x expired, so a
				// second service runs the operation with its own throttle.
				fresh = service("default")
				switch op {
				case "create":
					_, err = fresh.Create(ctx, owner.ID, ak.CreateInput{})
				case "get":
					_, err = fresh.Get(ctx, owner.ID, own.ID)
				case "update":
					_, err = fresh.Update(ctx, owner.ID, own.ID, ak.UpdateInput{Name: &name})
				case "delete":
					err = fresh.Delete(ctx, owner.ID, own.ID)
				case "list":
					_, err = fresh.List(ctx, owner.ID, ak.PageOptions{})
				}
				must(err)
				if present(x.ID) {
					t.Fatal("a key operation did not sweep expired keys of every configuration", op)
				}
				y, err := creator.Create(ctx, owner.ID, ak.CreateInput{})
				must(err)
				expire(y.ID)
				_, err = fresh.List(ctx, owner.ID, ak.PageOptions{})
				must(err)
				if !present(y.ID) {
					t.Fatal("a second operation within ten seconds swept again", op)
				}
			}
			// An API-key session read sweeps once its key verifies.
			credential, err := service("default").Create(ctx, owner.ID, ak.CreateInput{})
			must(err)
			sessions, err := ak.New(ak.Options{Store: store, EnableSession: true, DisableRateLimit: true})
			must(err)
			host, err := plainauth.New(plainauth.Options{Store: store, BaseURL: "https://sweep.example", Secret: strings.Repeat("w", 32), Plugins: []plainauth.Plugin{sessions.Plugin()}})
			must(err)
			read := func(secret string) int {
				r := httptest.NewRequest("GET", "https://sweep.example/api/auth/get-session", nil)
				r.Header.Set("X-Api-Key", secret)
				w := httptest.NewRecorder()
				host.ServeHTTP(w, r)
				return w.Code
			}
			x, err := creator.Create(ctx, owner.ID, ak.CreateInput{})
			must(err)
			expire(x.ID)
			if read(strings.Repeat("z", 64)) != 401 || !present(x.ID) {
				t.Fatal("a refused session read swept expired keys")
			}
			if read(credential.Secret) != 200 || present(x.ID) {
				t.Fatal("an API-key session read did not sweep expired keys")
			}
			y, err := creator.Create(ctx, owner.ID, ak.CreateInput{})
			must(err)
			expire(y.ID)
			if read(credential.Secret) != 200 || !present(y.ID) {
				t.Fatal("a second session read within ten seconds swept again")
			}

			mine, err := creator.Create(ctx, owner.ID, ak.CreateInput{})
			must(err)
			theirs, err := service("default").Create(ctx, owner.ID, ak.CreateInput{})
			must(err)
			expire(mine.ID)
			expire(theirs.ID)
			if n, err := service("purge").DeleteExpired(ctx); err != nil || n != 0 || !present(mine.ID) || !present(theirs.ID) {
				t.Fatal("DeleteExpired removed another configuration's keys", n, err)
			}
			if n, err := service("purge").DeleteAllExpired(ctx); err != nil || n < 2 || present(mine.ID) || present(theirs.ID) {
				t.Fatal("DeleteAllExpired left an expired key", n, err)
			}
		})
	}
}

// With DeferUpdates, verification answers an expired or used-up key at once
// and leaves its deletion, and the expired-key sweep, to the task runner,
// while usage counters still commit with the verification.
func TestAPIKeyDeferredUpdates(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"api-key"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			owner := testUser("deferred-owner")
			must(store.CreateUser(ctx, owner, "", nil))
			var mu sync.Mutex
			var tasks []func()
			runner := func(task func()) {
				mu.Lock()
				defer mu.Unlock()
				tasks = append(tasks, task)
			}
			run := func() {
				mu.Lock()
				pending := tasks
				tasks = nil
				mu.Unlock()
				for _, task := range pending {
					task()
				}
			}
			if _, err := ak.New(ak.Options{Store: store, DeferUpdates: true}); err == nil {
				t.Fatal("deferred updates were accepted without a task runner")
			}
			keys, err := ak.New(ak.Options{Store: store, DeferUpdates: true, BackgroundTasks: runner, DisableRateLimit: true})
			must(err)
			expire := func(id string) {
				t.Helper()
				_, err := store.db.ExecContext(ctx, store.bind(`UPDATE "apikey" SET "expiresAt"=? WHERE "id"=?`), store.date(time.Now().Add(-time.Minute)), id)
				must(err)
			}
			present := func(id string) bool {
				t.Helper()
				var n int
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT count(*) FROM "apikey" WHERE "id"=?`), id).Scan(&n))
				return n == 1
			}
			verify := func(secret, code string) {
				t.Helper()
				v, err := keys.Verify(ctx, secret, nil)
				must(err)
				if code == "" && !v.Valid || code != "" && (v.Valid || v.Error.Code != code) {
					t.Fatalf("verification answered %+v, want %q", v.Error, code)
				}
			}

			old, err := keys.Create(ctx, owner.ID, ak.CreateInput{})
			must(err)
			run()
			expire(old.ID)
			verify(old.Secret, "KEY_EXPIRED")
			if !present(old.ID) {
				t.Fatal("an expired key was deleted inside a deferred verification")
			}
			run()
			if present(old.ID) {
				t.Fatal("the deferred deletion of an expired key never ran")
			}

			one := int64(1)
			spent, err := keys.Create(ctx, owner.ID, ak.CreateInput{Policy: ak.Policy{Remaining: &one}})
			must(err)
			verify(spent.Secret, "")
			verify(spent.Secret, "USAGE_EXCEEDED")
			if k, err := keys.Get(ctx, owner.ID, spent.ID); err != nil || k.Remaining == nil || *k.Remaining != 0 {
				t.Fatal("a used-up key was deleted before the task runner ran", err)
			}
			run()
			if present(spent.ID) {
				t.Fatal("the deferred deletion of a used-up key never ran")
			}

			hour := time.Hour
			refilled, err := keys.Create(ctx, owner.ID, ak.CreateInput{Policy: ak.Policy{Remaining: &one, RefillInterval: &hour, RefillAmount: &one}})
			must(err)
			verify(refilled.Secret, "")
			verify(refilled.Secret, "USAGE_EXCEEDED")
			run()
			if !present(refilled.ID) {
				t.Fatal("a refillable key was deleted")
			}

			rescued, err := keys.Create(ctx, owner.ID, ak.CreateInput{Policy: ak.Policy{Remaining: &one}})
			must(err)
			verify(rescued.Secret, "")
			verify(rescued.Secret, "USAGE_EXCEEDED")
			_, err = keys.Update(ctx, owner.ID, rescued.ID, ak.UpdateInput{Policy: ak.Policy{RefillInterval: &hour, RefillAmount: &one}})
			must(err)
			run()
			if !present(rescued.ID) {
				t.Fatal("a deferred deletion removed a key that gained a refill after the answer")
			}

			renewed, err := keys.Create(ctx, owner.ID, ak.CreateInput{})
			must(err)
			expire(renewed.ID)
			verify(renewed.Secret, "KEY_EXPIRED")
			days := 48 * time.Hour
			_, err = keys.Update(ctx, owner.ID, renewed.ID, ak.UpdateInput{ExpiresIn: &days})
			must(err)
			run()
			if !present(renewed.ID) {
				t.Fatal("a deferred deletion removed a key renewed after the answer")
			}
			verify(renewed.Secret, "")

			five := int64(5)
			counted, err := keys.Create(ctx, owner.ID, ak.CreateInput{Policy: ak.Policy{Remaining: &five}})
			must(err)
			verify(counted.Secret, "")
			if k, err := keys.Get(ctx, owner.ID, counted.ID); err != nil || k.Remaining == nil || *k.Remaining != 4 {
				t.Fatal("a deferred verification left its usage uncommitted", err)
			}
			run()

			later, err := ak.New(ak.Options{Store: store, ConfigID: "later", DeferUpdates: true, BackgroundTasks: runner})
			must(err)
			other, err := ak.New(ak.Options{Store: store, ConfigID: "other"})
			must(err)
			x, err := other.Create(ctx, owner.ID, ak.CreateInput{})
			must(err)
			expire(x.ID)
			_, err = later.List(ctx, owner.ID, ak.PageOptions{})
			must(err)
			if !present(x.ID) {
				t.Fatal("the expired-key sweep ran before the task runner")
			}
			run()
			if present(x.ID) {
				t.Fatal("the expired-key sweep was not handed to the task runner")
			}

			// A valid deferred verification hands the sweep to the runner, and
			// a refused one does not sweep.
			seed, err := ak.New(ak.Options{Store: store, ConfigID: "verifier"})
			must(err)
			good, err := seed.Create(ctx, owner.ID, ak.CreateInput{})
			must(err)
			switched, err := seed.Create(ctx, owner.ID, ak.CreateInput{})
			must(err)
			no := false
			_, err = seed.Update(ctx, owner.ID, switched.ID, ak.UpdateInput{Policy: ak.Policy{Enabled: &no}})
			must(err)
			z, err := other.Create(ctx, owner.ID, ak.CreateInput{})
			must(err)
			expire(z.ID)
			verifier, err := ak.New(ak.Options{Store: store, ConfigID: "verifier", DeferUpdates: true, BackgroundTasks: runner, DisableRateLimit: true})
			must(err)
			if v, err := verifier.Verify(ctx, switched.Secret, nil); err != nil || v.Valid {
				t.Fatal("a disabled key verified", err)
			}
			run()
			if !present(z.ID) {
				t.Fatal("a refused deferred verification swept expired keys")
			}
			if v, err := verifier.Verify(ctx, good.Secret, nil); err != nil || !v.Valid {
				t.Fatal("a valid key was refused", err)
			}
			if !present(z.ID) {
				t.Fatal("a deferred verification swept before the task runner")
			}
			run()
			if present(z.ID) {
				t.Fatal("a deferred verification did not hand the expired-key sweep to the task runner")
			}
		})
	}
}
