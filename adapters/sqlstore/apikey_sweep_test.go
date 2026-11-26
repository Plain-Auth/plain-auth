package sqlstore

import (
	"testing"
	"time"

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
