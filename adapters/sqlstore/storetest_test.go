package sqlstore

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/storetest"
)

// SQLite, PostgreSQL and MySQL pass the exported store contract, with its
// AccountStore and SessionRefreshStore groups. SQLite gets a fresh database
// per case; the servers share one store, whose cases read only their own rows.
func TestStoreContract(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			if dialect == "sqlite" {
				storetest.Run(t, func(t *testing.T) auth.Store { return openTestStore(t, filepath.Join(t.TempDir(), "store.db")) })
				return
			}
			key := "AUTH_TEST_" + strings.ToUpper(dialect) + "_DSN"
			dsn := os.Getenv(key)
			if dsn == "" {
				t.Skipf("set %s to run the %s store contract", key, dialect)
			}
			store, err := Open(context.Background(), dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			storetest.Run(t, func(*testing.T) auth.Store { return store })
		})
	}
}
