package polar

import (
	"strings"
	"testing"

	"github.com/Plain-Auth/plain-auth/adapters/sqlstore"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestCheckoutLedgerSchemaMigration(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			db, dsn := database(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"polar", "sso"})
			if err != nil {
				t.Fatal(err)
			}
			migrate := func() error {
				st, err := sqlstore.OpenWithSchema(ctx, dialect, dsn, ddl)
				if err == nil {
					err = st.Close()
				}
				return err
			}
			start := make(chan struct{})
			result := make(chan error, 2)
			go func() { <-start; result <- migrate() }()
			go func() { <-start; _, err := OpenLedger(ctx, db, dialect); result <- err }()
			close(start)
			for range 2 {
				if err := <-result; err != nil {
					t.Fatal(err)
				}
			}
			l, err := OpenLedger(ctx, db, dialect)
			if err != nil {
				t.Fatal(err)
			}
			id := strings.Repeat("a", 64)
			stmt := l.bind("INSERT INTO plainauth_polar_delivery (event_key,body_hash,claim) VALUES (?,?,?)")
			if _, err := db.ExecContext(ctx, stmt, id, id, strings.Repeat("b", 36)); err != nil {
				t.Fatal(err)
			}
			if err := migrate(); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenLedger(ctx, db, dialect); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, stmt, id, id, strings.Repeat("c", 36)); err == nil {
				t.Fatal("accepted an already recorded delivery")
			}
			var n int
			if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM plainauth_polar_delivery").Scan(&n); err != nil || n != 1 {
				t.Fatal("lost checkout delivery receipt", err, n)
			}
			findings, err := sqlstore.CheckSchema(ctx, dialect, dsn, []string{"polar", "sso"})
			if err != nil || len(findings) != 0 {
				t.Fatal("incompatible billing schema", err, findings)
			}
		})
	}
}
