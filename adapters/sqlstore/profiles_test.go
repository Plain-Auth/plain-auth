package sqlstore

import (
	"crypto/rand"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/nabuhadba/go-better-auth/schema"
)

// Install the reference DDL and upgrade a populated core installation in
// different, run-specific table namespaces on the same local SQL engine.
func TestServerPluginSchemaUpgrade(t *testing.T) {
	for _, dialect := range []string{"postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			dsn := os.Getenv("BETTERAUTH_TEST_" + strings.ToUpper(dialect) + "_DSN")
			if dsn == "" {
				t.Skip("disposable database DSN not set")
			}
			ctx := t.Context()
			quote := `"`
			queries := postgresCatalog
			if dialect == "mysql" {
				quote = "`"
				queries = mysqlCatalog
			}
			base, err := schema.Generate(dialect, nil)
			if err != nil {
				t.Fatal(err)
			}
			expanded, err := schema.Generate(dialect, []string{"organization-teams", "rate-limit", "stripe-subscriptions", "two-factor"})
			if err != nil {
				t.Fatal(err)
			}
			var tables, names []string
			for statement := range strings.SplitSeq(expanded, ";") {
				stmt := strings.TrimSpace(statement)
				if stmt == "" {
					continue
				}
				first := strings.Index(stmt, quote)
				end := strings.Index(stmt[first+1:], quote)
				if first < 0 || end < 0 {
					t.Fatalf("invalid schema SQL %s", stmt)
				}
				name := stmt[first+1 : first+1+end]
				names = append(names, name)
				if strings.HasPrefix(stmt, "create table ") {
					tables = append(tables, name)
				}
			}
			prefix := "p" + strings.ToLower(rand.Text()[:8])
			migrated, fresh := prefix+"m_", prefix+"f_"
			withPrefix := func(script, prefix string) string {
				for _, name := range names {
					script = strings.ReplaceAll(script, quote+name+quote, quote+prefix+name+quote)
				}
				return script
			}
			store, err := OpenWithSchema(ctx, dialect, dsn, withPrefix(base, migrated))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			defer func() {
				for i := len(tables) - 1; i >= 0; i-- {
					for _, prefix := range []string{fresh, migrated} {
						if _, err := store.db.ExecContext(ctx, "DROP TABLE IF EXISTS "+quote+prefix+tables[i]+quote); err != nil {
							t.Error(err)
						}
					}
				}
			}()
			q := func(key string) string { return quote + key + quote }
			userTable := q(migrated + "user")
			insert := "INSERT INTO " + userTable + " (" + strings.Join([]string{q("id"), q("name"), q("email"), q("emailVerified"), q("createdAt"), q("updatedAt")}, ",") +
				") VALUES ('local','Fixture','local@example.test',false,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"
			if _, err := store.db.ExecContext(ctx, insert); err != nil {
				t.Fatal(err)
			}
			for statement := range strings.SplitSeq(withPrefix(expanded, fresh), ";") {
				if strings.TrimSpace(statement) != "" {
					if _, err := store.db.ExecContext(ctx, statement); err != nil {
						t.Fatal(err)
					}
				}
			}
			for range 2 {
				again, err := OpenWithSchema(ctx, dialect, dsn, withPrefix(expanded, migrated))
				if err != nil {
					t.Fatal(err)
				}
				if err := again.Close(); err != nil {
					t.Fatal(err)
				}
			}
			var email string
			if err := store.db.QueryRowContext(ctx, "SELECT email FROM "+userTable+" WHERE id='local'").Scan(&email); err != nil || email != "local@example.test" {
				t.Fatalf("preserving existing user: %q, %v", email, err)
			}
			for _, table := range tables {
				for category, query := range queries {
					actual := catalogRows(t, store, query, migrated+table, migrated)
					expected := catalogRows(t, store, query, fresh+table, fresh)
					if !reflect.DeepEqual(actual, expected) {
						t.Errorf("%s %s differs: got %v, expected %v", table, category, actual, expected)
					}
				}
			}
		})
	}
}
