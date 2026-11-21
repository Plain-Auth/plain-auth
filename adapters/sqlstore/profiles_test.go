package sqlstore

import (
	"database/sql"
	"reflect"
	"strings"
	"testing"

	"github.com/Stonewrit/stonewrit-auth/schema"
)

// Upgrade a populated installation and compare it to direct execution of the
// reference DDL in a separate database/schema on the same server.
func TestServerPluginSchemaUpgrade(t *testing.T) {
	for _, dialect := range []string{"postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			migratedDSN, refDSN := organizationTestDSN(t, dialect), organizationTestDSN(t, dialect)
			base, err := schema.Generate(dialect, nil)
			if err != nil {
				t.Fatal(err)
			}
			full, err := schema.Generate(dialect, []string{"admin", "anonymous", "device-authorization", "jwt", "last-login-method", "organization-teams", "passkey", "rate-limit", "stripe-subscriptions", "two-factor"})
			if err != nil {
				t.Fatal(err)
			}
			migrated, err := OpenWithSchema(ctx, dialect, migratedDSN, base)
			if err != nil {
				t.Fatal(err)
			}
			defer migrated.Close()
			var db *sql.DB
			queries := postgresCatalog
			if dialect == "postgres" {
				db, err = sql.Open("pgx", refDSN)
			} else {
				db, err = openMySQL(refDSN)
				queries = mysqlCatalog
			}
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			ref := &Store{db: db, dialect: dialect}
			q := `INSERT INTO "user" ("id","name","email","emailVerified","createdAt","updatedAt") VALUES ('local','Fixture','local@example.test',false,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`
			if _, err := migrated.db.ExecContext(ctx, migrated.bind(q)); err != nil {
				t.Fatal(err)
			}
			var tables []string
			for statement := range strings.SplitSeq(full, ";") {
				statement = strings.TrimSpace(statement)
				if statement == "" {
					continue
				}
				if _, err := db.ExecContext(ctx, statement); err != nil {
					t.Fatal(err)
				}
				if strings.HasPrefix(statement, "create table ") {
					table := strings.Fields(statement)[2]
					tables = append(tables, strings.Trim(table, "`\""))
				}
			}
			for range 2 {
				again, err := OpenWithSchema(ctx, dialect, migratedDSN, full)
				if err != nil {
					t.Fatal(err)
				}
				if err := again.Close(); err != nil {
					t.Fatal(err)
				}
			}
			var email string
			if err := migrated.db.QueryRowContext(ctx, migrated.bind(`SELECT "email" FROM "user" WHERE "id"='local'`)).Scan(&email); err != nil || email != "local@example.test" {
				t.Fatalf("preserving existing user: %q, %v", email, err)
			}
			for _, table := range tables {
				for category, query := range queries {
					actual := catalogRows(t, migrated, query, table, "")
					expected := catalogRows(t, ref, query, table, "")
					if !reflect.DeepEqual(actual, expected) {
						t.Errorf("%s %s differs: got %v, expected %v", table, category, actual, expected)
					}
				}
			}
		})
	}
}
