package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Compare each local server's actual catalogs against a separately installed
// copy of the pinned SQL. Prefixes keep reference tables isolated from data
// owned by the operator who supplied the disposable integration database.
func TestServerSchemaMatchesUpstream(t *testing.T) {
	for _, dialect := range []string{"postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			key := "BETTERAUTH_TEST_" + strings.ToUpper(dialect) + "_DSN"
			dsn := os.Getenv(key)
			if dsn == "" {
				t.Skipf("set %s to compare the %s server catalogs", key, dialect)
			}
			ctx := context.Background()
			s, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			prefix := "c" + strings.ToLower(rand.Text()[:12]) + "_"
			tables := []string{"user", "session", "account", "verification"}
			indices := []string{"session_userId_idx", "account_userId_idx", "verification_identifier_idx"}
			script, err := Schema(dialect)
			if err != nil {
				t.Fatal(err)
			}
			quote := `"`
			if dialect == "mysql" {
				quote = "`"
			}
			for _, name := range append(append([]string{}, tables...), indices...) {
				script = strings.ReplaceAll(script, quote+name+quote, quote+prefix+name+quote)
			}
			defer func() {
				for _, name := range []string{"verification", "account", "session", "user"} {
					if _, err := s.db.ExecContext(ctx, "DROP TABLE IF EXISTS "+quote+prefix+name+quote); err != nil {
						t.Error(err)
					}
				}
			}()
			for statement := range strings.SplitSeq(script, ";") {
				if strings.TrimSpace(statement) != "" {
					if _, err := s.db.ExecContext(ctx, statement); err != nil {
						t.Fatal(err)
					}
				}
			}
			queries := mysqlCatalog
			if dialect == "postgres" {
				queries = postgresCatalog
			}
			for _, table := range tables {
				for category, query := range queries {
					got := catalogRows(t, s, query, table, "")
					want := catalogRows(t, s, query, prefix+table, prefix)
					if !reflect.DeepEqual(got, want) {
						t.Errorf("%s %s differs\nGo: %q\nupstream: %q", table, category, got, want)
					}
				}
			}
		})
	}
}

// Indexes are compared by uniqueness, key order and columns. Server-generated
// constraint names depend on the physical table names.
var postgresCatalog = map[string]string{
	"columns": `SELECT column_name,data_type,is_nullable,COALESCE(column_default,''),ordinal_position::text
		FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=?`,
	"indexes": `SELECT i.indisunique::text,i.indisprimary::text,k.ordinality::text,a.attname
		FROM pg_index i JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace
		CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ordinality)
		JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=k.attnum WHERE n.nspname=current_schema() AND t.relname=?`,
	"foreign keys": `SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
		JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=current_schema() AND t.relname=? AND c.contype='f'`,
}

var mysqlCatalog = map[string]string{
	"columns": `SELECT column_name,column_type,is_nullable,COALESCE(column_default,''),ordinal_position
		FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=?`,
	"indexes": `SELECT non_unique,(index_name='PRIMARY'),seq_in_index,column_name FROM information_schema.statistics
		WHERE table_schema=DATABASE() AND table_name=?`,
	"foreign keys": `SELECT k.column_name,k.referenced_table_name,k.referenced_column_name,c.delete_rule,c.update_rule
		FROM information_schema.key_column_usage k JOIN information_schema.referential_constraints c
		ON c.constraint_schema=k.constraint_schema AND c.constraint_name=k.constraint_name AND c.table_name=k.table_name
		WHERE k.table_schema=DATABASE() AND k.table_name=? AND k.referenced_table_name IS NOT NULL`,
}

func catalogRows(t *testing.T, s *Store, query, table, prefix string) []string {
	t.Helper()
	rows, err := s.db.Query(s.bind(query), table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var result []string
	for rows.Next() {
		fields := make([]sql.NullString, len(columns))
		args := make([]any, len(fields))
		for i := range fields {
			args[i] = &fields[i]
		}
		if err := rows.Scan(args...); err != nil {
			t.Fatal(err)
		}
		row := fmt.Sprint(fields)
		if prefix != "" {
			row = strings.ReplaceAll(row, prefix, "")
			// PostgreSQL quotes the canonical reserved name "user".
			row = strings.ReplaceAll(row, "REFERENCES user(", `REFERENCES "user"(`)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(result)
	return result
}
