package sqlstore

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/Plain-Org/plain-auth/internal/polarledger"
)

//go:embed schema/*.sql
var schemas embed.FS

// Schema returns the full initialization script for an empty database.
// Open inspects existing tables and indexes before applying the baseline.
func Schema(dialect string) (string, error) {
	name, err := normalizeDialect(dialect)
	if err != nil {
		return "", err
	}
	script, err := schemas.ReadFile("schema/" + name + ".sql")
	return string(script), err
}

type migrationConnection interface {
	executor
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) migrate(ctx context.Context, baseline string) error {
	return s.withMigrationConnection(ctx, func(db migrationConnection) error {
		return s.applyMigrations(ctx, db, baseline)
	})
}

func (s *Store) withMigrationConnection(ctx context.Context, apply func(migrationConnection) error) error {
	if s.dialect == "mysql" {
		// MySQL's DDL commits implicitly. Keep the lock on one connection until
		// the full set of tables and indexes has been initialized.
		const name = "CONCAT('authn/migration/', MD5(DATABASE()))"
		lock, err := s.acquireMySQLNamedLock(ctx, name, 30, errors.New("sqlstore: unable to acquire MySQL schema migration lock"))
		if err != nil {
			return err
		}
		defer lock.release(nil)
		return apply(lock.conn)
	}
	var opts *sql.TxOptions
	if s.dialect == "postgres" {
		// Taking the advisory lock can start a snapshot before a preceding
		// migrator commits. Catalog probes and backfills need a fresh snapshot
		// after the lock is granted, regardless of the application's isolation.
		opts = &sql.TxOptions{Isolation: sql.LevelReadCommitted}
	}
	tx, err := s.db.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if s.dialect == "postgres" {
		// Serialize schema creation across independent application processes.
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtext('authn/schema'))"); err != nil {
			return err
		}
	}
	if err := apply(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// These expressions match the immutable initialization scripts embedded above.
var indexDDL = regexp.MustCompile("(?i)^create (?:unique )?index [`\"]([^\"`]+)[`\"] on [`\"]([^\"`]+)[`\"]")
var tableDDL = regexp.MustCompile("(?is)^create table ([`\"][a-zA-Z_][a-zA-Z0-9_]*[`\"]) \\((.*)\\)$")
var columnDDL = regexp.MustCompile("^[`\"]([a-zA-Z_][a-zA-Z0-9_]*)[`\"] ")

func (s *Store) applyMigrations(ctx context.Context, db migrationConnection, baseline string) error {
	for statement := range strings.SplitSeq(baseline, ";") {
		stmt := strings.TrimSpace(statement)
		if stmt == "" {
			continue
		}
		switch {
		case strings.HasPrefix(stmt, "create table "):
			if err := s.ensureTable(ctx, db, stmt); err != nil {
				return err
			}
			continue
		case indexDDL.MatchString(stmt):
			if s.dialect == "mysql" {
				// MySQL has no CREATE INDEX IF NOT EXISTS.
				match := indexDDL.FindStringSubmatch(stmt)
				if match == nil {
					return errors.New("sqlstore: invalid embedded index statement")
				}
				var exists int
				if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.statistics
      WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?`, match[2], match[1]).Scan(&exists); err != nil {
					return err
				}
				if exists > 0 {
					continue
				}
			} else {
				stmt = strings.Replace(stmt, "index ", "index if not exists ", 1)
			}
		default:
			return errors.New("sqlstore: unexpected embedded schema statement")
		}
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("sqlstore: initialize %s schema: %w", s.dialect, err)
		}
	}
	// Fail at startup when an existing table uses an incompatible layout.
	for _, query := range []string{
		`SELECT t."id",t."name",t."email",t."emailVerified",t."image",t."createdAt",t."updatedAt" FROM "user" t WHERE 1=0`,
		`SELECT t."id",t."expiresAt",t."token",t."createdAt",t."updatedAt",t."ipAddress",t."userAgent",t."userId" FROM "session" t WHERE 1=0`,
		`SELECT t."id",t."accountId",t."providerId",t."userId",t."accessToken",t."refreshToken",t."idToken",t."accessTokenExpiresAt",t."refreshTokenExpiresAt",t."scope",t."password",t."createdAt",t."updatedAt" FROM "account" t WHERE 1=0`,
		`SELECT t."id",t."identifier",t."value",t."expiresAt",t."createdAt",t."updatedAt" FROM "verification" t WHERE 1=0`,
	} {
		rows, err := db.QueryContext(ctx, s.bind(query))
		if err != nil {
			return fmt.Errorf("sqlstore: incompatible %s schema: %w", s.dialect, err)
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	return nil
}

// hasColumn reports whether a table has a column.
func (s *Store) hasColumn(ctx context.Context, db migrationConnection, table, column string) (bool, error) {
	rows, err := db.QueryContext(ctx, "SELECT * FROM "+table+" WHERE 1=0")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	return slices.Contains(columns, column), err
}

func (s *Store) ensureTable(ctx context.Context, db migrationConnection, stmt string) error {
	match := tableDDL.FindStringSubmatch(stmt)
	if match == nil {
		return errors.New("sqlstore: invalid generated table declaration")
	}
	table := match[1]
	if s.dialect == "postgres" && table == `"`+polarledger.CheckoutTable+`"` {
		// The plugin may open its standalone ledger while authctl migrates.
		if _, err := db.ExecContext(ctx, polarledger.PostgresSchemaLock); err != nil {
			return err
		}
	}
	if _, err := db.ExecContext(ctx, strings.Replace(stmt, "create table ", "create table if not exists ", 1)); err != nil {
		return err
	}
	rows, err := db.QueryContext(ctx, "SELECT * FROM "+table+" WHERE 1=0")
	if err != nil {
		return err
	}
	columns, err := rows.Columns()
	rows.Close()
	if err != nil {
		return err
	}
	have := make(map[string]bool, len(columns))
	for _, col := range columns {
		have[col] = true
	}
	// Kysely quotes every column name. A comma followed by a quoted name and
	// a space therefore starts another column, unlike commas in SQL type
	// parameters, constraints or literal defaults in these generated baselines.
	for _, definition := range strings.Split(match[2], ", ") {
		col := columnDDL.FindStringSubmatch(definition)
		if col == nil || have[col[1]] {
			continue
		}
		normalized := strings.ToLower(definition)
		if strings.Contains(normalized, "primary key") {
			return fmt.Errorf("sqlstore: existing table %s is missing primary key %s", table, col[1])
		}
		if strings.Contains(normalized, "not null") && !strings.Contains(normalized, " default ") {
			var exists bool
			if err := db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM "+table+")").Scan(&exists); err != nil {
				return err
			}
			if exists {
				return fmt.Errorf("sqlstore: explicitly backfill required column %s.%s before migrating existing rows", table, col[1])
			}
		}
		// SQLite implements inline uniqueness with an automatic index but only supports
		// adding it to an existing table as a separate index, in this same transaction.
		addUnique := s.dialect == "sqlite" && strings.HasSuffix(normalized, " unique")
		if addUnique {
			definition = definition[:len(definition)-len(" unique")]
		}
		if _, err := db.ExecContext(ctx, "ALTER TABLE "+table+" ADD COLUMN "+definition); err != nil {
			// On MySQL, DDL is not transactional and nothing serializes this
			// with a plugin opening its own tables, so another process may
			// have added the column first. PostgreSQL and SQLite migrations
			// hold a lock, and a failed PostgreSQL statement ends the
			// transaction anyway.
			if s.dialect == "mysql" {
				if added, readErr := s.hasColumn(ctx, db, table, col[1]); readErr == nil && added {
					continue
				}
			}
			return err
		}
		if addUnique {
			// Table/column names have already matched the schema identifier grammar.
			index := strings.Trim(table, `"`) + "_" + col[1] + "_unique"
			if _, err := db.ExecContext(ctx, `CREATE UNIQUE INDEX "`+index+`" ON `+table+` ("`+col[1]+`")`); err != nil {
				return err
			}
		}
	}
	if s.dialect == "mysql" {
		// CREATE TABLE IF NOT EXISTS leaves constraints on existing tables
		// untouched. Add any missing keys only after all columns are present.
		for _, key := range mysqlForeignKeyDDL.FindAllStringSubmatch(match[2], -1) {
			if err := ensureMySQLForeignKey(ctx, db, table, key); err != nil {
				return err
			}
		}
	}
	return nil
}

var mysqlForeignKeyDDL = regexp.MustCompile("constraint `\\w+` foreign key \\(`(\\w+)`\\) references `(\\w+)` \\(`(\\w+)`\\) on delete (cascade|set null)")

func ensureMySQLForeignKey(ctx context.Context, db migrationConnection, table string, key []string) error {
	definition, column, parent, parentColumn, deleteRule := key[0], key[1], key[2], key[3], key[4]
	const query = `SELECT COUNT(*), COALESCE(SUM(k.referenced_table_schema = DATABASE()
		AND k.referenced_table_name = ? AND (@@lower_case_table_names <> 0 OR BINARY k.referenced_table_name = BINARY ?)
		AND k.referenced_column_name = ? AND r.delete_rule = ?), 0)
		FROM information_schema.key_column_usage k
		JOIN information_schema.referential_constraints r
		ON r.constraint_schema = k.constraint_schema AND r.constraint_name = k.constraint_name AND r.table_name = k.table_name
		WHERE k.table_schema = DATABASE() AND k.table_name = ? AND k.column_name = ?
		AND k.referenced_table_name IS NOT NULL
		AND (@@lower_case_table_names <> 0 OR BINARY k.table_name = BINARY ?)`
	name := strings.Trim(table, "`")
	var total, matching int
	if err := db.QueryRowContext(ctx, query, parent, parent, parentColumn, strings.ToUpper(deleteRule), name, column, name).Scan(&total, &matching); err != nil {
		return err
	}
	if total != matching {
		return fmt.Errorf("sqlstore: existing foreign key for %s.%s has an incompatible target or delete rule", name, column)
	}
	if matching == 0 {
		if _, err := db.ExecContext(ctx, "ALTER TABLE "+table+" ADD "+definition); err != nil {
			return fmt.Errorf("sqlstore: add foreign key on %s.%s: %w", name, column, err)
		}
	}
	return nil
}
