// Package sqlstore implements Better Auth storage for SQLite, PostgreSQL, and MySQL.
package sqlstore

import (
	"context"
	"database/sql"

	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/mattn/go-sqlite3"
)

// Store persists users, credentials, and session digests in a SQL database.
type Store struct {
	db      *sql.DB
	dialect string
}

func normalizeDialect(name string) (string, error) {
	switch strings.ToLower(name) {
	case "postgres", "postgresql":
		return "postgres", nil
	case "mysql":
		return "mysql", nil
	case "sqlite", "sqlite3":
		return "sqlite", nil
	default:
		return "", fmt.Errorf("sqlstore: unsupported dialect %q", name)
	}
}

// Open connects to the given database and applies its schema. SQLite accepts
// a file path or ":memory:", PostgreSQL accepts a pgx connection string, and
// MySQL accepts a go-sql-driver/mysql DSN containing a database name.
func Open(ctx context.Context, dialect, dsn string) (*Store, error) {
	baseline, err := Schema(dialect)
	if err != nil {
		return nil, err
	}
	return OpenWithSchema(ctx, dialect, dsn, baseline)
}

// OpenWithSchema applies a trusted generated baseline including any selected
// plugin tables, columns and indexes. It accepts the initialization SQL shape
// returned by Schema and the application's schema-profile generator.
func OpenWithSchema(ctx context.Context, dialect, dsn, baseline string) (*Store, error) {
	name, err := normalizeDialect(dialect)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dsn == "" {
		return nil, errors.New("sqlstore: empty database path or connection string")
	}
	var db *sql.DB
	switch name {
	case "sqlite":
		db, err = openSQLite(dsn)
	case "postgres":
		db, err = sql.Open("pgx", dsn)
	case "mysql":
		db, err = openMySQL(dsn)
	}
	if err != nil {
		return nil, err
	}
	store := &Store{db: db, dialect: name}
	if err := store.migrate(ctx, baseline); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func openSQLite(path string) (*sql.DB, error) {
	dsn := path
	if path != ":memory:" {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		// The database contains personal data and password hashes.
		file, err := os.OpenFile(absolute, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
		u := url.URL{Scheme: "file", Path: "/" + strings.TrimPrefix(filepath.ToSlash(absolute), "/")}
		dsn = u.String()
	}
	db, err := sql.Open("sqlite3", dsn+"?_foreign_keys=on&_busy_timeout=5000&_txlock=immediate")
	if err == nil {
		// Each private in-memory database lives on a single connection.
		// Serializing file-backed writes also avoids in-process contention.
		db.SetMaxOpenConns(1)
	}
	return db, err
}

func openMySQL(dsn string) (*sql.DB, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	if cfg.DBName == "" {
		return nil, errors.New("sqlstore: MySQL connection string must select a database")
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	if cfg.Params == nil {
		cfg.Params = make(map[string]string)
	}
	cfg.Params["time_zone"] = "'+00:00'"
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	return sql.OpenDB(connector), nil
}

// bind translates the positional placeholders in the store's built-in queries.
func (s *Store) bind(query string) string {
	if s.dialect == "mysql" {
		return strings.ReplaceAll(query, `"`, "`")
	}
	if s.dialect != "postgres" {
		return query
	}
	var out strings.Builder
	index := 1
	for {
		before, after, found := strings.Cut(query, "?")
		out.WriteString(before)
		if !found {
			return out.String()
		}
		out.WriteByte('$')
		out.WriteString(strconv.Itoa(index))
		index++
		query = after
	}
}

// date matches the upstream adapter's millisecond precision and SQLite's
// ISO-8601 text representation. Network drivers receive native UTC times.
func (s *Store) date(t time.Time) any {
	t = t.UTC().Truncate(time.Millisecond)
	if s.dialect == "sqlite" {
		return t.Format("2006-01-02T15:04:05.000Z")
	}
	return t
}
