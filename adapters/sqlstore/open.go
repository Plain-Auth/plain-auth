// Package sqlstore persists authentication data in SQLite, PostgreSQL, and MySQL.
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
	"sync/atomic"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/walletschema"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/plugins/scim"
	"github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/mattn/go-sqlite3"
)

// Store persists users, credentials, and sessions in a SQL database.
type Store struct {
	organizationRoles        org.RolePolicy
	dynamicOrganizationRoles bool
	invitationLimit          *org.InvitationLimit
	accountFields            map[string]auth.AccountField
	accountFieldRules        map[string]auth.AccountFieldRule
	walletMapping            walletschema.Mapping
	walletQueryNames         *strings.Replacer
	scimPolicies             map[string]scim.Projection
	adminSchema              *atomic.Bool
	apiKeyLedgerReady        *atomic.Bool
	dpopNextSweep            *atomic.Int64
	adminRole, adminDenial   string
	membershipLimit          org.MembershipLimit
	teamOptions              *org.TeamOptions
	factorSchema             bool
	db                       *sql.DB
	dialect                  string
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
	store, err := connectDB(ctx, dialect, dsn, true)
	if err != nil {
		return nil, err
	}
	db := store.db
	if err := store.migrate(ctx, baseline); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store.detectInitialProfiles(ctx)
}

func (store *Store) detectInitialProfiles(ctx context.Context) (*Store, error) {
	db := store.db
	_, err := store.detectAdminSchema(ctx, db)
	if err != nil {
		db.Close()
		return nil, err
	}
	store.factorSchema, err = store.detectFactorSchema(ctx, db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func connectDB(ctx context.Context, dialect, dsn string, create bool) (*Store, error) {
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
		db, err = openSQLite(dsn, create)
	case "postgres":
		db, err = sql.Open("pgx", dsn)
	case "mysql":
		db, err = openMySQL(dsn)
	}
	if err != nil {
		return nil, err
	}
	return &Store{db: db, dialect: name, adminSchema: new(atomic.Bool), apiKeyLedgerReady: new(atomic.Bool), dpopNextSweep: new(atomic.Int64)}, nil
}

func openSQLite(path string, create bool) (*sql.DB, error) {
	dsn := path
	mode := ""
	if !create && path == ":memory:" {
		return nil, errors.New("sqlstore: an existing database is required")
	}
	if path != ":memory:" {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		// The database contains personal data and password hashes.
		flags := os.O_RDWR
		if create {
			flags |= os.O_CREATE
		} else {
			mode = "&mode=rw"
		}
		file, err := os.OpenFile(absolute, flags, 0o600)
		if err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
		u := url.URL{Scheme: "file", Path: "/" + strings.TrimPrefix(filepath.ToSlash(absolute), "/")}
		dsn = u.String()
	}
	db, err := sql.Open("sqlite3", dsn+"?_foreign_keys=on&_busy_timeout=5000&_txlock=immediate"+mode)
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

// beginReadSnapshot keeps related queries on the same committed database state.
func (s *Store) beginReadSnapshot(ctx context.Context) (*sql.Tx, error) {
	var options *sql.TxOptions
	if s.dialect != "sqlite" {
		options = &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}
	}
	return s.db.BeginTx(ctx, options)
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
