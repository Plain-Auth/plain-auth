package sqlstore

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth/schema"
)

// Hold the schema lock until the other connection is waiting for it. A server
// defaulting to repeatable read would otherwise keep the pre-lock snapshot
// through the catalog check and the historical key backfill.
func TestPostgresLedgerMigrationSeesPrecedingCommit(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	dsn := organizationTestDSN(t, "postgres")
	ddl, err := schema.Generate("postgres", []string{"api-key"})
	if err != nil {
		t.Fatal(err)
	}
	open := func() *Store {
		t.Helper()
		store, err := OpenWithSchema(ctx, "postgres", dsn, ddl)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		store.db.SetMaxOpenConns(1)
		return store
	}
	first, waiting := open(), open()
	if _, err := waiting.db.ExecContext(ctx, "SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL REPEATABLE READ"); err != nil {
		t.Fatal(err)
	}
	var waiterPID int
	if err := waiting.db.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&waiterPID); err != nil {
		t.Fatal(err)
	}
	tx, err := first.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtext('authn/schema'))"); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE plainauth_api_key_digest (digest bytea NOT NULL PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	// The marker and a fingerprint model a completed migration by another writer.
	if _, err = tx.ExecContext(ctx, `INSERT INTO plainauth_api_key_digest VALUES ($1), ($2)`, []byte{1}, []byte(strings.Repeat("f", 32))); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- waiting.PrepareAPIKeyLedger(ctx) }()
	for {
		var blocked bool
		if err := tx.QueryRowContext(ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1))`, waiterPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("second migration completed before the lock was released: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var count int
	if err := waiting.db.QueryRowContext(ctx, "SELECT count(*) FROM plainauth_api_key_digest").Scan(&count); err != nil || count != 2 {
		t.Fatalf("unexpected digest ledger after migration: %d entries, %v", count, err)
	}
	var isolation string
	if err := waiting.db.QueryRowContext(ctx, "SHOW transaction_isolation").Scan(&isolation); err != nil || isolation != "repeatable read" {
		t.Fatalf("migration changed the application's isolation level to %q: %v", isolation, err)
	}
}

// Model an independent schema installer that finishes after discovery but
// before the adapter's CREATE. It uses its own PostgreSQL connection.
type concurrentLedgerInstaller struct {
	migrationConnection
	other *sql.DB
	ddl   string
}

func (c concurrentLedgerInstaller) ExecContext(ctx context.Context, stmt string, args ...any) (sql.Result, error) {
	if strings.HasPrefix(stmt, "CREATE TABLE") {
		if _, err := c.other.ExecContext(ctx, c.ddl); err != nil {
			return nil, err
		}
	}
	return c.migrationConnection.ExecContext(ctx, stmt, args...)
}

func TestPostgresConcurrentLedgerInstaller(t *testing.T) {
	for _, trial := range []struct {
		name, column string
		valid        bool
	}{
		{"binary primary key", "bytea NOT NULL PRIMARY KEY", true},
		{"incompatible table", "text", false},
	} {
		t.Run(trial.name, func(t *testing.T) {
			ctx := t.Context()
			s, err := Open(ctx, "postgres", organizationTestDSN(t, "postgres"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			const table = "plainauth_api_key_digest"
			err = s.withMigrationConnection(ctx, func(db migrationConnection) error {
				installer := concurrentLedgerInstaller{db, s.db, "CREATE TABLE plainauth_api_key_digest (digest " + trial.column + ")"}
				return s.ensureDigestLedger(ctx, installer, table)
			})
			if trial.valid && err != nil {
				t.Fatal(err)
			}
			if !trial.valid && (err == nil || !strings.Contains(err.Error(), "full binary digest primary key")) {
				t.Fatal("concurrent installer bypassed schema validation", err)
			}
		})
	}
}
