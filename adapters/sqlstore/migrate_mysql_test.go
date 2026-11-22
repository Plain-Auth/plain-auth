package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMySQLMigrationPoolLifecycle(t *testing.T) {
	ctx := t.Context()
	real := mysqlTestConnector(t)
	observer := sql.OpenDB(real)
	t.Cleanup(func() { observer.Close() })
	base, err := Schema("mysql")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		fault        string
		apply, reuse bool
	}{
		{"success", true, true}, {"acquire", false, false}, {"acquire-zero", false, true}, {"acquire-null", false, true},
		{"release", true, false}, {"release-zero", true, false}, {"release-null", true, false},
	} {
		t.Run(tc.fault, func(t *testing.T) {
			db := sql.OpenDB(&mysqlPoolConnector{Connector: real, fault: tc.fault})
			db.SetMaxOpenConns(1)
			db.SetMaxIdleConns(1)
			t.Cleanup(func() { db.Close() })
			before := mysqlPhysicalID(t, db)
			store := &Store{db: db, dialect: "mysql"}
			table := "migration_probe_" + strings.ReplaceAll(tc.fault, "-", "_")
			script := base + ";create table `" + table + "` (`id` int primary key);"
			runErr := store.migrate(ctx, script)
			if tc.apply && runErr != nil || !tc.apply && runErr == nil {
				t.Fatalf("unexpected migration outcome: %v", runErr)
			}
			if tc.fault == "acquire" && !errors.Is(runErr, errMySQLPoolFixture) {
				t.Fatal("lost acquisition error", runErr)
			}
			var exists bool
			if err := observer.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=?)", table).Scan(&exists); err != nil {
				t.Fatal(err)
			}
			if exists != tc.apply {
				t.Fatal("unexpected committed migration state", exists)
			}
			after := mysqlPhysicalID(t, db)
			if (before == after) != tc.reuse {
				t.Errorf("unexpected physical connection reuse: %d -> %d", before, after)
			}
			deadline := time.Now().Add(3 * time.Second)
			for {
				var owner sql.NullInt64
				if err := observer.QueryRowContext(ctx, "SELECT IS_USED_LOCK(CONCAT('authn/migration/',MD5(DATABASE())))").Scan(&owner); err != nil {
					t.Fatal(err)
				}
				if !owner.Valid {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("migration named lock still has a physical owner", owner.Int64)
				}
				time.Sleep(5 * time.Millisecond)
			}
		})
	}
}

func TestMySQLMigrationCleanupPreservesApplyError(t *testing.T) {
	ctx := t.Context()
	real := mysqlTestConnector(t)
	db := sql.OpenDB(&mysqlPoolConnector{Connector: real, fault: "release"})
	t.Cleanup(func() { db.Close() })
	req, cancel := context.WithCancel(ctx)
	defer cancel()
	expected := errors.New("migration application error")
	seen := false
	s := &Store{db: db, dialect: "mysql"}
	err := s.withMigrationConnection(req, func(c migrationConnection) error {
		var owner bool
		if e := c.QueryRowContext(req, "SELECT CONNECTION_ID()=IS_USED_LOCK(CONCAT('authn/migration/',MD5(DATABASE())))").Scan(&owner); e != nil || !owner {
			t.Fatal("migration ran without its database lock", e)
		}
		seen = true
		cancel()
		return expected
	})
	if !seen || !errors.Is(err, expected) {
		t.Fatal("cleanup obscured the original migration error", err)
	}
}
