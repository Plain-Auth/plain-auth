package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
)

// columnRace adds a column itself just before the migration's ALTER, then
// fails it, as a concurrent migration that won the race leaves it; with
// added false it only fails the ALTER.
type columnRace struct {
	migrationConnection
	added bool
}

var errColumnRace = errors.New("duplicate column")

func (c columnRace) ExecContext(ctx context.Context, stmt string, args ...any) (sql.Result, error) {
	if strings.HasPrefix(stmt, "ALTER TABLE") && strings.Contains(stmt, "race_probe") {
		if c.added {
			if _, err := c.migrationConnection.ExecContext(ctx, stmt, args...); err != nil {
				return nil, err
			}
		}
		return nil, errColumnRace
	}
	return c.migrationConnection.ExecContext(ctx, stmt, args...)
}

// On MySQL, a column another process added first lets the migration
// continue; any other failure to add it is returned, as it is on the
// engines whose migrations hold a lock.
func TestMigrationColumnRace(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			s, err := Open(ctx, dialect, organizationTestDSN(t, dialect))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			q := `"`
			if dialect == "mysql" {
				q = "`"
			}
			name := func(n string) string { return q + n + q }
			if _, err := s.db.ExecContext(ctx, "DROP TABLE IF EXISTS "+name("race_probe")); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.db.ExecContext(context.Background(), "DROP TABLE IF EXISTS "+name("race_probe")) })
			if _, err := s.db.ExecContext(ctx, "create table "+name("race_probe")+" ("+name("id")+" varchar(36) not null primary key)"); err != nil {
				t.Fatal(err)
			}
			stmt := "create table " + name("race_probe") + " (" + name("id") + " varchar(36) not null primary key, " + name("note") + " text)"
			err = s.withMigrationConnection(ctx, func(db migrationConnection) error { return s.ensureTable(ctx, columnRace{db, false}, stmt) })
			if !errors.Is(err, errColumnRace) {
				t.Fatal("a failed column add was not returned", err)
			}
			err = s.withMigrationConnection(ctx, func(db migrationConnection) error { return s.ensureTable(ctx, columnRace{db, true}, stmt) })
			if dialect != "mysql" {
				if !errors.Is(err, errColumnRace) {
					t.Fatal("a locked migration ignored a failed column add", err)
				}
				return
			}
			if err != nil {
				t.Fatal("a column another process added stopped the migration", err)
			}
			if added, err := s.hasColumn(ctx, s.db, name("race_probe"), "note"); err != nil || !added {
				t.Fatal("the column is missing", added, err)
			}
		})
	}
}
