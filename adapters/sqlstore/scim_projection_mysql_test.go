package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestSCIMMySQLProjectionPoolLifecycle(t *testing.T) {
	ctx := t.Context()
	real := mysqlTestConnector(t)
	observer := sql.OpenDB(real)
	t.Cleanup(func() { observer.Close() })
	if _, err := observer.ExecContext(ctx, "CREATE TABLE scim_pool_probe (name VARCHAR(32) PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"success", "abort", "acquire", "begin", "commit", "release", "rollback", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			fixture := &mysqlPoolConnector{Connector: real, fault: fault, rollbackEntered: make(chan struct{}), resumeRollback: make(chan struct{})}
			db := sql.OpenDB(fixture)
			db.SetMaxOpenConns(1)
			db.SetMaxIdleConns(1)
			t.Cleanup(func() { db.Close() })
			store := &Store{db: db, dialect: "mysql"}
			const domain = "pooled-directory"
			const key = "SHA2(CONCAT(DATABASE(), '/plainauth/scim-projection/', ?), 256)"
			lockOwner := func() sql.NullInt64 {
				t.Helper()
				var id sql.NullInt64
				if e := observer.QueryRowContext(ctx, "SELECT IS_USED_LOCK("+key+")", domain).Scan(&id); e != nil {
					t.Fatal(e)
				}
				return id
			}
			before := mysqlPhysicalID(t, db)
			req, cancel := context.WithCancel(ctx)
			defer cancel()
			tx, end, err := store.beginSCIMTransaction(req, domain, true)
			if fault == "begin" || fault == "acquire" {
				if !errors.Is(err, errMySQLPoolFixture) || tx != nil {
					t.Fatal(err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if got := lockOwner(); !got.Valid || got.Int64 != before {
					t.Fatalf("reserved lock owner %v, expected %d", got, before)
				}
				if _, err = tx.ExecContext(req, "INSERT INTO scim_pool_probe (name) VALUES (?)", fault); err != nil {
					t.Fatal(err)
				}
				switch fault {
				case "cancel":
					cancel()
					<-fixture.rollbackEntered
					finished := make(chan struct{})
					go func() { end.rollback(); close(finished) }()
					// The worker still owns the named lock while the physical
					// rollback is outstanding. Other connections can observe it.
					got := lockOwner()
					close(fixture.resumeRollback)
					if !got.Valid || got.Int64 != before {
						t.Fatal("advisory lock released before physical rollback", got)
					}
					select {
					case <-finished:
					case <-time.After(3 * time.Second):
						t.Fatal("cancelled transaction did not release its connection")
					}
				case "abort", "rollback":
					end.rollback()
				default:
					err = end.commit()
					if fault == "commit" {
						if !errors.Is(err, errMySQLPoolFixture) {
							t.Fatal(err)
						}
					} else if err != nil {
						t.Fatal(err)
					}
				}
				end.rollback() // The ordinary deferred cleanup is harmless after completion.
			}
			after := mysqlPhysicalID(t, db)
			healthy := fault == "success" || fault == "abort"
			if healthy != (before == after) {
				t.Fatalf("unexpected physical session reuse: %d -> %d", before, after)
			}
			deadline := time.Now().Add(3 * time.Second)
			for lockOwner().Valid {
				if time.Now().After(deadline) {
					t.Fatal("named lock survived cleanup")
				}
				time.Sleep(5 * time.Millisecond)
			}
			var rows int
			if err := observer.QueryRowContext(ctx, "SELECT COUNT(*) FROM scim_pool_probe WHERE name=?", fault).Scan(&rows); err != nil {
				t.Fatal(err)
			}
			want := 0
			if fault == "success" || fault == "release" {
				want = 1
			}
			if rows != want {
				t.Fatalf("committed rows %d, want %d", rows, want)
			}
		})
	}
}
