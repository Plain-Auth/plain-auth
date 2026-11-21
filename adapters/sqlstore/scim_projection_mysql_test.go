package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

var errSCIMPoolFixture = errors.New("injected SCIM transaction boundary error")

// Use the real driver's transaction, connection and lock behavior, with a
// controlled failure at one boundary. No production connection is faulted.
type scimPoolConnector struct {
	driver.Connector
	fault                           string
	rollbackEntered, resumeRollback chan struct{}
}

func (c *scimPoolConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &scimPoolConn{scimMySQLDriverConn: conn.(scimMySQLDriverConn), fixture: c}, nil
}

type scimMySQLDriverConn interface {
	driver.Conn
	driver.ConnBeginTx
	driver.ExecerContext
	driver.QueryerContext
	driver.SessionResetter
	driver.Validator
}
type scimPoolConn struct {
	scimMySQLDriverConn
	fixture *scimPoolConnector
}

func (c *scimPoolConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.scimMySQLDriverConn.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	if c.fixture.fault == "begin" {
		return nil, errSCIMPoolFixture
	}
	return &scimPoolTx{Tx: tx, fixture: c.fixture}, nil
}
func (c *scimPoolConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if c.fixture.fault == "release" && strings.Contains(q, "RELEASE_LOCK(") {
		return nil, errSCIMPoolFixture
	}
	rows, err := c.scimMySQLDriverConn.QueryContext(ctx, q, args)
	if err == nil && c.fixture.fault == "acquire" && strings.Contains(q, "GET_LOCK(") {
		// The server executed the query, but its successful result was lost.
		value := make([]driver.Value, 1)
		if err = rows.Next(value); err != nil {
			rows.Close()
			return nil, err
		}
		if err = rows.Close(); err != nil {
			return nil, err
		}
		return nil, errSCIMPoolFixture
	}
	return rows, err
}

type scimPoolTx struct {
	driver.Tx
	fixture *scimPoolConnector
}

func (t *scimPoolTx) Commit() error {
	if t.fixture.fault == "commit" {
		return errSCIMPoolFixture
	}
	return t.Tx.Commit()
}
func (t *scimPoolTx) Rollback() error {
	switch t.fixture.fault {
	case "rollback":
		return errSCIMPoolFixture
	case "cancel":
		close(t.fixture.rollbackEntered)
		<-t.fixture.resumeRollback
	}
	return t.Tx.Rollback()
}
func TestSCIMMySQLProjectionPoolLifecycle(t *testing.T) {
	ctx := t.Context()
	dsn := organizationTestDSN(t, "mysql")
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.InterpolateParams = true
	real, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	observer := sql.OpenDB(real)
	t.Cleanup(func() { observer.Close() })
	if _, err = observer.ExecContext(ctx, "CREATE TABLE scim_pool_probe (name VARCHAR(32) PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"success", "abort", "acquire", "begin", "commit", "release", "rollback", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			fixture := &scimPoolConnector{Connector: real, fault: fault, rollbackEntered: make(chan struct{}), resumeRollback: make(chan struct{})}
			db := sql.OpenDB(fixture)
			db.SetMaxOpenConns(1)
			db.SetMaxIdleConns(1)
			t.Cleanup(func() { db.Close() })
			store := &Store{db: db, dialect: "mysql"}
			const domain = "pooled-directory"
			const key = "SHA2(CONCAT(DATABASE(), '/stonewrit/scim-projection/', ?), 256)"
			lockOwner := func() sql.NullInt64 {
				t.Helper()
				var id sql.NullInt64
				if e := observer.QueryRowContext(ctx, "SELECT IS_USED_LOCK("+key+")", domain).Scan(&id); e != nil {
					t.Fatal(e)
				}
				return id
			}
			physicalID := func() int64 {
				t.Helper()
				var id int64
				if e := db.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&id); e != nil {
					t.Fatal(e)
				}
				return id
			}
			before := physicalID()
			req, cancel := context.WithCancel(ctx)
			defer cancel()
			tx, end, err := store.beginSCIMTransaction(req, domain, true)
			if fault == "begin" || fault == "acquire" {
				if !errors.Is(err, errSCIMPoolFixture) || tx != nil {
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
						if !errors.Is(err, errSCIMPoolFixture) {
							t.Fatal(err)
						}
					} else if err != nil {
						t.Fatal(err)
					}
				}
				end.rollback() // The ordinary deferred cleanup is harmless after completion.
			}
			after := physicalID()
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
