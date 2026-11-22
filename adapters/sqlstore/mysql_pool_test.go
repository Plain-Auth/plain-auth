package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
)

func mysqlTestConnector(t *testing.T) driver.Connector {
	t.Helper()
	cfg, err := mysql.ParseDSN(organizationTestDSN(t, "mysql"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.InterpolateParams = true
	cfg.ParseTime = true
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return connector
}

func mysqlPhysicalID(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	var id int64
	if err := db.QueryRowContext(t.Context(), "SELECT CONNECTION_ID()").Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

var errMySQLPoolFixture = errors.New("injected MySQL connection boundary error")

// Use the real driver's transaction, connection and lock behavior, with a
// controlled failure at one boundary. No production connection is faulted.
type mysqlPoolConnector struct {
	driver.Connector
	fault                           string
	rollbackEntered, resumeRollback chan struct{}
}

func (c *mysqlPoolConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &mysqlPoolConn{mysqlDriverConn: conn.(mysqlDriverConn), fixture: c}, nil
}

type mysqlDriverConn interface {
	driver.Conn
	driver.ConnBeginTx
	driver.ExecerContext
	driver.QueryerContext
	driver.SessionResetter
	driver.Validator
}
type mysqlPoolConn struct {
	mysqlDriverConn
	fixture *mysqlPoolConnector
}

func (c *mysqlPoolConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.mysqlDriverConn.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	if c.fixture.fault == "begin" {
		return nil, errMySQLPoolFixture
	}
	return &mysqlPoolTx{Tx: tx, fixture: c.fixture}, nil
}

// Use the real driver's result framing even when the response status is
// injected. An uncertain release must leave the server's lock untouched.
func (c *mysqlPoolConn) lockFault(q string) (string, error) {
	fault, status, altered := strings.Cut(c.fixture.fault, "-")
	acquire := fault == "acquire" && strings.Contains(q, "GET_LOCK(")
	release := fault == "release" && strings.Contains(q, "RELEASE_LOCK(")
	if !(acquire || release) {
		return "", nil
	}
	if release && !altered {
		return "", errMySQLPoolFixture
	}
	switch status {
	case "zero":
		return "SELECT 0", nil
	case "null":
		return "SELECT NULL", nil
	}
	return "", nil
}

func (c *mysqlPoolConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if substitute, err := c.lockFault(q); err != nil {
		return nil, err
	} else if substitute != "" {
		return c.mysqlDriverConn.ExecContext(ctx, substitute, nil)
	}
	return c.mysqlDriverConn.ExecContext(ctx, q, args)
}

func (c *mysqlPoolConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if substitute, err := c.lockFault(q); err != nil {
		return nil, err
	} else if substitute != "" {
		return c.mysqlDriverConn.QueryContext(ctx, substitute, nil)
	}
	rows, err := c.mysqlDriverConn.QueryContext(ctx, q, args)
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
		return nil, errMySQLPoolFixture
	}
	return rows, err
}

type mysqlPoolTx struct {
	driver.Tx
	fixture *mysqlPoolConnector
}

func (t *mysqlPoolTx) Commit() error {
	if t.fixture.fault == "commit" {
		return errMySQLPoolFixture
	}
	err := t.Tx.Commit()
	if err == nil && t.fixture.fault == "commit-reply" {
		// The server committed the change, but its reply did not arrive.
		return errMySQLPoolFixture
	}
	return err
}
func (t *mysqlPoolTx) Rollback() error {
	switch t.fixture.fault {
	case "rollback":
		return errMySQLPoolFixture
	case "cancel":
		close(t.fixture.rollbackEntered)
		<-t.fixture.resumeRollback
	}
	return t.Tx.Rollback()
}
