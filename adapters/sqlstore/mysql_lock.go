package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"time"
)

// MySQL named locks belong to physical connections, including across implicit
// DDL commits. Keep the connection reserved until release is confirmed.
type mysqlNamedLock struct {
	conn       *sql.Conn
	releaseSQL string
	args       []any
}

// nameSQL is a fixed SQL expression from the caller. Bind any request data in args.
func (s *Store) acquireMySQLNamedLock(ctx context.Context, nameSQL string, waitSeconds int, busy error, args ...any) (*mysqlNamedLock, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	lock := &mysqlNamedLock{conn: conn, releaseSQL: "SELECT RELEASE_LOCK(" + nameSQL + ")", args: args}
	var result sql.NullInt64
	query := fmt.Sprintf("SELECT GET_LOCK(%s, %d)", nameSQL, waitSeconds)
	if err := conn.QueryRowContext(ctx, query, args...).Scan(&result); err != nil {
		// The server may have acquired the lock before its reply was lost.
		lock.discard()
		return nil, err
	}
	if !result.Valid || result.Int64 != 1 {
		_ = conn.Close()
		return nil, busy
	}
	return lock, nil
}

func (lock *mysqlNamedLock) discard() {
	_ = lock.conn.Raw(func(any) error { return driver.ErrBadConn })
	_ = lock.conn.Close()
}

// release receives the physical transaction outcome, or nil for autocommit.
// A cleanup failure cannot undo a committed write. Discard the connection
// in that case and leave the operation's original result intact.
func (lock *mysqlNamedLock) release(transactionErr error) {
	if transactionErr != nil {
		lock.discard()
		return
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var result sql.NullInt64
	if err := lock.conn.QueryRowContext(cleanup, lock.releaseSQL, lock.args...).Scan(&result); err != nil || !result.Valid || result.Int64 != 1 {
		lock.discard()
		return
	}
	_ = lock.conn.Close()
}
