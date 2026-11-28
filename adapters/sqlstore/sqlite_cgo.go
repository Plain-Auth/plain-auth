//go:build cgo

package sqlstore

import (
	"errors"

	"github.com/mattn/go-sqlite3"
)

// sqliteDuplicate reports a SQLite primary key or unique violation. The
// SQLite driver needs cgo, so a build without it uses the stub beside this
// file and serves PostgreSQL and MySQL alone.
func sqliteDuplicate(err error) bool {
	var lite sqlite3.Error
	return errors.As(err, &lite) && (lite.ExtendedCode == sqlite3.ErrConstraintPrimaryKey || lite.ExtendedCode == sqlite3.ErrConstraintUnique)
}
