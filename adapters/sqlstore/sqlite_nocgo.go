//go:build !cgo

package sqlstore

// sqliteDuplicate is never true without cgo: the SQLite driver cannot open
// a database then, so only PostgreSQL and MySQL errors reach the store.
func sqliteDuplicate(error) bool { return false }
