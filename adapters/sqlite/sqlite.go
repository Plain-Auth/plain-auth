// Package sqlite implements durable authentication storage using SQLite.
package sqlite

import (
	"context"

	"github.com/Plain-Auth/plain-auth/adapters/sqlstore"
)

// Store persists users, credentials, and sessions.
type Store = sqlstore.Store

// Open opens a database file and creates the required tables. Use ":memory:"
// for a private in-memory database whose lifetime matches the Store.
func Open(path string) (*Store, error) {
	return sqlstore.Open(context.Background(), "sqlite", path)
}
