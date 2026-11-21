// Package postgres implements Better Auth storage using PostgreSQL.
package postgres

import (
	"context"

	"github.com/nabuhadba/go-better-auth/adapters/sqlstore"
)

// Store persists users, credentials, and sessions.
type Store = sqlstore.Store

// Open opens the database and applies the Better Auth schema.
func Open(ctx context.Context, dsn string) (*Store, error) {
	return sqlstore.Open(ctx, "postgres", dsn)
}
