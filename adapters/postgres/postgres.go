// Package postgres implements authentication storage using PostgreSQL.
package postgres

import (
	"context"

	"github.com/Stonewrit/stonewrit-auth/adapters/sqlstore"
)

// Store persists users, credentials, and sessions.
type Store = sqlstore.Store

// Open opens the database and applies the authentication schema.
func Open(ctx context.Context, dsn string) (*Store, error) {
	return sqlstore.Open(ctx, "postgres", dsn)
}
