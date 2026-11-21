// Package mysql implements authentication storage using MySQL.
package mysql

import (
	"context"

	"github.com/nabuhadba/go-better-auth/adapters/sqlstore"
)

// Store persists users, credentials, and sessions.
type Store = sqlstore.Store

// Open opens the database and applies the authentication schema.
func Open(ctx context.Context, dsn string) (*Store, error) {
	return sqlstore.Open(ctx, "mysql", dsn)
}
