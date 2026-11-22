package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/Plain-Auth/plain-auth/adapters/sqlstore"
)

// A trusted fixture process classifies legacy links without exposing a route.
func reconcileSSOAccount(path string) error {
	ctx := context.Background()
	db, e := sqlstore.Open(ctx, "sqlite", path)
	if e != nil {
		return e
	}
	defer db.Close()
	var input sqlstore.OAuthAccountAttribution
	if e = json.NewDecoder(os.Stdin).Decode(&input); e != nil {
		return e
	}
	return db.ReconcileOAuthAccount(ctx, input)
}
