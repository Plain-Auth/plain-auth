package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	auth "github.com/Plain-Auth/plain-auth"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

var _ op.ClientDeletionStore = (*Store)(nil)

// Compare IDs in Go so case-insensitive database collations cannot change ownership.
func clientOwnerMatches(owner, tenant *string, userID, referenceID string) bool {
	if owner != nil && *owner != "" {
		return userID == *owner
	}
	return userID == "" && referenceID != "" && tenant != nil && referenceID == *tenant
}

func (s *Store) DeleteOAuthClient(ctx context.Context, id, userID, referenceID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var rowID, clientID string
	var owner, tenant *string
	const q = `SELECT "id","clientId","userId","referenceId" FROM "oauthClient"`
	err = tx.QueryRowContext(ctx, s.readForUpdate(q+localClientFilter), id).Scan(&rowID, &clientID, &owner, &tenant)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && clientID != id) {
		return op.ErrClientNotFound
	}
	if err != nil {
		return err
	}
	if !clientOwnerMatches(owner, tenant, userID, referenceID) {
		return auth.StatusOnlyError(401)
	}
	// Foreign keys remove this client's consents, tokens, and resource links in the same transaction.
	result, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "oauthClient" WHERE "id"=?`), rowID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return op.ErrClientNotFound
	}
	return tx.Commit()
}
