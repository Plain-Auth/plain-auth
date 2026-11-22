package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	auth "github.com/Plain-Auth/plain-auth"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

var _ op.SecretRotationStore = (*Store)(nil)

func (s *Store) RotateOAuthClientSecret(ctx context.Context, change op.ClientSecretReplacement) (op.ClientDetails, error) {
	if change.EncodedSecret == "" {
		return op.ClientDetails{}, errors.New("sqlstore: empty replacement client secret")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return op.ClientDetails{}, err
	}
	defer tx.Rollback()
	// Include the opaque row ID in the write so a deleted registration cannot
	// be confused with a later one while holding the database lock.
	var rowID, clientID string
	var owner, tenant, method, oldSecret *string
	const selectSecret = `SELECT "id","clientId","userId","referenceId","tokenEndpointAuthMethod","clientSecret" FROM "oauthClient"`
	err = tx.QueryRowContext(ctx, s.readForUpdate(selectSecret+localClientFilter), change.ClientID).Scan(&rowID, &clientID, &owner, &tenant, &method, &oldSecret)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && clientID != change.ClientID) {
		return op.ClientDetails{}, op.ErrClientNotFound
	}
	if err != nil {
		return op.ClientDetails{}, err
	}
	if owner != nil && *owner != "" {
		if change.UserID != *owner {
			return op.ClientDetails{}, auth.StatusOnlyError(401)
		}
	} else if change.UserID != "" || change.ReferenceID == "" || tenant == nil || *tenant != change.ReferenceID {
		return op.ClientDetails{}, auth.StatusOnlyError(401)
	}
	if oldSecret == nil || *oldSecret == "" || (method != nil && *method != "client_secret_basic" && *method != "client_secret_post") {
		return op.ClientDetails{}, op.ErrSecretRotationUnavailable
	}
	if *oldSecret == change.EncodedSecret {
		return op.ClientDetails{}, errors.New("sqlstore: replacement client secret matches current credential")
	}
	if _, err := tx.ExecContext(ctx, s.bind(`UPDATE "oauthClient" SET "clientSecret"=?,"updatedAt"=? WHERE "id"=?`), change.EncodedSecret, s.date(change.UpdatedAt), rowID); err != nil {
		return op.ClientDetails{}, err
	}
	updated, err := scanClientDetails(tx.QueryRowContext(ctx, s.bind(clientDetailsSelect+` WHERE "id"=?`), rowID))
	if err != nil {
		return op.ClientDetails{}, err
	}
	if err := tx.Commit(); err != nil {
		return op.ClientDetails{}, err
	}
	return updated, nil
}
