package sqlstore

import (
	"context"
	"encoding/json"

	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

var _ op.ClientCredentialsScopeStore = (*Store)(nil)

func (s *Store) SetOAuthClientCredentialsScopes(ctx context.Context, change op.ClientCredentialsScopeChange) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	c, err := scanClientDetails(tx.QueryRowContext(ctx, s.readForUpdate(clientDetailsSelect+clientFilter), change.ClientID, op.ResolvedDiscovery(ctx, change.ClientID)))
	if err != nil {
		return err
	}
	if err := change.CheckTarget(c); err != nil {
		return err
	}
	if change.Scopes == nil {
		change.Scopes = []string{}
	}
	scopes, err := json.Marshal(change.Scopes)
	if err != nil {
		return err
	}
	const q = `UPDATE "oauthClient" SET "clientCredentialsScopes"=?, "updatedAt"=? WHERE "clientId"=?`
	if _, err := tx.ExecContext(ctx, s.bind(q), string(scopes), s.date(change.UpdatedAt), c.ClientID); err != nil {
		return err
	}
	return tx.Commit()
}
