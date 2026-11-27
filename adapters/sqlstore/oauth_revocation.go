package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

var _ op.RevocationStore = (*Store)(nil)

func (s *Store) RevokeOAuthToken(ctx context.Context, clientID, digest string, kind op.StoredTokenKind, check func(op.MachineClient) error) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	client, err := scanMachineClient(tx.QueryRowContext(ctx, s.readForUpdate(machineClientSelect), clientID, op.ResolvedDiscovery(ctx, clientID)), clientID)
	if err != nil {
		return false, err
	}
	if err := check(client); err != nil {
		return false, err
	}
	param := s.exactSQLValue("?")
	match := ` WHERE "clientId"=` + param + ` AND "token"=` + param
	var found bool
	switch kind {
	case op.StoredAccessToken:
		result, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "oauthAccessToken"`+match), clientID, digest)
		if err != nil {
			return false, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return false, err
		}
		found = n > 0
	case op.StoredRefreshToken:
		var id, user string
		var revoked sql.NullTime
		err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id","userId","revoked" FROM "oauthRefreshToken"`+match), clientID, digest).Scan(&id, &user, &revoked)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if revoked.Valid {
			// The foreign key removes access tokens linked to each deleted refresh
			// row. Independent access tokens and other users' grants survive.
			_, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "oauthRefreshToken" WHERE "clientId"=`+param+` AND "userId"=`+param), clientID, user)
		} else {
			_, err = tx.ExecContext(ctx, s.bind(`UPDATE "oauthRefreshToken" SET "revoked"=? WHERE "id"=`+param), s.date(time.Now().UTC().Truncate(time.Second)), id)
			if err == nil {
				_, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "oauthAccessToken" WHERE "refreshId"=`+param), id)
			}
		}
		if err != nil {
			return false, err
		}
		found = true
	default:
		return false, errors.New("sqlstore: unknown OAuth token kind")
	}
	return found, tx.Commit()
}
