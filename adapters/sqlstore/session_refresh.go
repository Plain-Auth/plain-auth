package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	authn "github.com/Plain-Auth/plain-auth"
)

var _ authn.SessionRefreshStore = (*Store)(nil)

func (s *Store) RefreshSession(ctx context.Context, token string, previousExpiry, now, nextExpiry time.Time) (bool, error) {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	exact, _ := s.deviceTokenParameters([]string{token})
	var sessionID, userID string
	q := `SELECT "id","userId" FROM "session" WHERE "token"=` + exact + ` AND "expiresAt"=? AND "expiresAt">?`
	err = tx.QueryRowContext(ctx, s.readForUpdate(q), token, s.date(previousExpiry), s.date(now)).Scan(&sessionID, &userID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, s.bind(`UPDATE "session" SET "updatedAt"=?,"expiresAt"=? WHERE `+s.scimExact(`"id"`)+`=?`), s.date(now), s.date(nextExpiry), sessionID)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	// Carry the original external SAML identity through a sliding renewal on any replica.
	q = `UPDATE "verification" SET "expiresAt"=? WHERE "id"=? AND "identifier"=? AND ` + s.samlReceiptField("SessionID") + `=? AND ` + s.samlReceiptField("UserID") + `=? AND ` + s.samlReceiptField("TokenDigest") + `=?`
	if _, err = tx.ExecContext(ctx, s.bind(q), s.date(nextExpiry), originDigest("sls-", sessionID), samlSessionKind, sessionID, userID, originDigest("slt-", token)); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) DeleteExpiredSession(ctx context.Context, token string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM "session" WHERE "token"=? AND "expiresAt"<=?`), token, s.date(now))
	return err
}
