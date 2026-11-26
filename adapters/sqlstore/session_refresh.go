package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
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
	// The next read copies the renewed session back.
	if err := s.sessionMirror().forget(ctx, []string{token}); err != nil {
		return false, err
	}
	// Carry the original external SAML identity through a sliding renewal on any replica.
	binding := `"id"=? AND "identifier"=? AND ` + s.samlReceiptField("SessionID") + `=? AND ` + s.samlReceiptField("UserID") + `=? AND ` + s.samlReceiptField("TokenDigest") + `=?`
	args := []any{originDigest("sls-", sessionID), samlSessionKind, sessionID, userID, originDigest("slt-", token)}
	if _, err = tx.ExecContext(ctx, s.bind(`UPDATE "verification" SET "expiresAt"=? WHERE `+binding), append([]any{s.date(nextExpiry)}, args...)...); err != nil {
		return false, err
	}
	// Report an extended binding for its update after hooks. The Auth gives
	// a renewal a gate only without update before hooks, so this never stops.
	// The binding is looked up rather than counted, since MySQL counts only
	// rows whose values changed.
	if gate := authn.VerificationGateFrom(ctx); gate != nil {
		var extended bool
		if err := tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "verification" WHERE `+binding+`)`), args...).Scan(&extended); err != nil {
			return false, err
		}
		if extended {
			if _, err := gate.Update(sso.LogoutSessionRecord(originDigest("sls-", sessionID), userID, nextExpiry)); err != nil {
				return false, err
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) DeleteExpiredSession(ctx context.Context, token string, now time.Time) error {
	return s.deleteSessions(ctx, `"token"=? AND "expiresAt"<=?`, token, s.date(now))
}
