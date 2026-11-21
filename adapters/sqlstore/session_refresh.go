package sqlstore

import (
	"context"
	"time"

	authn "github.com/FineStack/frost-auth"
)

var _ authn.SessionRefreshStore = (*Store)(nil)

func (s *Store) RefreshSession(ctx context.Context, token string, previousExpiry, now, nextExpiry time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE "session" SET "updatedAt"=?,"expiresAt"=?
	WHERE "token"=? AND "expiresAt"=? AND "expiresAt">?`), s.date(now), s.date(nextExpiry), token, s.date(previousExpiry), s.date(now))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *Store) DeleteExpiredSession(ctx context.Context, token string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM "session" WHERE "token"=? AND "expiresAt"<=?`), token, s.date(now))
	return err
}
