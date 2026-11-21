package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	auth "github.com/FineStack/finestack-auth"
)

type providerAccessor interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) readProviderCredential(ctx context.Context, db providerAccessor, userID, id string, lock bool) (auth.ProviderAccountCredential, error) {
	var item auth.ProviderAccountCredential
	var access, refresh, identity, scope sql.NullString
	var expires, refreshExpires sql.NullTime
	query := `SELECT "id","userId","providerId","accountId","accessToken","refreshToken","idToken","scope","accessTokenExpiresAt","refreshTokenExpiresAt" FROM "account" WHERE "id"=? AND "userId"=?`
	if lock && s.dialect != "sqlite" {
		query += " FOR UPDATE"
	}
	err := db.QueryRowContext(ctx, s.bind(query), id, userID).Scan(&item.ID, &item.UserID, &item.ProviderID, &item.Subject, &access, &refresh, &identity, &scope, &expires, &refreshExpires)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (item.ID != id || item.UserID != userID)) {
		return item, auth.ErrNotFound
	}
	item.AccessToken, item.RefreshToken, item.IDToken, item.Scope = access.String, refresh.String, identity.String, scope.String
	item.ExpiresAt, item.RefreshExpiresAt = expires.Time, refreshExpires.Time
	return item, err
}

func (s *Store) ProviderCredential(ctx context.Context, userID, id string) (auth.ProviderAccountCredential, error) {
	return s.readProviderCredential(ctx, s.db, userID, id, false)
}
func (s *Store) UpdateProviderCredential(ctx context.Context, userID, id string, update func(auth.ProviderAccountCredential) (auth.ProviderAccountCredential, bool, error)) (auth.ProviderAccountCredential, error) {
	var item auth.ProviderAccountCredential
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return item, err
	}
	defer tx.Rollback()
	item, err = s.readProviderCredential(ctx, tx, userID, id, true)
	if err != nil {
		return item, err
	}
	item, changed, err := update(item)
	if err != nil || !changed {
		return item, err
	}
	var expires, refreshExpires any
	if !item.ExpiresAt.IsZero() {
		expires = s.date(item.ExpiresAt)
	}
	if !item.RefreshExpiresAt.IsZero() {
		refreshExpires = s.date(item.RefreshExpiresAt)
	}
	_, err = tx.ExecContext(ctx, s.bind(`UPDATE "account" SET "accessToken"=?,"refreshToken"=NULLIF(?,''),"idToken"=NULLIF(?,''),"accessTokenExpiresAt"=?,"refreshTokenExpiresAt"=?,"updatedAt"=? WHERE "id"=? AND "userId"=?`), item.AccessToken, item.RefreshToken, item.IDToken, expires, refreshExpires, s.date(time.Now()), id, userID)
	if err != nil {
		return item, err
	}
	return item, tx.Commit()
}
