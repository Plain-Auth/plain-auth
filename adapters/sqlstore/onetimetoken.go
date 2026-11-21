package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	auth "github.com/FineStack/frost-auth"
)

var _ auth.OneTimeTokenStore = (*Store)(nil)

func (s *Store) SaveOneTimeToken(ctx context.Context, key string, source auth.Session, now, expires time.Time) error {
	var err error
	for range 3 {
		err = s.saveOneTimeToken(ctx, key, source, now, expires)
		if !retryIdentity(err) {
			break
		}
	}
	return err
}
func (s *Store) saveOneTimeToken(ctx context.Context, key string, source auth.Session, now, expires time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "expiresAt"<=? AND ("identifier" LIKE 'one-time-token:%' OR "identifier" LIKE 'one-time-token-owner:%')`), s.date(now)); err != nil {
		return err
	}
	var id, owner, token string
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id","userId","token" FROM "session" WHERE "token"=? AND "expiresAt">?`), source.Token, s.date(now)).Scan(&id, &owner, &token)
	if err != nil {
		return factorRowError(err)
	}
	if id != source.ID || owner != source.UserID || token != source.Token {
		return auth.ErrNotFound
	}
	hash := sha256.Sum256([]byte(key))
	vid := "ot-" + hex.EncodeToString(hash[:16])
	insert := s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`)
	for _, row := range []struct{ id, identifier, value string }{{vid, "one-time-token:" + key, source.Token}, {rand.Text(), "one-time-token-owner:" + vid, owner + "\x1f" + id}} {
		if _, err = tx.ExecContext(ctx, insert, row.id, row.identifier, row.value, s.date(expires), s.date(now), s.date(now)); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) ConsumeOneTimeToken(ctx context.Context, key string, now time.Time) (auth.SessionResult, error) {
	var result auth.SessionResult
	var err error
	for range 3 {
		result, err = s.consumeOneTimeToken(ctx, key, now)
		if !retryIdentity(err) {
			break
		}
	}
	return result, err
}
func (s *Store) consumeOneTimeToken(ctx context.Context, key string, now time.Time) (auth.SessionResult, error) {
	var result auth.SessionResult
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var id, identifier, bound string
	want := "one-time-token:" + key
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id","identifier","value" FROM "verification" WHERE "identifier"=? AND "expiresAt">? ORDER BY "createdAt" DESC LIMIT 1`), want, s.date(now)).Scan(&id, &identifier, &bound)
	if err != nil {
		return result, factorRowError(err)
	}
	if identifier != want {
		return result, auth.ErrNotFound
	}
	var owner string
	marker := "one-time-token-owner:" + id
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "value" FROM "verification" WHERE "identifier"=?`), marker).Scan(&owner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? OR "identifier"=?`), id, marker); err != nil {
		return result, err
	}
	var session auth.StoredSession
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT `+sessionColumns+`,`+userColumns+` FROM "session" s JOIN "user" u ON u."id"=s."userId" WHERE s."token"=?`), bound).Scan(append(sessionFields(&session), userFields(&result.User)...)...)
	var denial error
	switch {
	case errors.Is(err, sql.ErrNoRows):
		denial = auth.ErrTransferSessionMissing
	case err != nil:
		return auth.SessionResult{}, err
	case session.Token != bound:
		denial = auth.ErrTransferSessionMissing
	case owner != "" && owner != strings.Join([]string{session.UserID, session.ID}, "\x1f"):
		denial = auth.ErrTransferSessionMissing
	case !session.ExpiresAt.After(now):
		denial = auth.ErrTransferSessionExpired
	}
	if err = tx.Commit(); err != nil {
		return auth.SessionResult{}, err
	}
	if denial != nil {
		return auth.SessionResult{}, denial
	}
	result.Session = session.Session
	return result, nil
}
