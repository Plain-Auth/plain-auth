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

	auth "github.com/Plain-Auth/plain-auth"
)

var _ auth.OneTimeTokenStore = (*Store)(nil)

func (s *Store) SaveOneTimeToken(ctx context.Context, key string, source auth.Session, now, expires time.Time) error {
	if err := source.RequireOwner(); err != nil {
		return err
	}
	start := time.Now()
	var err error
	for range 3 {
		err = s.saveOneTimeToken(ctx, key, source, now.Add(time.Since(start)), expires)
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
	started := time.Now()
	if err = s.lockActiveAccount(ctx, tx, source.UserID, source.Token, now); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "expiresAt"<=? AND ("identifier" LIKE 'one-time-token:%' OR "identifier" LIKE 'one-time-token-owner:%')`), s.date(now)); err != nil {
		return err
	}
	var id, owner, token string
	var sessionExpires time.Time
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id","userId","token","expiresAt" FROM "session" WHERE "token"=? AND "expiresAt">?`), source.Token, s.date(now)).Scan(&id, &owner, &token, &sessionExpires)
	if err != nil {
		return factorRowError(err)
	}
	at := now.Add(time.Since(started))
	if id != source.ID || owner != source.UserID || token != source.Token || !sessionExpires.After(at) {
		return auth.ErrNotFound
	}
	// Other compatible writers use random row IDs for verification records.
	var existing string
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id" FROM "verification" WHERE `+s.scimExact(`"identifier"`)+`=? LIMIT 1`), "one-time-token:"+key).Scan(&existing)
	if err == nil {
		return errors.New("duplicate one-time transfer key")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
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
	started := time.Now()
	var result auth.SessionResult
	var err error
	for range 3 {
		result, err = s.consumeOneTimeToken(ctx, key, now.Add(time.Since(started)))
		if !retryIdentity(err) {
			break
		}
	}
	return result, err
}
func (s *Store) consumeOneTimeToken(ctx context.Context, key string, now time.Time) (auth.SessionResult, error) {
	started := time.Now()
	var result auth.SessionResult
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var id, identifier, bound string
	var transferExpires time.Time
	want := "one-time-token:" + key
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id","identifier","value","expiresAt" FROM "verification" WHERE `+s.scimExact(`"identifier"`)+`=? AND "expiresAt">? ORDER BY "createdAt" DESC LIMIT 1`), want, s.date(now)).Scan(&id, &identifier, &bound, &transferExpires)
	if err != nil {
		return result, factorRowError(err)
	}
	if identifier != want {
		return result, auth.ErrNotFound
	}
	// Imported records can share a key because the canonical identifier is not
	// unique. Refuse an ambiguous transfer and burn every matching primary row.
	var other string
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id" FROM "verification" WHERE `+s.scimExact(`"identifier"`)+`=? AND "id"<>? AND "expiresAt">? LIMIT 1`), want, id, s.date(now)).Scan(&other)
	if err == nil {
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE `+s.scimExact(`"identifier"`)+`=?`), want); err != nil {
			return result, err
		}
		if err = tx.Commit(); err != nil {
			return result, err
		}
		return result, auth.ErrNotFound
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return result, err
	}
	var owner string
	marker := "one-time-token-owner:" + id
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "value" FROM "verification" WHERE `+s.scimExact(`"identifier"`)+`=?`), marker).Scan(&owner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE `+s.scimExact(`"id"`)+`=? OR `+s.scimExact(`"identifier"`)+`=?`), id, marker); err != nil {
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
	default:
		// A live administrative profile may have been installed on another node.
		// Consume the proof on policy denials; database failures remain retryable.
		err := s.lockActiveAccount(ctx, tx, session.UserID, bound, now.Add(time.Since(started)))
		var api *auth.APIError
		switch {
		case errors.Is(err, auth.ErrNotFound), errors.As(err, &api) && api.Code == "BANNED_USER":
			denial = auth.ErrTransferSessionMissing
		case err != nil:
			return auth.SessionResult{}, err
		}
	}
	at := now.Add(time.Since(started))
	if !transferExpires.After(at) {
		denial = auth.ErrNotFound
	} else if session.ID != "" && !session.ExpiresAt.After(at) {
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
