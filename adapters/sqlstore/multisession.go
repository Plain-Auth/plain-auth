package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"

	authn "github.com/FineStack/frost-auth"
)

var _ authn.DeviceSessionStore = (*Store)(nil)

// MySQL installations commonly use a case-insensitive collation. Session tokens
// are opaque credentials and must match byte for byte on every engine.
func (s *Store) deviceTokenParameters(tokens []string) (string, []any) {
	arg := "?"
	if s.dialect == "mysql" {
		arg = "BINARY ?"
	}
	args := make([]any, len(tokens))
	for i, token := range tokens {
		args[i] = token
	}
	return strings.TrimSuffix(strings.Repeat(arg+",", len(tokens)), ","), args
}

func (s *Store) DeviceSessions(ctx context.Context, tokens []string, now time.Time) (map[string]authn.SessionResult, error) {
	found := make(map[string]authn.SessionResult)
	for chunk := range slices.Chunk(tokens, 400) {
		params, args := s.deviceTokenParameters(chunk)
		rows, err := s.db.QueryContext(ctx, s.bind(`SELECT `+sessionColumns+`,`+userColumns+`
			FROM "session" s JOIN "user" u ON u."id"=s."userId" WHERE s."token" IN (`+params+`) AND s."expiresAt">?`), append(args, s.date(now))...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var row authn.StoredSession
			var user authn.User
			if err := rows.Scan(append(sessionFields(&row), userFields(&user)...)...); err != nil {
				rows.Close()
				return nil, err
			}
			found[row.Token] = authn.SessionResult{Session: row.Session, User: user}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return found, ctx.Err()
}

func (s *Store) DeleteDeviceSessions(ctx context.Context, tokens []string) error {
	var err error
	for range 3 {
		err = s.deleteDeviceSessions(ctx, tokens)
		if !retryIdentity(err) {
			break
		}
	}
	return err
}

func (s *Store) deleteDeviceSessions(ctx context.Context, tokens []string) error {
	if len(tokens) == 0 {
		return ctx.Err()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for chunk := range slices.Chunk(tokens, 400) {
		params, args := s.deviceTokenParameters(chunk)
		if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "session" WHERE "token" IN (`+params+`)`), args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) RevokeDeviceSession(ctx context.Context, active, target string, now time.Time) error {
	var err error
	for range 3 {
		err = s.revokeDeviceSession(ctx, active, target, now)
		if !retryIdentity(err) {
			break
		}
	}
	return err
}

func (s *Store) revokeDeviceSession(ctx context.Context, active, target string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, arg := s.deviceTokenParameters([]string{active})
	var owner string
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "userId" FROM "session" WHERE "token"=`+p+` AND "expiresAt">?`), arg[0], s.date(now)).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.ErrNotFound
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "session" WHERE "token"=`+p), target)
	if err != nil {
		return err
	}
	return tx.Commit()
}
