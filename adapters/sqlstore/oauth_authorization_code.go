package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

var _ op.AuthorizationCodeStore = (*Store)(nil)

func (s *Store) RedeemAuthorizationCode(ctx context.Context, clientID, identifier string, checkClient func(op.MachineClient) error, prepare func(op.AuthorizationCodeClient, json.RawMessage) (op.DelegatedAccessRecord, error)) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Serialize redemption and replay cleanup for the same registration, even
	// after the verification row itself is gone.
	var client op.AuthorizationCodeClient
	var registeredScopes []byte
	const clientSelect = "SELECT " + machineClientColumns + `,"scopes","requirePKCE" FROM "oauthClient"` + localClientFilter
	client.MachineClient, err = scanMachineClient(tx.QueryRowContext(ctx, s.readForUpdate(clientSelect), clientID), clientID, &registeredScopes, &client.RequirePKCE)
	if err != nil {
		return err
	}
	if err := checkClient(client.MachineClient); err != nil {
		return err
	}
	if registeredScopes != nil {
		if err := json.Unmarshal(registeredScopes, &client.Scopes); err != nil {
			return err
		}
	}
	matches := `"identifier"=` + s.exactSQLValue("?")
	var value []byte
	var expires time.Time
	read := `SELECT "value","expiresAt" FROM "verification" WHERE ` + matches + ` ORDER BY "createdAt" DESC,"id" DESC LIMIT 1`
	err = tx.QueryRowContext(ctx, s.readForUpdate(read), identifier).Scan(&value, &expires)
	if errors.Is(err, sql.ErrNoRows) || err == nil && !expires.After(time.Now()) {
		where := ` WHERE "clientId"=` + s.exactSQLValue("?") + ` AND "authorizationCodeId"=` + s.exactSQLValue("?")
		for _, table := range []string{`"oauthAccessToken"`, `"oauthRefreshToken"`} {
			if _, err := tx.ExecContext(ctx, s.bind("DELETE FROM "+table+where), clientID, identifier); err != nil {
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		return op.ErrAuthorizationCodeInvalid
	}
	if err != nil {
		return err
	}
	record, err := prepare(client, value)
	if err != nil {
		return err
	}
	var userID, sessionOwner string
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id" FROM "user" WHERE "id"=`+s.exactSQLValue("?")), record.UserID).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return op.ErrAuthorizationUserMissing
	}
	if err != nil {
		return err
	}
	var sessionEnd time.Time
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "userId","expiresAt" FROM "session" WHERE "id"=`+s.exactSQLValue("?")), record.SessionID).Scan(&sessionOwner, &sessionEnd)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (sessionOwner != userID || !sessionEnd.After(time.Now())) {
		return op.ErrAuthorizationSessionExpired
	}
	if err != nil {
		return err
	}
	if !expires.After(time.Now()) {
		return op.ErrAuthorizationCodeInvalid
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE `+matches), identifier); err != nil {
		return err
	}
	scopes, err := json.Marshal(record.Scopes)
	if err != nil {
		return err
	}
	const insert = `INSERT INTO "oauthAccessToken" ("id","token","clientId","userId","sessionId","referenceId","authorizationCodeId","scopes","createdAt","expiresAt") VALUES (?,?,?,?,?,?,?,?,?,?)`
	if _, err := tx.ExecContext(ctx, s.bind(insert), rand.Text(), record.StoredToken, clientID, userID, record.SessionID, record.ReferenceID, identifier, string(scopes), s.date(record.IssuedAt), s.date(record.ExpiresAt)); err != nil {
		return err
	}
	return tx.Commit()
}
