package sqlstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

var _ op.AuthorizationCodeStore = (*Store)(nil)
var _ op.OfflineAuthorizationCodeStore = (*Store)(nil)

func (s *Store) RedeemAuthorizationCode(ctx context.Context, clientID, identifier string, checkClient func(op.MachineClient) error, prepare func(op.AuthorizationCodeClient, json.RawMessage) (op.DelegatedAccessRecord, error)) error {
	return s.redeemCode(ctx, clientID, identifier, checkClient, prepare, nil)
}

type pendingOfflineCode struct {
	rowID, sessionID, storedRefresh string
	value                           []byte
}

func (s *Store) RedeemAuthorizationCodeWithRefresh(ctx context.Context, clientID, identifier string, checkClient func(op.MachineClient) error, prepare func(op.AuthorizationCodeClient, json.RawMessage) (op.DelegatedAccessRecord, error), issueRefresh func(string) (string, error)) error {
	var pending pendingOfflineCode
	if err := s.redeemCode(ctx, clientID, identifier, checkClient, prepare, &pending); err != nil || pending.rowID == "" {
		return err
	}
	digest, err := issueRefresh(pending.sessionID)
	if err != nil {
		return err
	}
	if digest == "" {
		return errors.New("sqlstore: empty refresh token digest")
	}
	pending.storedRefresh = digest
	return s.redeemCode(ctx, clientID, identifier, checkClient, prepare, &pending)
}

func (s *Store) redeemCode(ctx context.Context, clientID, identifier string, checkClient func(op.MachineClient) error, prepare func(op.AuthorizationCodeClient, json.RawMessage) (op.DelegatedAccessRecord, error), pending *pendingOfflineCode) error {
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
	var rowID string
	var expires time.Time
	read := `SELECT "id","value","expiresAt" FROM "verification" WHERE ` + matches + ` ORDER BY "createdAt" DESC,"id" DESC LIMIT 1`
	err = tx.QueryRowContext(ctx, s.readForUpdate(read), identifier).Scan(&rowID, &value, &expires)
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
	if pending != nil && pending.storedRefresh != "" && (rowID != pending.rowID || !bytes.Equal(pending.value, value)) {
		return op.ErrAuthorizationCodeInvalid
	}
	record, err := prepare(client, value)
	if err != nil {
		return err
	}
	if pending != nil && pending.storedRefresh != "" && (record.Refresh == nil || record.SessionID != pending.sessionID) {
		return op.ErrAuthorizationCodeInvalid
	}
	var userID, sessionOwner string
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id" FROM "user" WHERE "id"=`+s.exactSQLValue("?")), record.UserID).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return op.ErrAuthorizationUserMissing
	}
	if err != nil {
		return err
	}
	var sessionStart, sessionEnd time.Time
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "userId","createdAt","expiresAt" FROM "session" WHERE "id"=`+s.exactSQLValue("?")), record.SessionID).Scan(&sessionOwner, &sessionStart, &sessionEnd)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (sessionOwner != userID || !sessionEnd.After(time.Now())) {
		return op.ErrAuthorizationSessionExpired
	}
	if err != nil {
		return err
	}
	if !expires.After(time.Now()) {
		return op.ErrAuthorizationCodeInvalid
	}
	if record.Refresh != nil {
		if pending == nil {
			return errors.New("sqlstore: offline grant requires refresh token issuance")
		}
		if pending.storedRefresh == "" {
			// Release these locks before invoking application callbacks. On return
			// we verify the same code row and recheck its current permissions.
			pending.rowID, pending.sessionID, pending.value = rowID, record.SessionID, value
			return nil
		}
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE `+matches), identifier); err != nil {
		return err
	}
	scopes, err := json.Marshal(record.Scopes)
	if err != nil {
		return err
	}
	var claims *string
	if len(record.RequestedUserInfoClaims) > 0 {
		b, err := json.Marshal(record.RequestedUserInfoClaims)
		if err != nil {
			return err
		}
		encoded := string(b)
		claims = &encoded
	}
	var refreshID *string
	if refresh := record.Refresh; refresh != nil {
		id := rand.Text()
		refreshID = &id
		authTime := sessionStart
		if refresh.AuthTime != nil {
			authTime = *refresh.AuthTime
		}
		const insertRefresh = `INSERT INTO "oauthRefreshToken" ("id","token","clientId","userId","sessionId","referenceId","authorizationCodeId","scopes","createdAt","expiresAt","authTime","requestedUserInfoClaims") VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
		if _, err := tx.ExecContext(ctx, s.bind(insertRefresh), id, pending.storedRefresh, clientID, userID, record.SessionID, record.ReferenceID, identifier, string(scopes), s.date(record.IssuedAt), s.date(refresh.ExpiresAt), s.date(authTime), claims); err != nil {
			return err
		}
	}
	const insert = `INSERT INTO "oauthAccessToken" ("id","token","clientId","userId","sessionId","referenceId","authorizationCodeId","scopes","createdAt","expiresAt","refreshId","requestedUserInfoClaims") VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
	if _, err := tx.ExecContext(ctx, s.bind(insert), rand.Text(), record.StoredToken, clientID, userID, record.SessionID, record.ReferenceID, identifier, string(scopes), s.date(record.IssuedAt), s.date(record.ExpiresAt), refreshID, claims); err != nil {
		return err
	}
	return tx.Commit()
}
