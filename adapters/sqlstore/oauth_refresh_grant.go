package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

var _ op.RefreshGrantStore = (*Store)(nil)

type pendingRotation struct {
	id, user, session string
	rotate            bool
	keys              op.RefreshGrantDigests
}

func (s *Store) ExchangeRefreshGrant(ctx context.Context, clientID, digest string, check func(op.MachineClient) error, prepare func(op.AuthorizationCodeClient, op.RefreshGrant) (op.DelegatedAccessRecord, error), issue func(string, bool) (op.RefreshGrantDigests, error)) error {
	var pending pendingRotation
	if err := s.exchangeRefresh(ctx, clientID, digest, check, prepare, &pending); err != nil {
		return err
	}
	keys, err := issue(pending.session, pending.rotate)
	if err != nil {
		return err
	}
	if keys.Access == "" || pending.rotate != (keys.Refresh != "") {
		return errors.New("sqlstore: invalid replacement token digests")
	}
	pending.keys = keys
	return s.exchangeRefresh(ctx, clientID, digest, check, prepare, &pending)
}

func (s *Store) exchangeRefresh(ctx context.Context, clientID, digest string, check func(op.MachineClient) error, prepare func(op.AuthorizationCodeClient, op.RefreshGrant) (op.DelegatedAccessRecord, error), pending *pendingRotation) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	client, err := s.readDelegatedClient(ctx, tx, clientID, check)
	if err != nil {
		return err
	}
	parent, err := s.readRefreshParent(ctx, tx, clientID, digest)
	if err != nil {
		return err
	}
	if pending.keys.Access != "" && (pending.id != parent.id || pending.user != parent.user || pending.session != parent.SessionID) {
		return op.ErrInvalidRefreshToken
	}
	record, err := prepare(client, parent.RefreshGrant)
	if err != nil {
		return err
	}
	if parent.revoked != nil {
		// Other issuers may have an active response-reuse interval. Never
		// clear the family within it, even if this issuer cannot replay it.
		if parent.rotatedAt == nil || parent.replayUntil == nil || time.Now().After(*parent.replayUntil) {
			param := s.exactSQLValue("?")
			if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "oauthRefreshToken" WHERE "clientId"=`+param+` AND "userId"=`+param), clientID, parent.user); err != nil {
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
		}
		return op.ErrInvalidRefreshToken
	}
	if pending.keys.Access == "" {
		pending.rotate = record.Refresh != nil
		pending.id, pending.user, pending.session = parent.id, parent.user, parent.SessionID
		return nil
	}
	if pending.rotate != (record.Refresh != nil) {
		return op.ErrInvalidRefreshToken
	}
	if record.Refresh != nil {
		record.Refresh.AuthTime = parent.authTime
		stamp := s.date(record.IssuedAt)
		res, err := tx.ExecContext(ctx, s.bind(`UPDATE "oauthRefreshToken" SET "revoked"=?, "rotatedAt"=? WHERE "id"=`+s.exactSQLValue("?")+` AND "revoked" IS NULL`), stamp, stamp, parent.id)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return op.ErrInvalidRefreshToken
		}
	}
	record.StoredToken = pending.keys.Access
	record.UserID, record.ReferenceID, record.RequestedUserInfoClaims = parent.user, parent.reference, parent.claims
	var liveSession *string
	if parent.SessionLive {
		liveSession = parent.session
	}
	if err := s.insertDelegatedTokens(ctx, tx, clientID, parent.code, liveSession, parent.session, pending.keys.Refresh, record); err != nil {
		return err
	}
	return tx.Commit()
}

type refreshParent struct {
	op.RefreshGrant
	id, user                                  string
	code, session, reference                  *string
	authTime, revoked, rotatedAt, replayUntil *time.Time
	claims                                    []string
}

func (s *Store) readRefreshParent(ctx context.Context, tx *sql.Tx, clientID, digest string) (refreshParent, error) {
	var parent refreshParent
	var expires time.Time
	var scopes, resources, claims, confirmation []byte
	param := s.exactSQLValue("?")
	query := `SELECT "id","userId","sessionId","authorizationCodeId","referenceId","authTime","revoked","rotatedAt","rotationReplayExpiresAt","expiresAt","scopes","resources","requestedUserInfoClaims","confirmation" FROM "oauthRefreshToken" WHERE "clientId"=` + param + ` AND "token"=` + param
	err := tx.QueryRowContext(ctx, s.readForUpdate(query), clientID, digest).Scan(&parent.id, &parent.user, &parent.session, &parent.code, &parent.reference, &parent.authTime, &parent.revoked, &parent.rotatedAt, &parent.replayUntil, &expires, &scopes, &resources, &claims, &confirmation)
	if errors.Is(err, sql.ErrNoRows) {
		return parent, op.ErrInvalidRefreshToken
	}
	if err != nil {
		return parent, err
	}
	parent.SenderBound = len(confirmation) > 0 && string(confirmation) != "null"
	for _, field := range []struct {
		data  []byte
		names *[]string
	}{{scopes, &parent.Scopes}, {resources, &parent.Resources}, {claims, &parent.claims}} {
		if len(field.data) > 0 {
			if err := json.Unmarshal(field.data, field.names); err != nil {
				return parent, err
			}
		}
	}
	if parent.code != nil {
		parent.AuthorizationCodeID = *parent.code
	}
	if parent.session != nil {
		parent.SessionID = *parent.session
		var end time.Time
		err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "expiresAt" FROM "session" WHERE "id"=`+param+` AND "userId"=`+param), parent.SessionID, parent.user).Scan(&end)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return parent, err
		}
		parent.SessionLive = err == nil && end.After(time.Now())
	}
	if !expires.After(time.Now()) {
		return parent, op.ErrInvalidRefreshToken
	}
	return parent, nil
}
