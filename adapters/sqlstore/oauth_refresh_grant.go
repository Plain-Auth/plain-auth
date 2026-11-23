package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

var _ op.RefreshGrantStore = (*Store)(nil)

type pendingRotation struct {
	id, user string
	issue    op.DelegatedTokenIssue
	scopes   []string
	keys     op.RefreshGrantDigests
}

func (s *Store) ExchangeRefreshGrant(ctx context.Context, clientID, digest string, check func(op.MachineClient) error, prepare func(op.AuthorizationCodeClient, op.RefreshGrant) (op.DelegatedAccessRecord, error), issue func(string, bool) (op.RefreshGrantDigests, error)) error {
	return s.ExchangeOpenIDRefresh(ctx, clientID, digest, check, prepare, func(grant op.DelegatedTokenIssue) (op.RefreshGrantDigests, error) {
		if grant.IDToken.Subject != "" {
			return op.RefreshGrantDigests{}, errors.New("sqlstore: ID token requires an OpenID refresh exchange")
		}
		return issue(grant.SessionID, grant.Refresh)
	})
}

func (s *Store) ExchangeOpenIDRefresh(ctx context.Context, clientID, digest string, check func(op.MachineClient) error, prepare func(op.AuthorizationCodeClient, op.RefreshGrant) (op.DelegatedAccessRecord, error), issue func(op.DelegatedTokenIssue) (op.RefreshGrantDigests, error)) error {
	var pending pendingRotation
	if err := s.exchangeRefresh(ctx, clientID, digest, check, prepare, &pending); err != nil {
		return err
	}
	keys, err := issue(pending.issue)
	if err != nil {
		return err
	}
	if keys.Access == "" || pending.issue.Refresh != (keys.Refresh != "") {
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
	if pending.keys.Access != "" && (pending.id != parent.id || pending.user != parent.UserID || pending.issue.SessionID != parent.SessionID) {
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
			if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "oauthRefreshToken" WHERE "clientId"=`+param+` AND "userId"=`+param), clientID, parent.UserID); err != nil {
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
		}
		return op.ErrInvalidRefreshToken
	}
	if record.IDTokenUserFields != nil {
		record.IDToken.ClaimsInput, err = s.idTokenClaimsSnapshot(ctx, tx, parent.UserID, client, record)
		if err != nil {
			return err
		}
	}
	grant := op.DelegatedTokenIssue{SessionID: parent.SessionID, Refresh: record.Refresh != nil, IDToken: record.IDToken}
	if pending.keys.Access == "" {
		pending.id, pending.user, pending.issue = parent.id, parent.UserID, grant
		pending.scopes = slices.Clone(record.Scopes)
		return nil
	}
	if pending.issue != grant || !slices.Equal(pending.scopes, record.Scopes) {
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
	record.UserID, record.ReferenceID, record.RequestedUserInfoClaims = parent.UserID, parent.reference, parent.claims
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
	id                                        string
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
	err := tx.QueryRowContext(ctx, s.readForUpdate(query), clientID, digest).Scan(&parent.id, &parent.UserID, &parent.session, &parent.code, &parent.reference, &parent.authTime, &parent.revoked, &parent.rotatedAt, &parent.replayUntil, &expires, &scopes, &resources, &claims, &confirmation)
	if errors.Is(err, sql.ErrNoRows) {
		return parent, op.ErrInvalidRefreshToken
	}
	if err != nil {
		return parent, err
	}
	if parent.authTime != nil {
		parent.AuthTime = parent.authTime.UTC()
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
	if slices.Contains(parent.Scopes, "openid") {
		// Lock the account before its session, as code redemption does.
		var user string
		err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id" FROM "user" WHERE "id"=`+param), parent.UserID).Scan(&user)
		if errors.Is(err, sql.ErrNoRows) {
			return parent, op.ErrInvalidRefreshToken
		}
		if err != nil {
			return parent, err
		}
	}
	if parent.session != nil {
		parent.SessionID = *parent.session
		var end time.Time
		err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "expiresAt" FROM "session" WHERE "id"=`+param+` AND "userId"=`+param), parent.SessionID, parent.UserID).Scan(&end)
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
