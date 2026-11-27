package sqlstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

var _ op.OpenIDGrantStore = (*Store)(nil)
var _ op.AuthorizationCodeStore = (*Store)(nil)
var _ op.OfflineAuthorizationCodeStore = (*Store)(nil)

func (s *Store) RedeemAuthorizationCode(ctx context.Context, clientID, identifier string, checkClient func(op.MachineClient) error, prepare func(op.AuthorizationCodeClient, json.RawMessage) (op.DelegatedAccessRecord, error)) error {
	return s.redeemCode(ctx, clientID, identifier, checkClient, prepare, nil)
}

type pendingOfflineCode struct {
	rowID, storedRefresh string
	value                []byte
	issue                op.DelegatedTokenIssue
	prepared             bool
}

func (s *Store) RedeemAuthorizationCodeWithRefresh(ctx context.Context, clientID, identifier string, checkClient func(op.MachineClient) error, prepare func(op.AuthorizationCodeClient, json.RawMessage) (op.DelegatedAccessRecord, error), issueRefresh func(string) (string, error)) error {
	return s.RedeemOpenIDCode(ctx, clientID, identifier, checkClient, prepare, func(grant op.DelegatedTokenIssue) (string, error) {
		if grant.IDToken.Subject != "" {
			return "", errors.New("sqlstore: ID token requires an OpenID code exchange")
		}
		return issueRefresh(grant.SessionID)
	})
}

func (s *Store) RedeemOpenIDCode(ctx context.Context, clientID, identifier string, checkClient func(op.MachineClient) error, prepare func(op.AuthorizationCodeClient, json.RawMessage) (op.DelegatedAccessRecord, error), issue func(op.DelegatedTokenIssue) (string, error)) error {
	var pending pendingOfflineCode
	if err := s.redeemCode(ctx, clientID, identifier, checkClient, prepare, &pending); err != nil || pending.rowID == "" {
		return err
	}
	digest, err := issue(pending.issue)
	if err != nil {
		return err
	}
	if pending.issue.Refresh != (digest != "") {
		return errors.New("sqlstore: unexpected refresh token digest")
	}
	pending.storedRefresh, pending.prepared = digest, true
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
	client, err := s.readDelegatedClient(ctx, tx, clientID, checkClient)
	if err != nil {
		return err
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
	if pending != nil && pending.prepared && (rowID != pending.rowID || !bytes.Equal(pending.value, value)) {
		return op.ErrAuthorizationCodeInvalid
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
	if record.IDToken.Subject != "" && record.IDToken.AuthTime.IsZero() {
		record.IDToken.AuthTime = sessionStart.UTC()
	}
	if record.IDTokenUserFields != nil {
		record.IDToken.ClaimsInput, err = s.idTokenClaimsSnapshot(ctx, tx, userID, client, record)
		if err != nil {
			return err
		}
	}
	// Asked in every pass, after every check that could refuse; a two-pass
	// grant's second pass asks about the same row and gets the kept answer.
	if ok, err := auth.VerificationGateFrom(ctx).Delete(op.AuthorizationCodeRecord(rowID, userID, expires)); err != nil {
		return err
	} else if !ok {
		return op.ErrAuthorizationCodeInvalid // a declined spend keeps the code and revokes nothing
	}
	issue := op.DelegatedTokenIssue{SessionID: record.SessionID, Refresh: record.Refresh != nil, IDToken: record.IDToken, Deferred: record.Deferred}
	if pending != nil && pending.prepared {
		if pending.issue != issue {
			return op.ErrAuthorizationCodeInvalid
		}
	} else if issue.Refresh || issue.IDToken.Subject != "" || issue.Deferred {
		if pending == nil {
			return errors.New("sqlstore: grant requires deferred token issuance")
		}
		// Release row locks before key generation, signing or host callbacks.
		// Recheck the precise grant and its current identity before spending it.
		pending.rowID, pending.issue, pending.value = rowID, issue, value
		return nil
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE `+matches), identifier); err != nil {
		return err
	}
	var refreshDigest string
	if record.Refresh != nil {
		refreshDigest = pending.storedRefresh
		if record.Refresh.AuthTime == nil {
			record.Refresh.AuthTime = &sessionStart
		}
	}
	if err := s.insertDelegatedTokens(ctx, tx, clientID, &identifier, &record.SessionID, &record.SessionID, refreshDigest, record); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) insertDelegatedTokens(ctx context.Context, tx *sql.Tx, clientID string, codeID, accessSessionID, refreshSessionID *string, refreshDigest string, record op.DelegatedAccessRecord) error {
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
		var authTime any
		if refresh.AuthTime != nil {
			authTime = s.date(*refresh.AuthTime)
		}
		resources, err := resourceColumn(refresh.Resources)
		if err != nil {
			return err
		}
		const insertRefresh = `INSERT INTO "oauthRefreshToken" ("id","token","clientId","userId","sessionId","referenceId","authorizationCodeId","scopes","createdAt","expiresAt","authTime","requestedUserInfoClaims","resources","confirmation") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
		if _, err := tx.ExecContext(ctx, s.bind(insertRefresh), id, refreshDigest, clientID, record.UserID, refreshSessionID, record.ReferenceID, codeID, string(scopes), s.date(record.IssuedAt), s.date(refresh.ExpiresAt), authTime, claims, resources, confirmationColumn(record.Thumbprint)); err != nil {
			return err
		}
	}
	// A signed access token is not stored.
	if record.StoredToken == "" {
		return nil
	}
	resources, err := resourceColumn(record.Resources)
	if err != nil {
		return err
	}
	const insert = `INSERT INTO "oauthAccessToken" ("id","token","clientId","userId","sessionId","referenceId","authorizationCodeId","scopes","createdAt","expiresAt","refreshId","requestedUserInfoClaims","resources","confirmation") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
	_, err = tx.ExecContext(ctx, s.bind(insert), rand.Text(), record.StoredToken, clientID, record.UserID, accessSessionID, record.ReferenceID, codeID, string(scopes), s.date(record.IssuedAt), s.date(record.ExpiresAt), refreshID, claims, resources, confirmationColumn(record.Thumbprint))
	return err
}

// confirmationColumn encodes a DPoP binding, or NULL for none.
func confirmationColumn(thumb string) sql.NullString {
	if thumb == "" {
		return sql.NullString{}
	}
	raw, _ := json.Marshal(map[string]string{"jkt": thumb})
	return sql.NullString{String: string(raw), Valid: true}
}

// resourceColumn encodes a token's resources, or NULL for none.
func resourceColumn(ids []string) (sql.NullString, error) {
	if len(ids) == 0 {
		return sql.NullString{}, nil
	}
	raw, err := json.Marshal(ids)
	return sql.NullString{String: string(raw), Valid: err == nil}, err
}

func (s *Store) readDelegatedClient(ctx context.Context, tx *sql.Tx, clientID string, check func(op.MachineClient) error) (op.AuthorizationCodeClient, error) {
	var client op.AuthorizationCodeClient
	var registeredScopes, redirects []byte
	var subject, logoutURI sql.NullString
	var logout sql.NullBool
	const clientSelect = "SELECT " + machineClientColumns + `,"scopes","requirePKCE","subjectType","redirectUris","enableEndSession","backchannelLogoutUri" FROM "oauthClient"` + localClientFilter
	var err error
	client.MachineClient, err = scanMachineClient(tx.QueryRowContext(ctx, s.readForUpdate(clientSelect), clientID), clientID, &registeredScopes, &client.RequirePKCE, &subject, &redirects, &logout, &logoutURI)
	if err != nil {
		return client, err
	}
	if err := check(client.MachineClient); err != nil {
		return client, err
	}
	client.SubjectType = subject.String
	client.EmitSessionID = logout.Bool || logoutURI.String != ""
	if client.SubjectType == "pairwise" && len(redirects) != 0 {
		if err := json.Unmarshal(redirects, &client.RedirectURIs); err != nil {
			return client, err
		}
	}
	if registeredScopes != nil {
		if err := json.Unmarshal(registeredScopes, &client.Scopes); err != nil {
			return client, err
		}
	}
	return client, nil
}
