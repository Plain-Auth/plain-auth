package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

var _ op.GrantTokenStore = (*Store)(nil)

// pendingGrant carries an extension grant's first pass to its second.
type pendingGrant struct {
	issue                 op.DelegatedTokenIssue
	deferred, prepared    bool
	storedRefresh, userID string
}

// StoreGrantTokens stores the tokens an extension grant issues for a user,
// as a code exchange does without a code: a refresh token, an ID token or
// host fields are made between two passes, outside the transaction.
func (s *Store) StoreGrantTokens(ctx context.Context, clientID string, check func(op.MachineClient) error, prepare func(op.AuthorizationCodeClient) (op.DelegatedAccessRecord, error), issue func(op.DelegatedTokenIssue) (string, error)) error {
	var pending pendingGrant
	if err := s.storeGrant(ctx, clientID, check, prepare, &pending); err != nil || !pending.deferred {
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
	return s.storeGrant(ctx, clientID, check, prepare, &pending)
}

func (s *Store) storeGrant(ctx context.Context, clientID string, check func(op.MachineClient) error, prepare func(op.AuthorizationCodeClient) (op.DelegatedAccessRecord, error), pending *pendingGrant) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	client, err := s.readDelegatedClient(ctx, tx, clientID, check)
	if err != nil {
		return err
	}
	record, err := prepare(client)
	if err != nil {
		return err
	}
	var userID string
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id" FROM "user" WHERE "id"=`+s.exactSQLValue("?")), record.UserID).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return op.ErrAuthorizationUserMissing
	}
	if err != nil {
		return err
	}
	// A grant names a session only to bind its tokens to it, which must be
	// the user's and live.
	var session *string
	if record.SessionID != "" {
		var owner string
		var start, end time.Time
		err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "userId","createdAt","expiresAt" FROM "session" WHERE "id"=`+s.exactSQLValue("?")), record.SessionID).Scan(&owner, &start, &end)
		if errors.Is(err, sql.ErrNoRows) || err == nil && (owner != userID || !end.After(time.Now())) {
			return op.ErrAuthorizationSessionExpired
		}
		if err != nil {
			return err
		}
		if record.IDToken.Subject != "" && record.IDToken.AuthTime.IsZero() {
			record.IDToken.AuthTime = start.UTC()
		}
		if record.Refresh != nil && record.Refresh.AuthTime == nil {
			record.Refresh.AuthTime = &start
		}
		session = &record.SessionID
	}
	if record.IDTokenUserFields != nil {
		record.IDToken.ClaimsInput, err = s.idTokenClaimsSnapshot(ctx, tx, userID, client, record)
		if err != nil {
			return err
		}
	}
	issue := op.DelegatedTokenIssue{SessionID: record.SessionID, Refresh: record.Refresh != nil, IDToken: record.IDToken, Deferred: record.Deferred}
	if pending.prepared {
		if pending.issue != issue || pending.userID != userID {
			return op.ErrGrantChanged
		}
	} else if issue.Refresh || issue.IDToken.Subject != "" || issue.Deferred {
		// Release row locks before key generation, signing or host callbacks.
		pending.issue, pending.userID, pending.deferred = issue, userID, true
		return nil
	}
	if err := s.insertDelegatedTokens(ctx, tx, clientID, nil, session, session, pending.storedRefresh, record); err != nil {
		return err
	}
	return tx.Commit()
}
