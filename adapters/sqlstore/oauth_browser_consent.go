package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"time"

	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

var _ op.BrowserConsentStore = (*Store)(nil)

const browserConsentKey = "oauth-browser-consent"

func (s *Store) SaveBrowserConsent(ctx context.Context, p op.BrowserConsentPrompt) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.date(time.Now().UTC())
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier"=? AND "expiresAt"<=?`), browserConsentKey, now); err != nil {
		return err
	}
	id := s.verificationReservationID(browserConsentKey + ":" + p.ID)
	const insert = `INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`
	if _, err := tx.ExecContext(ctx, s.bind(insert), id, browserConsentKey, p.Binding, s.date(p.ExpiresAt), now, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) consumeConsentPrompt(ctx context.Context, tx *sql.Tx, p op.BrowserConsentPrompt, now time.Time) error {
	id := s.verificationReservationID(browserConsentKey + ":" + p.ID)
	res, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=? AND "value"=`+s.exactSQLValue("?")+` AND "expiresAt">?`), id, browserConsentKey, p.Binding, s.date(now))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return op.ErrBrowserConsentExpired
	}
	return nil
}

func (s *Store) writeBrowserConsent(ctx context.Context, tx *sql.Tx, input op.BrowserCodeIssue, existingID string, now time.Time) error {
	scopes := input.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	data, err := json.Marshal(scopes)
	if err != nil {
		return err
	}
	claims := input.RequestedUserInfoClaims
	if claims == nil {
		claims = []string{}
	}
	approved, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	when := s.date(now.UTC().Truncate(time.Second))
	if existingID != "" {
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE "oauthConsent" SET "scopes"=?,"resources"=NULL,"requestedUserInfoClaims"=?,"updatedAt"=? WHERE "id"=?`), string(data), string(approved), when, existingID)
		return err
	}
	var ref any
	if input.ReferenceID != "" {
		ref = input.ReferenceID
	}
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "oauthConsent" ("id","userId","clientId","referenceId","scopes","requestedUserInfoClaims","createdAt","updatedAt") VALUES (?,?,?,?,?,?,?,?)`), rand.Text(), input.UserID, input.Client.ClientID, ref, string(data), string(approved), when, when)
	return err
}
