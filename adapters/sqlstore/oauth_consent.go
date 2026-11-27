package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

var _ op.ConsentStore = (*Store)(nil)

const consentSelect = `SELECT "id","clientId","userId","referenceId","resources","requestedUserInfoClaims","scopes","createdAt","updatedAt" FROM "oauthConsent"`
const consentByID = consentSelect + ` WHERE "id"=?`

func scanConsent(row rowScanner) (op.Consent, error) {
	var c op.Consent
	var resources, claims, scopes []byte
	err := row.Scan(&c.ID, &c.ClientID, &c.UserID, &c.ReferenceID, &resources, &claims, &scopes, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return c, auth.ErrNotFound
	}
	if err != nil {
		return c, err
	}
	for _, field := range []struct {
		raw []byte
		dst *[]string
	}{{resources, &c.Resources}, {claims, &c.RequestedUserInfoClaims}, {scopes, &c.Scopes}} {
		if field.raw != nil {
			if err := json.Unmarshal(field.raw, field.dst); err != nil {
				return op.Consent{}, err
			}
		}
	}
	return c, nil
}

func ownedConsent(row rowScanner, owner string) (op.Consent, error) {
	c, err := scanConsent(row)
	if err == nil && (c.UserID == nil || *c.UserID != owner) {
		return op.Consent{}, auth.StatusOnlyError(401)
	}
	return c, err
}

func (s *Store) OAuthConsent(ctx context.Context, owner, id string) (op.Consent, error) {
	return ownedConsent(s.db.QueryRowContext(ctx, s.bind(consentByID), id), owner)
}
func (s *Store) OAuthConsents(ctx context.Context, owner string) ([]op.Consent, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(consentSelect+` WHERE "userId"=? ORDER BY "id"`), owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	consents := []op.Consent{}
	for rows.Next() {
		c, err := ownedConsent(rows, owner)
		if err != nil {
			return nil, err
		}
		consents = append(consents, c)
	}
	return consents, rows.Err()
}

func (s *Store) UpdateOAuthConsent(ctx context.Context, owner, id string, scopes, providerScopes []string, now time.Time) (op.Consent, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return op.Consent{}, err
	}
	defer tx.Rollback()
	c, err := ownedConsent(tx.QueryRowContext(ctx, s.readForUpdate(consentByID), id), owner)
	if err != nil {
		return op.Consent{}, err
	}
	var clientScopes []byte
	var reference, clientOwner, discovery *string
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "scopes","referenceId","userId","clientDiscoveryId" FROM "oauthClient" WHERE "clientId"=?`), c.ClientID).Scan(&clientScopes, &reference, &clientOwner, &discovery)
	if errors.Is(err, sql.ErrNoRows) {
		return op.Consent{}, op.ErrClientNotFound
	}
	if err != nil {
		return op.Consent{}, err
	}
	if discovery != nil && *discovery != "" && *discovery != op.ResolvedDiscovery(ctx, c.ClientID) {
		return op.Consent{}, &op.UnresolvedClientError{ClientID: c.ClientID, DiscoveryID: *discovery}
	}
	var allowed []string
	if clientScopes != nil {
		if err := json.Unmarshal(clientScopes, &allowed); err != nil {
			return op.Consent{}, err
		}
	}
	if allowed == nil {
		allowed = providerScopes
	}
	for _, scope := range scopes {
		if !slices.Contains(allowed, scope) {
			who := "null"
			if reference != nil {
				who = *reference
			} else if clientOwner != nil {
				who = *clientOwner
			}
			return op.Consent{}, &auth.OAuthError{Status: 400, Code: "invalid_request", Description: "unable to provide scopes to " + who}
		}
	}
	if scopes == nil {
		scopes = []string{}
	}
	encoded, err := json.Marshal(scopes)
	if err != nil {
		return op.Consent{}, err
	}
	if _, err = tx.ExecContext(ctx, s.bind(`UPDATE "oauthConsent" SET "scopes"=?,"updatedAt"=? WHERE "id"=? AND "userId"=?`), string(encoded), s.date(now), id, owner); err != nil {
		return op.Consent{}, err
	}
	c.Scopes, c.UpdatedAt = scopes, now
	if err := tx.Commit(); err != nil {
		return op.Consent{}, err
	}
	return c, nil
}

func (s *Store) DeleteOAuthConsent(ctx context.Context, owner, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = ownedConsent(tx.QueryRowContext(ctx, s.readForUpdate(consentByID), id), owner); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "oauthConsent" WHERE "id"=? AND "userId"=?`), id, owner); err != nil {
		return err
	}
	return tx.Commit()
}
