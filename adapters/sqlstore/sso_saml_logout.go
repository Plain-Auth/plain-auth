package sqlstore

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/sso"
)

const samlSessionKind = "saml-logout-session"
const samlRequestKind = "saml-logout-request"

type samlSessionRecord struct {
	SessionID, UserID, TokenDigest, ProviderID, Reference string
	Identity                                              sso.SAMLLogoutIdentity
}

func (s *Store) putSAMLRecord(ctx context.Context, tx *sql.Tx, id, kind string, value any, now, expires time.Time) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	// Restrict expiration to this feature's short-lived records in the shared table.
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier"=? AND "expiresAt"<=?`), kind, s.date(now)); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), id, kind, string(raw), s.date(expires), s.date(now), s.date(now))
	return err
}

func (s *Store) recordSAMLSession(ctx context.Context, tx *sql.Tx, provider, reference, userID, subject string, identity sso.SAMLLogoutIdentity, session auth.StoredSession) error {
	if session.ID == "" || session.Token == "" || userID == "" || reference == "" || !identity.Valid(subject) {
		return sso.ErrInvalidSAML
	}
	record := samlSessionRecord{SessionID: session.ID, UserID: userID, TokenDigest: originDigest("slt-", session.Token), ProviderID: provider, Reference: reference, Identity: identity}
	return s.putSAMLRecord(ctx, tx, originDigest("sls-", session.ID), samlSessionKind, record, session.CreatedAt, session.ExpiresAt)
}

func (s *Store) lockedLogoutProvider(ctx context.Context, tx *sql.Tx, id, ref string) (sso.BrowserProvider, error) {
	q := `SELECT ` + browserProviderCols + ` FROM "ssoProvider" p WHERE ` + browserProviderWhere + ` AND ` + s.scimExact(`p."providerId"`) + `=?`
	p, err := scanBrowserProvider(tx.QueryRowContext(ctx, s.readForUpdate(q), id))
	if errors.Is(err, sql.ErrNoRows) || err == nil && (p.SAML == nil || p.Reference != ref || ref == "" || p.ProviderID != id) {
		return p, sso.ErrChanged
	}
	return p, err
}

func (s *Store) lockedSAMLSession(ctx context.Context, tx *sql.Tx, actor sso.Actor, provider, ref string, now time.Time) (samlSessionRecord, sso.BrowserProvider, error) {
	var record samlSessionRecord
	var p sso.BrowserProvider
	if actor.UserID == "" || actor.SessionID == "" || actor.SessionToken == "" {
		return record, p, sso.ErrSAMLLogoutSession
	}
	err := s.lockActiveAccount(ctx, tx, actor.UserID, actor.SessionToken, now)
	if errors.Is(err, auth.ErrNotFound) {
		return record, p, sso.ErrSAMLLogoutSession
	}
	if err != nil {
		return record, p, err
	}
	p, err = s.lockedLogoutProvider(ctx, tx, provider, ref)
	if err != nil {
		return record, p, err
	}
	var raw string
	exactToken, _ := s.deviceTokenParameters([]string{actor.SessionToken})
	q := `SELECT v."value" FROM "verification" v WHERE v."id"=? AND v."identifier"=? AND v."expiresAt">? AND EXISTS (SELECT 1 FROM "session" s WHERE ` + s.scimExact(`s."id"`) + `=? AND ` + s.scimExact(`s."userId"`) + `=? AND s."token"=` + exactToken + `)`
	err = tx.QueryRowContext(ctx, s.readForUpdate(q), originDigest("sls-", actor.SessionID), samlSessionKind, s.date(now), actor.SessionID, actor.UserID, actor.SessionToken).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return record, p, sso.ErrSAMLLogoutSession
	}
	if err != nil {
		return record, p, err
	}
	if json.Unmarshal([]byte(raw), &record) != nil || record.SessionID != actor.SessionID || record.UserID != actor.UserID || record.TokenDigest != originDigest("slt-", actor.SessionToken) || record.ProviderID != provider || record.Reference != ref {
		return record, p, sso.ErrSAMLLogoutSession
	}
	return record, p, nil
}

func (s *Store) SAMLSessionForLogout(ctx context.Context, actor sso.Actor, provider, reference string, now time.Time) (sso.SAMLLogoutIdentity, error) {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return sso.SAMLLogoutIdentity{}, err
	}
	defer tx.Rollback()
	rec, _, err := s.lockedSAMLSession(ctx, tx, actor, provider, reference, now)
	return rec.Identity, err
}

func (s *Store) StartSAMLLogout(ctx context.Context, actor sso.Actor, identity sso.SAMLLogoutIdentity, pending sso.SAMLLogoutRequest, requireProof bool, now time.Time) error {
	if pending.ID == "" || len(pending.ID) > 128 || len(pending.State) < 20 || len(pending.State) > 80 || len(pending.BrowserHash) != 64 || pending.CallbackURL == "" || !pending.ExpiresAt.After(now) {
		return sso.ErrSAMLLogoutResponse
	}
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rec, p, err := s.lockedSAMLSession(ctx, tx, actor, pending.ProviderID, pending.Reference, now)
	if err != nil {
		return err
	}
	if rec.Identity != identity {
		return sso.ErrSAMLLogoutSession
	}
	if !requireProof {
		requireProof, err = s.requiresSSODomain(ctx, tx, p.Provider)
		if err != nil {
			return err
		}
	}
	if requireProof {
		ok, err := s.domainVerified(ctx, tx, p.Provider, p.Reference)
		if err != nil {
			return err
		}
		if !ok {
			return sso.ErrDomainUnverified
		}
	}
	if err = s.putSAMLRecord(ctx, tx, originDigest("slr-", pending.State), samlRequestKind, pending, now, pending.ExpiresAt); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=?`), originDigest("sls-", actor.SessionID), samlSessionKind); err != nil {
		return err
	}
	exactToken, _ := s.deviceTokenParameters([]string{actor.SessionToken})
	result, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "session" WHERE `+s.scimExact(`"id"`)+`=? AND `+s.scimExact(`"userId"`)+`=? AND "token"=`+exactToken), actor.SessionID, actor.UserID, actor.SessionToken)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return sso.ErrSAMLLogoutSession
	}
	return tx.Commit()
}

func (s *Store) ConsumeSAMLLogout(ctx context.Context, proof sso.SAMLLogoutRequest, now time.Time) (string, error) {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err = s.lockedLogoutProvider(ctx, tx, proof.ProviderID, proof.Reference); err != nil {
		return "", err
	}
	id := originDigest("slr-", proof.State)
	var raw string
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "value" FROM "verification" WHERE "id"=? AND "identifier"=? AND "expiresAt">?`), id, samlRequestKind, s.date(now)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", sso.ErrSAMLLogoutResponse
	}
	if err != nil {
		return "", err
	}
	var p sso.SAMLLogoutRequest
	if json.Unmarshal([]byte(raw), &p) != nil || p.State != proof.State || p.ID != proof.ID || p.ProviderID != proof.ProviderID || p.Reference != proof.Reference || !p.ExpiresAt.After(now) || subtle.ConstantTimeCompare([]byte(p.BrowserHash), []byte(proof.BrowserHash)) != 1 {
		return "", sso.ErrSAMLLogoutResponse
	}
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=?`), id, samlRequestKind); err != nil {
		return "", err
	}
	return p.CallbackURL, tx.Commit()
}
