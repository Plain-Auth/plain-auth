package sqlstore

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
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
	if s.sweeping() {
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier"=? AND "expiresAt"<=?`), kind, s.date(now)); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), id, kind, string(raw), s.date(expires), s.date(now), s.date(now))
	return err
}

func (s *Store) recordSAMLSession(ctx context.Context, tx *sql.Tx, provider, reference, userID, subject string, identity sso.SAMLLogoutIdentity, session auth.StoredSession) error {
	if session.ID == "" || session.Token == "" || userID == "" || reference == "" || !identity.Valid(subject) {
		return sso.ErrInvalidSAML
	}
	id := originDigest("sls-", session.ID)
	// A declined binding is not stored, and the sign-in goes on without
	// single logout.
	if ok, err := auth.VerificationGateFrom(ctx).Create(sso.LogoutSessionRecord(id, userID, session.ExpiresAt)); err != nil || !ok {
		return err
	}
	record := samlSessionRecord{SessionID: session.ID, UserID: userID, TokenDigest: originDigest("slt-", session.Token), ProviderID: provider, Reference: reference, Identity: identity}
	return s.putSAMLRecord(ctx, tx, id, samlSessionKind, record, session.CreatedAt, session.ExpiresAt)
}

func (s *Store) lockedLogoutProvider(ctx context.Context, tx *sql.Tx, id, ref string) (sso.BrowserProvider, error) {
	q := `SELECT ` + browserProviderCols + ` FROM "ssoProvider" p WHERE ` + browserProviderWhere + ` AND ` + s.scimExact(`p."providerId"`) + `=?`
	p, err := scanBrowserProvider(tx.QueryRowContext(ctx, s.readForUpdate(q), id))
	if errors.Is(err, sql.ErrNoRows) || err == nil && (p.SAML == nil || p.Reference != ref || ref == "" || p.ProviderID != id) {
		return p, sso.ErrChanged
	}
	return p, err
}

// lockedSAMLSession locks the actor's account, the provider and the actor
// session's logout binding, and returns the binding and its expiry.
func (s *Store) lockedSAMLSession(ctx context.Context, tx *sql.Tx, actor sso.Actor, provider, ref string, now time.Time) (samlSessionRecord, time.Time, sso.BrowserProvider, error) {
	var record samlSessionRecord
	var expires time.Time
	var p sso.BrowserProvider
	if actor.UserID == "" || actor.SessionID == "" || actor.SessionToken == "" {
		return record, expires, p, sso.ErrSAMLLogoutSession
	}
	err := s.lockActiveAccount(ctx, tx, actor.UserID, actor.SessionToken, now)
	if errors.Is(err, auth.ErrNotFound) {
		return record, expires, p, sso.ErrSAMLLogoutSession
	}
	if err != nil {
		return record, expires, p, err
	}
	p, err = s.lockedLogoutProvider(ctx, tx, provider, ref)
	if err != nil {
		return record, expires, p, err
	}
	var raw string
	exactToken, _ := s.deviceTokenParameters([]string{actor.SessionToken})
	q := `SELECT v."value",v."expiresAt" FROM "verification" v WHERE v."id"=? AND v."identifier"=? AND v."expiresAt">? AND EXISTS (SELECT 1 FROM "session" s WHERE ` + s.scimExact(`s."id"`) + `=? AND ` + s.scimExact(`s."userId"`) + `=? AND s."token"=` + exactToken + `)`
	err = tx.QueryRowContext(ctx, s.readForUpdate(q), originDigest("sls-", actor.SessionID), samlSessionKind, s.date(now), actor.SessionID, actor.UserID, actor.SessionToken).Scan(&raw, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return record, expires, p, sso.ErrSAMLLogoutSession
	}
	if err != nil {
		return record, expires, p, err
	}
	if json.Unmarshal([]byte(raw), &record) != nil || record.SessionID != actor.SessionID || record.UserID != actor.UserID || record.TokenDigest != originDigest("slt-", actor.SessionToken) || record.ProviderID != provider || record.Reference != ref {
		return record, expires, p, sso.ErrSAMLLogoutSession
	}
	return record, expires.UTC(), p, nil
}

func (s *Store) SAMLSessionForLogout(ctx context.Context, actor sso.Actor, provider, reference string, now time.Time) (sso.SAMLLogoutIdentity, error) {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return sso.SAMLLogoutIdentity{}, err
	}
	defer tx.Rollback()
	rec, _, _, err := s.lockedSAMLSession(ctx, tx, actor, provider, reference, now)
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
	rec, expires, p, err := s.lockedSAMLSession(ctx, tx, actor, pending.ProviderID, pending.Reference, now)
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
	gate := auth.VerificationGateFrom(ctx)
	requestID, bindingID := originDigest("slr-", pending.State), originDigest("sls-", actor.SessionID)
	// The request's create hooks and the binding's delete hooks run in one pass.
	keep, e1 := gate.Create(sso.LogoutRequestRecord(requestID, pending.ExpiresAt))
	drop, e2 := gate.Delete(sso.LogoutSessionRecord(bindingID, actor.UserID, expires))
	if err = errors.Join(e1, e2); err != nil {
		return err
	}
	// A declined request is not stored, so its LogoutResponse is refused; a
	// declined binding stays, unusable, until it expires. The session ends
	// either way.
	if keep {
		if err = s.putSAMLRecord(ctx, tx, requestID, samlRequestKind, pending, now, pending.ExpiresAt); err != nil {
			return err
		}
	}
	if drop {
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=?`), bindingID, samlSessionKind); err != nil {
			return err
		}
	}
	exactToken, _ := s.deviceTokenParameters([]string{actor.SessionToken})
	n, err := s.deleteSessionsTx(ctx, tx, s.scimExact(`"id"`)+`=? AND `+s.scimExact(`"userId"`)+`=? AND "token"=`+exactToken, actor.SessionID, actor.UserID, actor.SessionToken)
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
	var expires time.Time
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "value","expiresAt" FROM "verification" WHERE "id"=? AND "identifier"=? AND "expiresAt">?`), id, samlRequestKind, s.date(now)).Scan(&raw, &expires)
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
	// A declined spend keeps the request and refuses the response.
	if ok, err := auth.VerificationGateFrom(ctx).Delete(sso.LogoutRequestRecord(id, expires)); err != nil {
		return "", err
	} else if !ok {
		return "", sso.ErrSAMLLogoutResponse
	}
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=?`), id, samlRequestKind); err != nil {
		return "", err
	}
	return p.CallbackURL, tx.Commit()
}
