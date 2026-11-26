package sqlstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
)

var errSAMLSessionSetChanged = errors.New("SAML logout session set changed during locking")

// RevokeSAMLIDPSessions serializes incoming requests with login, SP logout and
// directory mutations across replicas. It does not authorize by browser cookie.
func (s *Store) RevokeSAMLIDPSessions(ctx context.Context, req sso.SAMLIDPLogout, browserToken string, requireProof bool, now time.Time) (bool, error) {
	if !req.ValidAt(now) {
		return false, sso.ErrSAMLLogoutRequest
	}
	started := time.Now()
	var err error
	for range 3 {
		var cleared bool
		cleared, err = s.revokeIDPLogout(ctx, req, browserToken, requireProof, now, started)
		if !errors.Is(err, errSAMLSessionSetChanged) && !retryIdentity(err) {
			return cleared, err
		}
	}
	return false, err
}

// Other verification kinds may contain arbitrary non-JSON text. Callers supply
// only the fixed field paths of a local SAML session receipt.
func (s *Store) samlReceiptField(path string) string {
	const payload = `(CASE WHEN "identifier"='saml-logout-session' THEN "value" ELSE '{}' END)`
	switch s.dialect {
	case "postgres":
		return "(" + payload + "::jsonb #>> '{" + strings.ReplaceAll(path, ".", ",") + "}')"
	case "mysql":
		return "BINARY JSON_UNQUOTE(JSON_EXTRACT(" + payload + ", '$." + path + "'))"
	default:
		return "json_extract(" + payload + ", '$." + path + "')"
	}
}

// matchingSAMLReceipts returns the logout bindings req names, and their
// expiries by session ID, kept apart so that a renewal between two reads
// does not change the compared records.
func (s *Store) matchingSAMLReceipts(ctx context.Context, tx *sql.Tx, req sso.SAMLIDPLogout, now time.Time) ([]samlSessionRecord, map[string]time.Time, error) {
	q := `SELECT "id","value","expiresAt" FROM "verification" WHERE "identifier"=? AND "expiresAt">? AND ` + s.samlReceiptField("Reference") + `=? AND ` + s.samlReceiptField("Identity.NameID.Value") + `=? AND ` + s.samlReceiptField("Identity.SessionIndex") + `=? ORDER BY "id"`
	rows, err := tx.QueryContext(ctx, s.bind(q), samlSessionKind, s.date(now), req.Reference, req.Identity.NameID.Value, req.Identity.SessionIndex)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var records []samlSessionRecord
	expiries := map[string]time.Time{}
	for rows.Next() {
		var raw, id string
		var expires time.Time
		if err := rows.Scan(&id, &raw, &expires); err != nil {
			return nil, nil, err
		}
		var rec samlSessionRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			return nil, nil, err
		}
		if rec.Reference != req.Reference || rec.ProviderID != req.ProviderID || rec.Identity != req.Identity {
			continue
		}
		if rec.SessionID == "" || rec.UserID == "" || rec.TokenDigest == "" || id != originDigest("sls-", rec.SessionID) {
			return nil, nil, sso.ErrSAMLLogoutRequest
		}
		records = append(records, rec)
		expiries[rec.SessionID] = expires.UTC()
	}
	return records, expiries, rows.Err()
}

func (s *Store) revokeIDPLogout(ctx context.Context, req sso.SAMLIDPLogout, browserToken string, requireProof bool, now, started time.Time) (bool, error) {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	gate := auth.VerificationGateFrom(ctx)
	gate.Attempt() // an attempt RevokeSAMLIDPSessions retries asks afresh
	records, _, err := s.matchingSAMLReceipts(ctx, tx, req, now)
	if err != nil {
		return false, err
	}
	// Match the lock order used by browser logout and provider administration.
	// Lock existing sessions before their directory, then recheck the set.
	// A login that committed in between is included on the next attempt.
	type lockedSession struct {
		record samlSessionRecord
		token  string
	}
	locked := make(map[string]lockedSession, len(records))
	sessionWhere := s.scimExact(`"id"`) + `=? AND ` + s.scimExact(`"userId"`) + `=?`
	for _, rec := range records {
		var token string
		err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "token" FROM "session" WHERE `+sessionWhere), rec.SessionID, rec.UserID).Scan(&token)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
		if originDigest("slt-", token) != rec.TokenDigest {
			token = ""
		}
		locked[rec.SessionID] = lockedSession{record: rec, token: token}
	}
	p, err := s.lockedLogoutProvider(ctx, tx, req.ProviderID, req.Reference)
	if err != nil {
		return false, err
	}
	if !p.SAML.MetadataValidAt(now) || p.SAML.IdentityProviderEntityID() != req.Issuer {
		return false, sso.ErrSAMLLogoutRequest
	}
	if !requireProof {
		requireProof, err = s.requiresSSODomain(ctx, tx, p.Provider)
		if err != nil {
			return false, err
		}
	}
	if requireProof {
		valid, err := s.domainVerified(ctx, tx, p.Provider, p.Reference)
		if err != nil {
			return false, err
		}
		if !valid {
			return false, sso.ErrDomainUnverified
		}
	}
	records, expiries, err := s.matchingSAMLReceipts(ctx, tx, req, now)
	if err != nil {
		return false, err
	}
	key, _ := json.Marshal([]string{"saml-idp-logout", p.ID, req.Issuer, req.ID})
	if err = s.claimIDToken(ctx, tx, p.ProviderID, sha256.Sum256(key), now, now.Add(24*time.Hour)); errors.Is(err, auth.ErrIDTokenUsed) {
		return false, sso.ErrSAMLLogoutRequest
	} else if err != nil {
		return false, err
	}
	for _, rec := range records {
		if previous, ok := locked[rec.SessionID]; !ok || previous.record != rec {
			return false, errSAMLSessionSetChanged
		}
	}
	drop := make(map[string]bool, len(records))
	var asked error
	for _, rec := range records {
		// Every binding is asked about before any stop, so their hooks run
		// in one pass.
		ok, err := gate.Delete(sso.LogoutSessionRecord(originDigest("sls-", rec.SessionID), rec.UserID, expiries[rec.SessionID]))
		asked, drop[rec.SessionID] = errors.Join(asked, err), ok
	}
	if asked != nil {
		return false, asked
	}
	cleared := false
	for _, rec := range records {
		token := locked[rec.SessionID].token
		if token != "" {
			param, _ := s.deviceTokenParameters([]string{token})
			n, err := s.deleteSessionsTx(ctx, tx, sessionWhere+` AND "token"=`+param, rec.SessionID, rec.UserID, token)
			if err != nil {
				return false, err
			}
			cleared = cleared || n == 1 && token == browserToken
		}
		if !drop[rec.SessionID] {
			continue // a declined binding stays, unusable, until it expires
		}
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=?`), originDigest("sls-", rec.SessionID), samlSessionKind); err != nil {
			return false, err
		}
	}
	atCommit := now.Add(time.Since(started))
	if !req.ValidAt(atCommit) || !p.SAML.MetadataValidAt(atCommit) {
		return false, sso.ErrSAMLLogoutRequest
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return cleared, nil
}
