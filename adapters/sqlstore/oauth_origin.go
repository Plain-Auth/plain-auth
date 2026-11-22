package sqlstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/sso"
)

type oauthAuthority struct {
	Kind, RecordID, Issuer, OrganizationID string
	Protocol                               string `json:",omitempty"`
}

func providerAuthority(p sso.Provider) oauthAuthority {
	a := enterpriseAuthority(p.ID, p.Issuer, p.OrganizationID)
	if p.SAML != nil {
		a.Protocol = "saml"
		a.Issuer = p.SAML.IdentityProviderEntityID()
	}
	return a
}

func enterpriseAuthority(record, issuer string, org *string) oauthAuthority {
	result := oauthAuthority{Kind: "enterprise", RecordID: record, Issuer: issuer}
	if org != nil {
		result.OrganizationID = *org
	}
	return result
}

type oauthIdentity struct {
	ID, UserID, ProviderID, Subject string
	CreatedMS                       int64
}
type oauthAttribution struct {
	Identity  oauthIdentity
	Authority oauthAuthority
}

var socialAuthority = oauthAuthority{Kind: "social"}

func originDigest(prefix, value string) string {
	h := sha256.Sum256([]byte(value))
	return prefix + hex.EncodeToString(h[:16])
}
func sourceOwner(uid string) string { return originDigest("oauth-owner:", uid) }
func sourceID(id string) string     { return originDigest("os-", id) }

func (s *Store) readAccountSource(ctx context.Context, db rowQuerier, id oauthIdentity) (oauthAuthority, bool, error) {
	var raw, owner string
	err := db.QueryRowContext(ctx, s.bind(`SELECT "identifier","value" FROM "verification" WHERE "id"=?`), sourceID(id.ID)).Scan(&owner, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return oauthAuthority{}, false, nil
	}
	if err != nil {
		return oauthAuthority{}, false, err
	}
	var p oauthAttribution
	if owner != sourceOwner(id.UserID) || json.Unmarshal([]byte(raw), &p) != nil || p.Identity != id || (p.Authority != socialAuthority && (p.Authority.Kind != "enterprise" || p.Authority.RecordID == "" || p.Authority.Issuer == "")) {
		return oauthAuthority{}, false, auth.ErrOAuthLinkRequired
	}
	return p.Authority, true, nil
}

func (s *Store) putOriginRecord(ctx context.Context, tx *sql.Tx, id, key, value string) error {
	now := s.date(time.Now())
	q := `INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`
	if s.dialect == "mysql" {
		q += ` ON DUPLICATE KEY UPDATE "identifier"=?,"value"=?,"updatedAt"=?`
	} else {
		q += ` ON CONFLICT("id") DO UPDATE SET "identifier"=?,"value"=?,"updatedAt"=?`
	}
	_, err := tx.ExecContext(ctx, s.bind(q), id, key, value, s.date(time.Unix(1<<31-1, 0)), now, now, key, value, now)
	return err
}

func (s *Store) writeAccountSource(ctx context.Context, tx *sql.Tx, id oauthIdentity, authority oauthAuthority) error {
	payload, err := json.Marshal(oauthAttribution{Identity: id, Authority: authority})
	if err != nil {
		return err
	}
	return s.putOriginRecord(ctx, tx, sourceID(id.ID), sourceOwner(id.UserID), string(payload))
}
func (s *Store) markEnterpriseNamespace(ctx context.Context, tx *sql.Tx, provider string) error {
	return s.putOriginRecord(ctx, tx, originDigest("on-", provider), "enterprise-namespace", provider)
}
func (s *Store) requireAccountSource(ctx context.Context, db rowQuerier, id oauthIdentity, want oauthAuthority) error {
	actual, known, err := s.readAccountSource(ctx, db, id)
	if err != nil {
		return err
	}
	if known {
		if actual == want {
			return nil
		}
		return auth.ErrOAuthLinkRequired
	}
	if want == socialAuthority {
		// Canonical legacy accounts have no source discriminator. A database
		// with a directory catalog may already have lost a historical provider.
		has, e := s.hasKeyOwnerTable(ctx, db, "ssoProvider")
		if e != nil {
			return e
		}
		if !has {
			var used bool
			e = db.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "verification" WHERE "id"=?)`), originDigest("on-", id.ProviderID)).Scan(&used)
			if e != nil {
				return e
			}
			if !used {
				return nil
			}
		}
	}
	return auth.ErrOAuthLinkRequired
}

// OAuthAccountAttribution describes a historical account whose source the
// operator verified independently. A blank enterprise record and issuer select
// the startup-configured social provider.
type OAuthAccountAttribution struct {
	AccountID, UserID, ProviderID, Subject                         string
	EnterpriseRecordID, EnterpriseIssuer, EnterpriseOrganizationID string
}

// ReconcileOAuthAccount records an independently established account source.
// It never replaces an existing source or exposes a browser endpoint.
func (s *Store) ReconcileOAuthAccount(ctx context.Context, in OAuthAccountAttribution) error {
	if in.AccountID == "" || in.UserID == "" || !sso.MutableProviderID(in.ProviderID) || in.Subject == "" || (in.EnterpriseRecordID == "") != (in.EnterpriseIssuer == "") || in.EnterpriseRecordID == "" && in.EnterpriseOrganizationID != "" {
		return auth.ErrOAuthLinkRequired
	}
	tx, e := s.beginMembershipChange(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var id oauthIdentity
	var created time.Time
	q := `SELECT "id","userId","providerId","accountId","createdAt" FROM "account" WHERE ` + s.scimExact(`"id"`) + `=?`
	e = tx.QueryRowContext(ctx, s.readForUpdate(q), in.AccountID).Scan(&id.ID, &id.UserID, &id.ProviderID, &id.Subject, &created)
	if errors.Is(e, sql.ErrNoRows) {
		return auth.ErrNotFound
	}
	if e != nil {
		return e
	}
	if id.ID != in.AccountID || id.UserID != in.UserID || id.ProviderID != in.ProviderID || id.Subject != in.Subject {
		return auth.ErrOAuthLinkRequired
	}
	id.CreatedMS = created.UnixMilli()
	want := socialAuthority
	if in.EnterpriseRecordID != "" {
		query := `SELECT "id","issuer","organizationId" FROM "ssoProvider" WHERE "oidcConfig" IS NOT NULL AND "samlConfig" IS NULL AND ` + s.scimExact(`"providerId"`) + `=?`
		var record, issuer string
		var org *string
		e = tx.QueryRowContext(ctx, s.readForUpdate(query), in.ProviderID).Scan(&record, &issuer, &org)
		if errors.Is(e, sql.ErrNoRows) {
			return sso.ErrMissing
		}
		if e != nil {
			return e
		}
		want = enterpriseAuthority(record, issuer, org)
		if record != in.EnterpriseRecordID || issuer != in.EnterpriseIssuer || want.OrganizationID != in.EnterpriseOrganizationID {
			return auth.ErrOAuthLinkRequired
		}
		if e = s.markEnterpriseNamespace(ctx, tx, in.ProviderID); e != nil {
			return e
		}
	}
	old, known, e := s.readAccountSource(ctx, tx, id)
	if e != nil {
		return e
	}
	if known {
		if old != want {
			return auth.ErrOAuthLinkRequired
		}
		return tx.Commit()
	}
	if e = s.writeAccountSource(ctx, tx, id, want); e != nil {
		return e
	}
	return tx.Commit()
}
