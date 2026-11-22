package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"strings"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/plugins/sso"
)

var _ sso.DomainStore = (*Store)(nil)

func (s *Store) CheckSSODomainSchema(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT p."domainVerified" FROM "ssoProvider" p WHERE 1=0`))
	if err != nil {
		return errors.New("sqlstore: SSO domain verification requires the sso-domain-verification schema profile")
	}
	return rows.Close()
}
func (s *Store) domainMetadata(ctx context.Context, db rowQuerier, p sso.Provider) (bool, string, string, error) {
	var raw string
	var flag sql.NullBool
	var saml bool
	var state sql.NullString
	q := `SELECT p."domainVerified", v."value", COALESCE(p."oidcConfig",p."samlConfig"),p."samlConfig" IS NOT NULL FROM "ssoProvider" p LEFT JOIN "verification" v ON v."id"=? AND v."identifier"='enterprise-domain-proof' WHERE ` + browserProviderWhere + ` AND ` + s.scimExact(`p."id"`) + `=? AND ` + s.scimExact(`p."providerId"`) + `=? AND ` + s.scimExact(`p."domain"`) + `=? AND ` + s.scimExact(`p."userId"`) + `=? AND ` + s.scimExact(`p."issuer"`) + `=?`
	args := []any{originDigest("dp-", p.ID), p.ID, p.ProviderID, p.Domain, p.UserID, p.Issuer}
	if p.OrganizationID == nil {
		q += ` AND p."organizationId" IS NULL`
	} else {
		q += ` AND ` + s.scimExact(`p."organizationId"`) + `=?`
		args = append(args, *p.OrganizationID)
	}
	err := db.QueryRowContext(ctx, s.bind(q), args...).Scan(&flag, &state, &raw, &saml)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "", "", nil
	}
	if err != nil {
		return false, "", "", err
	}
	if saml {
		p.SAML = &sso.SAMLConfig{}
	} else {
		p.SAML = nil
	}
	scope, err := enterpriseReference(p, raw)
	if err != nil {
		return false, "", "", err
	}
	return !strings.Contains(p.ProviderID, ".") && flag.Valid && flag.Bool && state.String == "verified:"+scope, state.String, scope, nil
}
func (s *Store) domainVerified(ctx context.Context, db rowQuerier, p sso.Provider, reference string) (bool, error) {
	verified, _, scope, err := s.domainMetadata(ctx, db, p)
	return verified && (reference == "" || reference == scope), err
}
func (s *Store) SSODomainVerified(ctx context.Context, p sso.Provider, reference string) (bool, error) {
	return s.domainVerified(ctx, s.db, p, reference)
}

func (s *Store) CreateSSODomainProvider(ctx context.Context, actor sso.Actor, p sso.Provider, limit int, identifier string) (string, error) {
	if _, err := sso.DomainTargets(p.ProviderID, identifier, p.Domain); err != nil {
		return "", err
	}
	ch := sso.DomainChallenge{Identifier: identifier}
	err := s.ssoRegister(ctx, actor, p, limit, true, &ch)
	if err != nil {
		return "", err
	}
	return ch.Token, nil
}
func (s *Store) issueDomainToken(ctx context.Context, tx *sql.Tx, p sso.Provider, ch *sso.DomainChallenge) error {
	now := time.Now().UTC()
	ch.ProviderID = p.ProviderID
	ch.Domain = p.Domain
	ch.Token = rand.Text()[:24]
	id := originDigest("dc-", p.ID)
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=?`), id); err != nil {
		return err
	}
	q := `INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`
	if _, err := tx.ExecContext(ctx, s.bind(q), id, ch.Identifier, ch.Token, s.date(now.Add(7*24*time.Hour)), s.date(now), s.date(now)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.bind(`UPDATE "ssoProvider" SET "domainVerified"=? WHERE "id"=?`), false, p.ID); err != nil {
		return err
	}
	return s.putOriginRecord(ctx, tx, originDigest("dp-", p.ID), "enterprise-domain-proof", "pending:"+ch.Scope)
}

func (s *Store) domainMutation(ctx context.Context, actor sso.Actor, id string, fn func(*sql.Tx, sso.Provider) error) error {
	return s.withManagedSSOProvider(ctx, actor, id, func(tx *sql.Tx, p sso.BrowserProvider) error { return fn(tx, p.Provider) })
}
func (s *Store) withManagedSSOProvider(ctx context.Context, actor sso.Actor, id string, fn func(*sql.Tx, sso.BrowserProvider) error) error {
	if !sso.MutableProviderID(id) {
		return sso.ErrMissing
	}
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.lockActiveAccount(ctx, tx, actor.UserID, actor.SessionToken, time.Now()); errors.Is(err, auth.ErrNotFound) {
		return sso.ErrUnauthenticated
	} else if err != nil {
		return err
	}
	q := `SELECT ` + browserProviderCols + ` FROM "ssoProvider" p WHERE ` + browserProviderWhere + ` AND ` + s.scimExact(`p."providerId"`) + `=?`
	p, err := scanBrowserProvider(tx.QueryRowContext(ctx, s.readForUpdate(q), id))
	if errors.Is(err, sql.ErrNoRows) {
		return sso.ErrMissing
	}
	if err != nil {
		return err
	}
	if err = s.authorizeSSOManager(ctx, tx, actor, p.Provider); err != nil {
		return err
	}
	if err = fn(tx, p); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) SSODomainChallenge(ctx context.Context, actor sso.Actor, id, identifier string, issue bool) (sso.DomainChallenge, error) {
	ch := sso.DomainChallenge{ProviderID: id, Identifier: identifier}
	err := s.domainMutation(ctx, actor, id, func(tx *sql.Tx, p sso.Provider) error {
		if _, e := sso.DomainTargets(id, identifier, p.Domain); e != nil {
			return e
		}
		verified, state, scope, e := s.domainMetadata(ctx, tx, p)
		if e != nil {
			return e
		}
		if verified {
			return sso.ErrDomainVerified
		}
		ch.Domain = p.Domain
		ch.Scope = scope
		if state == "pending:"+ch.Scope {
			e = s.readDomainToken(ctx, tx, p.ID, identifier, &ch.Token)
			if e == nil {
				return nil
			}
			if !errors.Is(e, sso.ErrNoChallenge) {
				return e
			}
		}
		if !issue {
			return sso.ErrNoChallenge
		}
		return s.issueDomainToken(ctx, tx, p, &ch)
	})
	if err != nil {
		return sso.DomainChallenge{}, err
	}
	return ch, nil
}
func (s *Store) readDomainToken(ctx context.Context, tx *sql.Tx, recordID, label string, token *string) error {
	q := `SELECT "value" FROM "verification" WHERE "id"=? AND ` + s.scimExact(`"identifier"`) + `=? AND "expiresAt">?`
	err := tx.QueryRowContext(ctx, s.readForUpdate(q), originDigest("dc-", recordID), label, s.date(time.Now())).Scan(token)
	if errors.Is(err, sql.ErrNoRows) {
		return sso.ErrNoChallenge
	}
	return err
}
func (s *Store) ConfirmSSODomain(ctx context.Context, actor sso.Actor, ch sso.DomainChallenge) error {
	err := s.domainMutation(ctx, actor, ch.ProviderID, func(tx *sql.Tx, p sso.Provider) error {
		if _, e := sso.DomainTargets(p.ProviderID, ch.Identifier, p.Domain); e != nil {
			return e
		}
		verified, state, scope, err := s.domainMetadata(ctx, tx, p)
		if err != nil {
			return err
		}
		if scope != ch.Scope || p.Domain != ch.Domain {
			return sso.ErrDomainChanged
		}
		if verified {
			return sso.ErrDomainVerified
		}
		if state != "pending:"+ch.Scope {
			return sso.ErrDomainChanged
		}
		var token string
		if err = s.readDomainToken(ctx, tx, p.ID, ch.Identifier, &token); err != nil {
			return err
		}
		if token != ch.Token {
			return sso.ErrDomainChanged
		}
		if _, err = tx.ExecContext(ctx, s.bind(`UPDATE "ssoProvider" SET "domainVerified"=? WHERE "id"=?`), true, p.ID); err != nil {
			return err
		}
		return s.putOriginRecord(ctx, tx, originDigest("dp-", p.ID), "enterprise-domain-proof", "verified:"+ch.Scope)
	})
	if errors.Is(err, sso.ErrMissing) {
		return sso.ErrDomainChanged
	}
	return err
}
func (s *Store) removeDomainMetadata(ctx context.Context, tx *sql.Tx, id string) error {
	_, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id" IN (?,?)`), originDigest("dp-", id), originDigest("dc-", id))
	return err
}

func (s *Store) requiresSSODomain(ctx context.Context, db rowQuerier, p sso.Provider) (bool, error) {
	var required bool
	err := db.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "verification" WHERE "id"=? AND "identifier"='enterprise-domain-proof')`), originDigest("dp-", p.ID)).Scan(&required)
	return required, err
}
func (s *Store) SSODomainRequired(ctx context.Context, p sso.Provider) (bool, error) {
	return s.requiresSSODomain(ctx, s.db, p)
}
