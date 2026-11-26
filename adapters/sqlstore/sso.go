package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/plugins/sso"
)

var _ sso.Store = (*Store)(nil)

func (s *Store) ssoActor(ctx context.Context, tx *sql.Tx, a sso.Actor) error {
	u, err := s.organizationActor(ctx, tx, a.UserID, a.SessionID, time.Now())
	if errors.Is(err, org.ErrUnauthenticated) || err == nil && u.ID != a.UserID {
		return sso.ErrUnauthenticated
	}
	return err
}
func ssoAdmin(role string) bool {
	for _, r := range strings.Split(role, ",") {
		r = strings.TrimSpace(r)
		if r == "owner" || r == "admin" {
			return true
		}
	}
	return false
}

func (s *Store) ssoOrgRole(ctx context.Context, tx *sql.Tx, orgID, userID string) (string, error) {
	err := s.lockOrganization(ctx, tx, orgID)
	if errors.Is(err, org.ErrNotFound) {
		return "", sso.ErrNotMember
	}
	if err != nil {
		return "", err
	}
	var role string
	q := `SELECT "role" FROM "member" WHERE ` + s.scimExact(`"organizationId"`) + `=? AND ` + s.scimExact(`"userId"`) + `=?`
	err = tx.QueryRowContext(ctx, s.readForUpdate(q), orgID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		err = sso.ErrNotMember
	}
	return role, err
}

func (s *Store) ssoRegister(ctx context.Context, a sso.Actor, p sso.Provider, limit int, insert bool, challenge *sso.DomainChallenge) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.lockActiveAccount(ctx, tx, a.UserID, a.SessionToken, time.Now()); errors.Is(err, auth.ErrNotFound) {
		return sso.ErrUnauthenticated
	} else if err != nil {
		return err
	}
	if limit <= 0 {
		return sso.ErrDisabled
	}
	if p.UserID != a.UserID {
		return sso.ErrForbidden
	}
	var n int
	err = tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "ssoProvider" WHERE `+s.scimExact(`"userId"`)+`=?`), a.UserID).Scan(&n)
	if err != nil {
		return err
	}
	if n >= limit {
		return sso.ErrLimit
	}
	if p.OrganizationID != nil {
		// An organization ID is meaningful only with the membership tables installed.
		exists, err := s.hasKeyOwnerTable(ctx, tx, "member")
		if err != nil {
			return err
		}
		if !exists {
			return sso.ErrNotMember
		}
		role, err := s.ssoOrgRole(ctx, tx, *p.OrganizationID, a.UserID)
		if err != nil {
			return err
		}
		if !ssoAdmin(role) {
			return sso.ErrOrgRole
		}
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "ssoProvider" WHERE "providerId"=?) OR EXISTS(SELECT 1 FROM "account" WHERE "providerId"=?)`), p.ProviderID, p.ProviderID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return sso.ErrDuplicate
	}
	if !insert {
		return nil
	}
	if (p.OIDC == nil) == (p.SAML == nil) {
		return sso.ErrMissing
	}
	var oidcConfig, samlConfig any
	var cfg []byte
	if p.SAML != nil {
		cfg, err = s.marshalSAMLConfig(p.SAML)
		if err != nil {
			return err
		}
		if p.SAML.IDPMetadata.Metadata != "" {
			parsed, e := sso.DecodeSAMLConfig(cfg)
			if e != nil || !parsed.MetadataValidAt(time.Now()) {
				return sso.ErrInvalidSAML
			}
			p.SAML = parsed
		}
		samlConfig = string(cfg)
	} else {
		cfg, err = json.Marshal(p.OIDC)
		if err != nil {
			return err
		}
		oidcConfig = string(cfg)
	}
	columns, params := `"id","issuer","domain","oidcConfig","samlConfig","providerId","userId","organizationId"`, "?,?,?,?,?,?,?,?"
	args := []any{p.ID, p.Issuer, p.Domain, oidcConfig, samlConfig, p.ProviderID, a.UserID, p.OrganizationID}
	extra, values := s.providerFieldWrite(p.AdditionalFields, true)
	for i, column := range extra {
		columns += "," + column
		params += ",?"
		args = append(args, values[i])
	}
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "ssoProvider" (`+columns+`) VALUES (`+params+`)`), args...)
	if duplicateConstraint(err) {
		return sso.ErrDuplicate
	}
	if err != nil {
		return err
	}
	if err = s.markEnterpriseNamespace(ctx, tx, p.ProviderID); err != nil {
		return err
	}
	if challenge != nil {
		challenge.Scope, err = enterpriseReference(p, string(cfg))
		if err != nil {
			return err
		}
		if err = s.issueDomainToken(ctx, tx, p, challenge, true); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) CheckSSORegistration(ctx context.Context, a sso.Actor, p sso.Provider, limit int) error {
	return s.ssoRegister(ctx, a, p, limit, false, nil)
}
func (s *Store) CreateSSOProvider(ctx context.Context, a sso.Actor, p sso.Provider, limit int) error {
	return s.ssoRegister(ctx, a, p, limit, true, nil)
}

func (s *Store) ReadSSOProviders(ctx context.Context, a sso.Actor, id string) ([]sso.Provider, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.ssoActor(ctx, tx, a); err != nil {
		return nil, err
	}
	// Ownership is a property of the shared data. A node without organization
	// HTTP routes must enforce the same membership policy as other nodes.
	orgTables, err := s.hasKeyOwnerTable(ctx, tx, "member")
	if err != nil {
		return nil, err
	}
	q := `SELECT ` + s.providerCols()
	args := []any{}
	if orgTables {
		q += `,m."role"`
	}
	q += ` FROM "ssoProvider" p`
	if orgTables {
		q += ` LEFT JOIN "organization" o ON ` + s.scimExact(`o."id"`) + `=p."organizationId" LEFT JOIN "member" m ON ` + s.scimExact(`m."organizationId"`) + `=o."id" AND ` + s.scimExact(`m."userId"`) + `=?`
		args = append(args, a.UserID)
	}
	q += ` WHERE ` + browserProviderWhere
	if id != "" {
		q += ` AND ` + s.scimExact(`p."providerId"`) + `=?`
		args = append(args, id)
	} else if orgTables {
		q += ` AND ((p."organizationId" IS NULL AND ` + s.scimExact(`p."userId"`) + `=?) OR m."id" IS NOT NULL)`
		args = append(args, a.UserID)
	} else {
		q += ` AND p."organizationId" IS NULL AND ` + s.scimExact(`p."userId"`) + `=?`
		args = append(args, a.UserID)
	}
	q += ` ORDER BY p."id"`
	rows, err := tx.QueryContext(ctx, s.bind(q), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sso.Provider
	for rows.Next() {
		var p sso.Provider
		var oidc, saml sql.NullString
		var role sql.NullString
		dest := s.providerFieldDest([]any{&p.ID, &p.ProviderID, &p.Issuer, &p.Domain, &p.UserID, &p.OrganizationID, &oidc, &saml})
		if orgTables {
			dest = append(dest, &role)
		}
		if err = rows.Scan(dest...); err != nil {
			return nil, err
		}
		if p.AdditionalFields, err = s.providerFields(dest, 8); err != nil {
			return nil, err
		}
		allowed := p.UserID == a.UserID
		if p.OrganizationID != nil {
			allowed = role.Valid && ssoAdmin(role.String)
		}
		if !allowed {
			if id != "" {
				return nil, sso.ErrForbidden
			}
			continue
		}
		if _, err = providerConfiguration(&p, oidc, saml); err != nil {
			if errors.Is(err, sso.ErrInvalidSAML) {
				continue
			}
			return nil, err
		}
		out = append(out, p)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if id != "" && len(out) == 0 {
		return nil, sso.ErrMissing
	}
	return out, nil
}

// The canonical creator foreign key cascades on account deletion. MySQL can
// ignore inline REFERENCES, so enforce that same effect on every engine.
func (s *Store) cleanupSSOProviders(ctx context.Context, tx *sql.Tx, userID string) error {
	exists, err := s.hasKeyOwnerTable(ctx, tx, "ssoProvider")
	if err != nil || !exists {
		return err
	}
	rows, err := tx.QueryContext(ctx, s.bind(`SELECT "id" FROM "ssoProvider" WHERE `+s.scimExact(`"userId"`)+`=?`), userID)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, id := range ids {
		if err = s.removeDomainMetadata(ctx, tx, id); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "ssoProvider" WHERE `+s.scimExact(`"userId"`)+`=?`), userID)
	return err
}
