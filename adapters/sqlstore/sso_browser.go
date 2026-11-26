package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/plugins/sso"
)

var _ sso.BrowserStore = (*Store)(nil)

const browserProviderCols = `p."id",p."providerId",p."issuer",p."domain",p."userId",p."organizationId",p."oidcConfig",p."samlConfig"`
const browserProviderWhere = `((p."oidcConfig" IS NOT NULL AND p."samlConfig" IS NULL) OR (p."oidcConfig" IS NULL AND p."samlConfig" IS NOT NULL))`

func scanBrowserProvider(row rowScanner) (sso.BrowserProvider, error) {
	var p sso.BrowserProvider
	var oidc, saml sql.NullString
	if err := row.Scan(&p.ID, &p.ProviderID, &p.Issuer, &p.Domain, &p.UserID, &p.OrganizationID, &oidc, &saml); err != nil {
		return p, err
	}
	raw, err := providerConfiguration(&p.Provider, oidc, saml)
	if err != nil {
		return p, err
	}
	p.Reference, err = enterpriseReference(p.Provider, raw)
	return p, err
}

func providerConfiguration(p *sso.Provider, oidc, rawSAML sql.NullString) (string, error) {
	if oidc.Valid == rawSAML.Valid {
		return "", sso.ErrMissing
	}
	if rawSAML.Valid {
		cfg, err := sso.DecodeSAMLConfig([]byte(rawSAML.String))
		p.SAML = cfg
		return rawSAML.String, err
	}
	return oidc.String, json.Unmarshal([]byte(oidc.String), &p.OIDC)
}
func enterpriseReference(p sso.Provider, raw string) (string, error) {
	var cfg map[string]any
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&cfg); err != nil || cfg == nil {
		return "", errors.New("sqlstore: invalid enterprise configuration")
	}
	// Secret rotation keeps the same authority. The immutable registration,
	// tenant and every other configuration key bind the identity and DNS proof.
	payloadValues := []any{p.ID, p.ProviderID, p.UserID, p.OrganizationID, p.Issuer, p.Domain, cfg}
	if p.SAML != nil {
		payloadValues = append(payloadValues, "saml")
	} else {
		delete(cfg, "clientSecret")
	}
	payload, err := json.Marshal(payloadValues)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(payload)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

func (s *Store) FindBrowserProvider(ctx context.Context, sel sso.Selector) (sso.BrowserProvider, error) {
	return s.findBrowserProvider(ctx, sel, false)
}
func (s *Store) FindVerifiedBrowserProvider(ctx context.Context, sel sso.Selector) (sso.BrowserProvider, error) {
	return s.findBrowserProvider(ctx, sel, true)
}
func (s *Store) findBrowserProvider(ctx context.Context, sel sso.Selector, requireProof bool) (sso.BrowserProvider, error) {
	var found sso.BrowserProvider
	query := `SELECT ` + browserProviderCols + ` FROM "ssoProvider" p WHERE ` + browserProviderWhere
	if sel.Protocol == "oidc" {
		query += ` AND p."oidcConfig" IS NOT NULL`
	} else if sel.Protocol == "saml" {
		query += ` AND p."samlConfig" IS NOT NULL`
	}
	args := []any{}
	switch {
	case sel.ProviderID != "":
		query += ` AND ` + s.scimExact(`p."providerId"`) + `=?`
		args = append(args, sel.ProviderID)
	case sel.OrganizationSlug != "":
		exists, err := s.hasKeyOwnerTable(ctx, s.db, "organization")
		if err != nil {
			return found, err
		}
		if !exists {
			return found, sso.ErrMissing
		}
		query += ` AND p."organizationId" IN (SELECT "id" FROM "organization" WHERE ` + s.scimExact(`"slug"`) + `=?)`
		args = append(args, sel.OrganizationSlug)
	case sel.Domain == "":
		return found, sso.ErrMissing
	}
	rows, e := s.db.QueryContext(ctx, s.bind(query), args...)
	if e != nil {
		return found, e
	}
	defer rows.Close()
	// Close the scan before checking scope metadata. A SQLite pool may expose
	// only one connection, and many directories can share a suffix.
	type candidate struct {
		p      sso.BrowserProvider
		suffix int
	}
	var matches []candidate
	for rows.Next() {
		p, e := scanBrowserProvider(rows)
		if errors.Is(e, sso.ErrInvalidSAML) {
			continue
		}
		if e != nil {
			return found, e
		}
		suffix := 0
		if sel.ProviderID == "" && sel.OrganizationSlug == "" {
			suffix = sso.DomainMatch(sel.Domain, p.Domain)
			if suffix < 0 {
				continue
			}
		}
		matches = append(matches, candidate{p, suffix})
	}
	if e = rows.Err(); e != nil {
		return found, e
	}
	if e = rows.Close(); e != nil {
		return found, e
	}
	if len(matches) == 0 {
		return found, sso.ErrMissing
	}
	if sel.ProviderID != "" {
		if len(matches) != 1 {
			return found, sso.ErrMissing
		}
		return matches[0].p, nil
	}
	bestTier, bestSuffix := -1, -1
	ambiguous := false
	for _, m := range matches {
		required := requireProof
		if !required {
			required, e = s.SSODomainRequired(ctx, m.p.Provider)
			if e != nil {
				return found, e
			}
		}
		tier := 0
		if required {
			valid, e := s.SSODomainVerified(ctx, m.p.Provider, m.p.Reference)
			if e != nil {
				return found, e
			}
			if !valid {
				continue
			}
			tier = 1
		}
		if tier > bestTier || tier == bestTier && m.suffix > bestSuffix {
			found = m.p
			bestTier, bestSuffix = tier, m.suffix
			ambiguous = false
		} else if tier == bestTier && m.suffix == bestSuffix {
			ambiguous = true
		}
	}
	if bestTier < 0 {
		return found, sso.ErrDomainUnverified
	}
	if ambiguous {
		return sso.BrowserProvider{}, sso.ErrMissing
	}
	return found, nil
}

var _ sso.UserResolutionStore = (*Store)(nil)

// ResolvesSSOUsers reports that enterprise sign-in honours a resolver's
// selected user.
func (*Store) ResolvesSSOUsers() {}

func (s *Store) CompleteEnterpriseLogin(ctx context.Context, ref string, provision bool, id, subject string, tokens auth.OAuthTokens, user auth.User, session auth.StoredSession, opts auth.OAuthLoginOptions) (auth.User, bool, error) {
	return s.completeEnterpriseLogin(ctx, ref, provision, id, subject, tokens, user, session, opts, false, nil)
}
func (s *Store) CompleteVerifiedEnterpriseLogin(ctx context.Context, ref string, provision bool, id, subject string, tokens auth.OAuthTokens, user auth.User, session auth.StoredSession, opts auth.OAuthLoginOptions) (auth.User, bool, error) {
	return s.completeEnterpriseLogin(ctx, ref, provision, id, subject, tokens, user, session, opts, true, nil)
}
func (s *Store) completeEnterpriseLogin(ctx context.Context, ref string, provision bool, id, subject string, tokens auth.OAuthTokens, user auth.User, session auth.StoredSession, opts auth.OAuthLoginOptions, requireProof bool, assertion *sso.AssertionReceipt) (auth.User, bool, error) {
	var orgID *string
	var admission *memberAdmission
	checkedAt := session.CreatedAt
	// The root prepared the profile's user fields outside this transaction.
	fields := opts.ProfileFields
	opts.ProfileFields = nil
	var hooks oauthTransactionHooks
	hooks = oauthTransactionHooks{
		guard: func(tx *sql.Tx) error {
			if admission.snapshot != "" {
				checkedAt = admission.checkedAt(session.CreatedAt)
				if !session.ExpiresAt.After(checkedAt) {
					return sso.ErrUnauthenticated
				}
				if !opts.IDTokenValidUntil.IsZero() && !opts.IDTokenValidUntil.After(checkedAt) {
					return auth.ErrIDTokenUsed
				}
			}
			q := `SELECT ` + browserProviderCols + ` FROM "ssoProvider" p WHERE ` + browserProviderWhere + ` AND ` + s.scimExact(`p."providerId"`) + `=?`
			p, err := scanBrowserProvider(tx.QueryRowContext(ctx, s.readForUpdate(q), id))
			if errors.Is(err, sql.ErrNoRows) || err == nil && (ref == "" || p.Reference != ref) {
				return sso.ErrChanged
			}
			if err != nil {
				return err
			}
			if (assertion != nil) != (p.SAML != nil) {
				return sso.ErrChanged
			}
			if assertion != nil {
				if err = s.consumeSAMLAssertion(ctx, tx, p, *assertion, checkedAt); err != nil {
					return err
				}
			}
			required := requireProof
			if !required {
				required, err = s.requiresSSODomain(ctx, tx, p.Provider)
				if err != nil {
					return err
				}
			}
			if required {
				valid, e := s.domainVerified(ctx, tx, p.Provider, p.Reference)
				if e != nil {
					return e
				}
				if !valid {
					return sso.ErrDomainUnverified
				}
				_, domain, ok := strings.Cut(strings.ToLower(user.Email), "@")
				hooks.trustEmailDomain = ok && sso.DomainMatch(domain, p.Domain) >= 0
			}
			var matches int
			q = `SELECT COUNT(*) FROM "account" WHERE ` + s.scimExact(`"providerId"`) + `=? AND ` + s.scimExact(`"accountId"`) + `=?`
			if err = tx.QueryRowContext(ctx, s.bind(q), id, subject).Scan(&matches); err != nil {
				return err
			}
			if matches > 1 {
				return auth.ErrOAuthLinkRequired
			}
			hooks.authority = providerAuthority(p.Provider)
			orgID = p.OrganizationID
			if orgID != nil {
				return s.lockOrganization(ctx, tx, *orgID)
			}
			return nil
		},
		withSession: func(tx *sql.Tx, u auth.User, session auth.StoredSession) error {
			if assertion == nil || assertion.Logout == nil {
				return nil
			}
			return s.recordSAMLSession(ctx, tx, id, ref, u.ID, subject, *assertion.Logout, session)
		},
		afterIdentity: func(tx *sql.Tx, u auth.User) error {
			if !provision || orgID == nil {
				return nil
			}
			var pending bool
			e := tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "invitation" WHERE "organizationId"=? AND "email"=? AND "status"='pending' AND "expiresAt">?)`), *orgID, strings.ToLower(u.Email), s.date(checkedAt)).Scan(&pending)
			if e != nil || pending {
				return e
			}
			e = s.checkNewMember(ctx, tx, *orgID, u.ID, admission, nil)
			if errors.Is(e, org.ErrAlreadyMember) {
				return nil
			}
			if e != nil {
				return e
			}
			return s.addMember(ctx, tx, org.Member{ID: rand.Text(), OrganizationID: *orgID, UserID: u.ID, Role: "member", CreatedAt: session.CreatedAt})
		},
	}
	// Matching an unverified directory domain never grants linking to an existing email.
	opts.AllowVerifiedEmailLink, opts.TrustedProvider, opts.AllowDifferentEmails = false, false, false
	var u auth.User
	var created bool
	err := s.withMemberAdmission(ctx, func(decision *memberAdmission) error {
		admission = decision
		var err error
		u, created, err = s.completeOAuthWith(ctx, id, subject, tokens, user, session, opts, &hooks, false, fields)
		return err
	})
	// A concurrent deletion can remove the original link while the account
	// lookup is blocked. Report that stale provider even when identity matching
	// rejected the now-unlinked email before the transaction guard could run.
	if errors.Is(err, auth.ErrOAuthLinkRequired) || errors.Is(err, auth.ErrOAuthSignupDisabled) {
		current, lookup := s.FindBrowserProvider(ctx, sso.Selector{ProviderID: id})
		if errors.Is(lookup, sso.ErrMissing) || lookup == nil && current.Reference != ref {
			return auth.User{}, false, sso.ErrChanged
		}
		if lookup != nil {
			return auth.User{}, false, lookup
		}
	}
	return u, created, err
}
