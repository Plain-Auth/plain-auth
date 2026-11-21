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

	auth "github.com/Stonewrit/stonewrit-auth"
	org "github.com/Stonewrit/stonewrit-auth/plugins/organization"
	"github.com/Stonewrit/stonewrit-auth/plugins/sso"
)

var _ sso.BrowserStore = (*Store)(nil)

const browserProviderCols = `p."id",p."providerId",p."issuer",p."domain",p."userId",p."organizationId",p."oidcConfig"`
const browserProviderWhere = `p."oidcConfig" IS NOT NULL AND p."samlConfig" IS NULL`

func scanBrowserProvider(row rowScanner) (sso.BrowserProvider, error) {
	var p sso.BrowserProvider
	var raw string
	if err := row.Scan(&p.ID, &p.ProviderID, &p.Issuer, &p.Domain, &p.UserID, &p.OrganizationID, &raw); err != nil {
		return p, err
	}
	var cfg map[string]any
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if e := decoder.Decode(&cfg); e != nil || cfg == nil {
		return p, errors.New("sqlstore: invalid enterprise configuration")
	}
	if e := json.Unmarshal([]byte(raw), &p.OIDC); e != nil {
		return p, errors.New("sqlstore: invalid enterprise provider")
	}
	// Secret rotation does not change ownership. Include all other stored configuration
	// keys and the immutable record ID so a replacement cannot finish an old flow.
	delete(cfg, "clientSecret")
	payload, err := json.Marshal([]any{p.ID, p.ProviderID, p.UserID, p.OrganizationID, p.Issuer, p.Domain, cfg})
	if err != nil {
		return p, err
	}
	hash := sha256.Sum256(payload)
	p.Reference = base64.RawURLEncoding.EncodeToString(hash[:])
	return p, nil
}

func (s *Store) FindBrowserProvider(ctx context.Context, sel sso.Selector) (sso.BrowserProvider, error) {
	var found sso.BrowserProvider
	query := `SELECT ` + browserProviderCols + ` FROM "ssoProvider" p WHERE ` + browserProviderWhere
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
	best := -1
	ambiguous := false
	for rows.Next() {
		p, e := scanBrowserProvider(rows)
		if e != nil {
			return found, e
		}
		score := 0
		if sel.ProviderID == "" && sel.OrganizationSlug == "" {
			score = sso.DomainMatch(sel.Domain, p.Domain)
			if score < 0 {
				continue
			}
		}
		if score > best {
			best = score
			found = p
			ambiguous = false
		} else if score == best {
			ambiguous = true
		}
	}
	if e = rows.Err(); e != nil {
		return found, e
	}
	if best < 0 || ambiguous {
		return sso.BrowserProvider{}, sso.ErrMissing
	}
	return found, nil
}

func (s *Store) CompleteEnterpriseLogin(ctx context.Context, ref string, provision bool, id, subject string, tokens auth.OAuthTokens, user auth.User, session auth.StoredSession, opts auth.OAuthLoginOptions) (auth.User, bool, error) {
	var orgID *string
	hooks := oauthTransactionHooks{
		guard: func(tx *sql.Tx) error {
			q := `SELECT ` + browserProviderCols + ` FROM "ssoProvider" p WHERE ` + browserProviderWhere + ` AND ` + s.scimExact(`p."providerId"`) + `=?`
			p, err := scanBrowserProvider(tx.QueryRowContext(ctx, s.readForUpdate(q), id))
			if errors.Is(err, sql.ErrNoRows) || err == nil && (ref == "" || p.Reference != ref) {
				return sso.ErrChanged
			}
			if err != nil {
				return err
			}
			var matches int
			q = `SELECT COUNT(*) FROM "account" WHERE ` + s.scimExact(`"providerId"`) + `=? AND ` + s.scimExact(`"accountId"`) + `=?`
			if err = tx.QueryRowContext(ctx, s.bind(q), id, subject).Scan(&matches); err != nil {
				return err
			}
			if matches > 1 {
				return auth.ErrOAuthLinkRequired
			}
			orgID = p.OrganizationID
			if orgID != nil {
				return s.lockOrganization(ctx, tx, *orgID)
			}
			return nil
		},
		afterIdentity: func(tx *sql.Tx, u auth.User) error {
			if !provision || orgID == nil {
				return nil
			}
			var pending bool
			e := tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "invitation" WHERE "organizationId"=? AND "email"=? AND "status"='pending' AND "expiresAt">?)`), *orgID, strings.ToLower(u.Email), s.date(session.CreatedAt)).Scan(&pending)
			if e != nil || pending {
				return e
			}
			e = s.checkNewMember(ctx, tx, *orgID, u.ID)
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
	opts.AllowVerifiedEmailLink = false
	u, created, err := s.completeOAuthWith(ctx, id, subject, tokens, user, session, opts, &hooks)
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
