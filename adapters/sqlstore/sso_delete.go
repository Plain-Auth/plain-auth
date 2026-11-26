package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
)

var _ sso.DeletionStore = (*Store)(nil)

var (
	errGuardPlanned = errors.New("sqlstore: provider mutation planned")
	errGuardChanged = errors.New("sqlstore: provider mutation changed while its guard ran")
)

// providerGuard carries a MutationGuard decision from a dry run to the run
// that commits.
type providerGuard struct {
	approved bool
	planned  *sso.ProviderMutation
}

// check is called at the guard point inside the transaction: a dry run
// records m and stops, an approved run continues only for the same snapshot.
func (g *providerGuard) check(m sso.ProviderMutation) error {
	if g == nil {
		return nil
	}
	if !g.approved {
		g.planned = &m
		return errGuardPlanned
	}
	if !sameMutation(*g.planned, m) {
		return errGuardChanged
	}
	return nil
}

func sameMutation(a, b sso.ProviderMutation) bool {
	org := func(p *string) string {
		if p == nil {
			return "\x00"
		}
		return *p
	}
	return a.Action == b.Action && a.ID == b.ID && a.ProviderID == b.ProviderID && a.Reference == b.Reference && org(a.OrganizationID) == org(b.OrganizationID) &&
		a.LinkedAccounts == b.LinkedAccounts && a.AuthenticationBoundaryChanged == b.AuthenticationBoundaryChanged
}

// guarded runs a provider mutation as a dry run that stops at its guard
// point and rolls back, asks guard outside any transaction, then runs it
// again and commits only for the same snapshot, planning again up to three
// times before ErrChanged.
func guarded(ctx context.Context, guard sso.MutationGuard, run func(*providerGuard) error) error {
	if guard == nil {
		return run(nil)
	}
	for range 3 {
		g := &providerGuard{}
		err := run(g)
		if !errors.Is(err, errGuardPlanned) {
			return err
		}
		if guard(ctx, *g.planned) != nil {
			return sso.ErrMutationRejected
		}
		g.approved = true
		if err = run(g); !errors.Is(err, errGuardChanged) {
			return err
		}
	}
	return sso.ErrChanged
}

// DeleteSSOProvider removes a specific persisted OIDC provider and all links
// under its case-sensitive ID. Retrying is bound to its original record ID.
func (s *Store) DeleteSSOProvider(ctx context.Context, actor sso.Actor, providerID, recordID string, guard sso.MutationGuard) error {
	if !sso.MutableProviderID(providerID) || recordID == "" {
		return sso.ErrMissing
	}
	var err error
	for range 3 {
		err = guarded(ctx, guard, func(g *providerGuard) error { return s.deleteSSOProvider(ctx, actor, providerID, recordID, g) })
		if !retryIdentity(err) {
			break
		}
	}
	return err
}

func (s *Store) deleteSSOProvider(ctx context.Context, actor sso.Actor, id, recordID string, guard *providerGuard) error {
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
	// Callbacks lock existing account links before the provider and tenant.
	// Taking the same locks here also fences a last login on another node.
	accountWhere := s.scimExact(`"providerId"`) + `=?`
	if s.dialect != "sqlite" {
		rows, err := tx.QueryContext(ctx, s.readForUpdate(`SELECT "id" FROM "account" WHERE `+accountWhere+` ORDER BY "id"`), id)
		if err != nil {
			return err
		}
		for rows.Next() {
			// Drain the result so every matching row is locked before proceeding.
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	q := `SELECT ` + browserProviderCols + ` FROM "ssoProvider" p WHERE ` + browserProviderWhere + ` AND ` + s.scimExact(`p."providerId"`) + `=? AND ` + s.scimExact(`p."id"`) + `=?`
	p, err := scanBrowserProvider(tx.QueryRowContext(ctx, s.readForUpdate(q), id, recordID))
	if errors.Is(err, sql.ErrNoRows) {
		return sso.ErrMissing
	}
	if err != nil {
		return err
	}
	if err = s.authorizeSSOManager(ctx, tx, actor, p.Provider); err != nil {
		return err
	}
	// The provider ID is shared with static OAuth providers. Matching that
	// public name never proves ownership of a canonical account row.
	if err = s.markEnterpriseNamespace(ctx, tx, id); err != nil {
		return err
	}
	owned, err := s.ownedEnterpriseLinks(ctx, tx, p)
	if err != nil {
		return err
	}
	mutation := sso.ProviderMutation{Action: "delete", AuthenticationBoundaryChanged: true, ID: recordID, ProviderID: id, OrganizationID: p.OrganizationID, Reference: p.Reference, LinkedAccounts: len(owned)}
	if err = guard.check(mutation); err != nil {
		return err
	}
	for _, link := range owned {
		result, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "account" WHERE `+s.scimExact(`"id"`)+`=? AND `+accountWhere+` AND `+s.scimExact(`"userId"`)+`=? AND `+s.scimExact(`"accountId"`)+`=?`), link.ID, id, link.UserID, link.Subject)
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err != nil {
			return err
		} else if n != 1 {
			return sso.ErrUnclassifiedAccounts
		}
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=?`), sourceID(link.ID), sourceOwner(link.UserID)); err != nil {
			return err
		}
	}
	if err = s.removeDomainMetadata(ctx, tx, recordID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "ssoProvider" WHERE `+s.scimExact(`"id"`)+`=? AND `+s.scimExact(`"providerId"`)+`=?`), recordID, id)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil {
		return err
	} else if n != 1 {
		return sso.ErrMissing
	}
	return tx.Commit()
}

func (s *Store) ownedEnterpriseLinks(ctx context.Context, tx *sql.Tx, p sso.BrowserProvider) ([]oauthIdentity, error) {
	q := `SELECT "id","userId","providerId","accountId","createdAt" FROM "account" WHERE ` + s.scimExact(`"providerId"`) + `=? ORDER BY "id"`
	// Existing links were locked before the provider row. A link created by an
	// earlier holder of the provider lock must now be included as well.
	rows, err := tx.QueryContext(ctx, s.readForUpdate(q), p.ProviderID)
	if err != nil {
		return nil, err
	}
	var accounts []oauthIdentity
	for rows.Next() {
		var link oauthIdentity
		var created time.Time
		if err = rows.Scan(&link.ID, &link.UserID, &link.ProviderID, &link.Subject, &created); err != nil {
			rows.Close()
			return nil, err
		}
		link.CreatedMS = created.UnixMilli()
		accounts = append(accounts, link)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	owned := accounts[:0]
	for _, link := range accounts {
		origin, known, e := s.readAccountSource(ctx, tx, link)
		if errors.Is(e, auth.ErrOAuthLinkRequired) || e == nil && !known {
			return nil, sso.ErrUnclassifiedAccounts
		}
		if e != nil {
			return nil, e
		}
		if origin.Kind == "enterprise" && origin.RecordID == p.ID {
			if origin != providerAuthority(p.Provider) {
				return nil, sso.ErrUnclassifiedAccounts
			}
			owned = append(owned, link)
		}
	}
	return owned, nil
}

func (s *Store) authorizeSSOManager(ctx context.Context, tx *sql.Tx, actor sso.Actor, p sso.Provider) error {
	if p.OrganizationID == nil {
		if p.UserID != actor.UserID {
			return sso.ErrForbidden
		}
	} else {
		exists, e := s.hasKeyOwnerTable(ctx, tx, "member")
		if e != nil {
			return e
		}
		if !exists {
			return sso.ErrForbidden
		}
		role, e := s.ssoOrgRole(ctx, tx, *p.OrganizationID, actor.UserID)
		if errors.Is(e, sso.ErrNotMember) || e == nil && !ssoAdmin(role) {
			return sso.ErrForbidden
		}
		if e != nil {
			return e
		}
	}
	return nil
}
