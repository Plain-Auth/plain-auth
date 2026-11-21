package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/plugins/sso"
)

var _ sso.DeletionStore = (*Store)(nil)

// DeleteSSOProvider removes a specific persisted OIDC provider and all links
// under its case-sensitive ID. Retrying is bound to its original record ID.
func (s *Store) DeleteSSOProvider(ctx context.Context, actor sso.Actor, providerID, recordID string, guard sso.MutationGuard) error {
	if !sso.MutableProviderID(providerID) || recordID == "" {
		return sso.ErrMissing
	}
	var err error
	for range 3 {
		err = s.deleteSSOProvider(ctx, actor, providerID, recordID, guard)
		if !retryIdentity(err) {
			break
		}
	}
	return err
}

func (s *Store) deleteSSOProvider(ctx context.Context, actor sso.Actor, id, recordID string, guard sso.MutationGuard) error {
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
	if guard != nil {
		mutation := sso.ProviderMutation{Action: "delete", ID: recordID, ProviderID: id, OrganizationID: p.OrganizationID, Reference: p.Reference}
		if err = tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "account" WHERE `+accountWhere), id).Scan(&mutation.LinkedAccounts); err != nil {
			return err
		}
		if err = guard(ctx, mutation); err != nil {
			return sso.ErrMutationRejected
		}
	}
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "account" WHERE `+accountWhere), id); err != nil {
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
