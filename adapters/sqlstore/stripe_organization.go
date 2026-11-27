package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	org "github.com/Plain-Org/plain-auth/plugins/organization"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
)

func billingTable(ctx context.Context) string {
	if _, ok := billing.OrganizationFromContext(ctx); ok {
		return `"organization"`
	}
	return `"user"`
}

func stripeOwnerKey(ctx context.Context, kind, reference string) string {
	if _, ok := billing.OrganizationFromContext(ctx); ok {
		return "stripe-org-" + kind + ":" + reference
	}
	return "stripe-" + kind + ":" + reference
}

func (s *Store) organizationBillingColumn(ctx context.Context, q rowQuerier) (bool, error) {
	var query string
	switch s.dialect {
	case "sqlite":
		query = `SELECT count(*) FROM pragma_table_info('organization') WHERE name='stripeCustomerId'`
	case "postgres":
		query = `SELECT count(*) FROM pg_catalog.pg_attribute WHERE attrelid=pg_catalog.to_regclass('organization') AND attname='stripeCustomerId' AND attnum>0 AND NOT attisdropped`
	case "mysql":
		query = `SELECT count(*) FROM information_schema.columns WHERE table_schema=database() AND table_name='organization' AND column_name='stripeCustomerId'`
	}
	var n int
	err := q.QueryRowContext(ctx, query).Scan(&n)
	return n > 0, err
}

func (s *Store) CheckStripeOrganizationSchema(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT o."stripeCustomerId",m."role",m."userId",ss."activeOrganizationId" FROM "organization" o JOIN "member" m ON m."organizationId"=o."id" JOIN "session" ss ON ss."userId"=m."userId" WHERE 1=0`))
	if err != nil {
		return err
	}
	return rows.Close()
}

// The canonical subscription reference can name either entity. Refuse an
// ambiguous local reference or customer mapping even on user-only instances.
func (s *Store) distinctStripeReference(ctx context.Context, q rowQuerier, ref, customer string) error {
	other := `"user"`
	if _, ok := billing.OrganizationFromContext(ctx); !ok {
		exists, err := s.organizationBillingColumn(ctx, q)
		if err != nil || !exists {
			return err
		}
		other = `"organization"`
	}
	var collision bool
	if err := q.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM `+other+` WHERE "id"=?)`), ref).Scan(&collision); err != nil {
		return err
	}
	if collision {
		return billing.ErrCheckoutReconcile
	}
	// A customer the other kind of account holds is in use.
	if customer != "" {
		if err := q.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM `+other+` WHERE "stripeCustomerId"=?)`), customer).Scan(&collision); err != nil {
			return err
		}
		if collision {
			return billing.ErrCustomerInUse
		}
	}
	return nil
}

// authorizeStripeActor reads the actor's membership role and asks the
// host's policy before any transaction opens, so host code never runs
// with rows locked; the transaction then requires the same role.
func (s *Store) authorizeStripeActor(ctx context.Context, scope billing.OrganizationScope, reference string) (string, error) {
	if reference == "" || reference != scope.ID || scope.Authorize == nil {
		return "", billing.ErrOrganizationBillingAccess
	}
	role, err := stripeMemberRole(ctx, s.db, s.bind(stripeMemberQuery), reference, scope.Actor)
	if err != nil {
		return "", err
	}
	if !scope.Authorize(billing.ReferenceAuthorization{UserID: scope.Actor, OrganizationID: reference, SessionID: scope.Session, Role: role, Action: scope.Action}) {
		return "", billing.ErrOrganizationBillingAccess
	}
	return role, nil
}

const stripeMemberQuery = `SELECT "role" FROM "member" WHERE "organizationId"=? AND "userId"=? LIMIT 2`

// stripeMemberRole reads the actor's single membership role; none, or more
// than one membership, refuses billing access.
func stripeMemberRole(ctx context.Context, db interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, query, reference, actor string) (string, error) {
	rows, err := db.QueryContext(ctx, query, reference, actor)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var role string
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", err
		}
		return "", billing.ErrOrganizationBillingAccess
	}
	if err := rows.Scan(&role); err != nil {
		return "", err
	}
	if rows.Next() {
		return "", billing.ErrOrganizationBillingAccess
	}
	return role, rows.Err()
}

// lockStripeOrganization locks the actor's session and the organization and
// requires the role the policy authorized before the transaction.
func (s *Store) lockStripeOrganization(ctx context.Context, tx *sql.Tx, scope billing.OrganizationScope, reference, token string, now time.Time, authorized string) error {
	if reference == "" || reference != scope.ID {
		return billing.ErrOrganizationBillingAccess
	}
	if scope.Actor != "" {
		if token == "" || scope.Session == "" || scope.Authorize == nil {
			return billing.ErrOrganizationBillingAccess
		}
		if err := s.lockActiveAccount(ctx, tx, scope.Actor, token, now); err != nil {
			return err
		}
		var active sql.NullString
		param, _ := s.deviceTokenParameters([]string{token})
		err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "activeOrganizationId" FROM "session" WHERE "id"=? AND "userId"=? AND "token"=`+param), scope.Session, scope.Actor, token).Scan(&active)
		if errors.Is(err, sql.ErrNoRows) || err == nil && scope.Active && active.String != reference {
			return billing.ErrOrganizationBillingAccess
		}
		if err != nil {
			return err
		}
	} else if token != "" {
		return billing.ErrOrganizationBillingAccess
	}
	if err := s.lockOrganization(ctx, tx, reference); err != nil {
		if errors.Is(err, org.ErrNotFound) {
			return billing.ErrOrganizationBillingAccess
		}
		return err
	}
	if scope.Actor == "" {
		return nil
	}
	role, err := stripeMemberRole(ctx, tx, s.readForUpdate(stripeMemberQuery), reference, scope.Actor)
	if err != nil {
		return err
	}
	if role != authorized {
		return billing.ErrOrganizationBillingAccess
	}
	return nil
}

func (s *Store) StripeOrganizationAccount(ctx context.Context, token string, now time.Time) (billing.OrganizationAccount, error) {
	var out billing.OrganizationAccount
	scope, ok := billing.OrganizationFromContext(ctx)
	if !ok || scope.Actor == "" || token == "" {
		return out, billing.ErrOrganizationBillingAccess
	}
	err := s.billingTransaction(ctx, scope.ID, token, now, func(tx *sql.Tx) error {
		var cus sql.NullString
		if err := tx.QueryRowContext(ctx, s.bind(`SELECT "name","stripeCustomerId" FROM "organization" WHERE "id"=?`), scope.ID).Scan(&out.Name, &cus); err != nil {
			return err
		}
		out.Customer = cus.String
		if out.Customer != "" {
			return s.checkCustomerOwner(ctx, tx, scope.ID, out.Customer)
		}
		return nil
	})
	return out, err
}

func (s *Store) StripeCustomerOrganization(ctx context.Context, customer string) (string, error) {
	if customer == "" {
		return "", nil
	}
	var found sql.NullString
	var n int
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT count(*),min("id") FROM "organization" WHERE "stripeCustomerId"=?`), customer).Scan(&n, &found)
	if err != nil || n == 0 {
		return "", err
	}
	if n != 1 {
		return "", billing.ErrCheckoutReconcile
	}
	var collision bool
	err = s.db.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "user" WHERE "id"=? OR "stripeCustomerId"=?)`), found.String, customer).Scan(&collision)
	if collision {
		return "", billing.ErrCheckoutReconcile
	}
	return found.String, err
}
