package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	auth "github.com/Plain-Org/plain-auth"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
)

var _ billing.UserCustomerStore = (*Store)(nil)

// CheckStripeCustomerSchema checks for the user's stripeCustomerId column,
// which the stripe-subscriptions and stripe-organization profiles add. The
// column is qualified: SQLite reads an unknown quoted name as a string.
func (s *Store) CheckStripeCustomerSchema(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT u."stripeCustomerId" FROM "user" u WHERE 1=0`))
	if err != nil {
		return err
	}
	return rows.Close()
}

// LinkStripeUserCustomer stores customer as the user's Stripe customer
// while the user has none and no personal Checkout reservation, and reports
// whether it did. A reservation copied the empty column, so the Checkout
// binds its own customer; linking another would refuse that binding.
func (s *Store) LinkStripeUserCustomer(ctx context.Context, userID, customer string) (bool, error) {
	if customer == "" {
		return false, errors.New("sqlstore: empty Stripe customer")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	err = s.lockAccount(ctx, tx, userID)
	if errors.Is(err, auth.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var current sql.NullString
	if err := tx.QueryRowContext(ctx, s.bind(`SELECT "stripeCustomerId" FROM "user" WHERE "id"=?`), userID).Scan(&current); err != nil {
		return false, err
	}
	var pending bool
	if err := tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "verification" WHERE "identifier"=?)`), "stripe-checkout:"+userID).Scan(&pending); err != nil {
		return false, err
	}
	if current.String != "" || pending {
		return false, nil
	}
	var other bool
	if err := tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "user" WHERE "stripeCustomerId"=? AND "id"<>?)`), customer, userID).Scan(&other); err != nil {
		return false, err
	}
	if other {
		return false, billing.ErrCustomerInUse
	}
	if err := s.distinctStripeReference(ctx, tx, userID, customer); err != nil {
		if errors.Is(err, billing.ErrCheckoutReconcile) {
			return false, billing.ErrCustomerInUse
		}
		return false, err
	}
	if _, err := s.execUserUpdate(ctx, tx, userID, s.bind(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`), customer, userID); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
