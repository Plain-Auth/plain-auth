package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	auth "github.com/nabuhadba/go-better-auth"
)

// StripeCustomer looks up the customer's own stored Stripe ID. Requires the
// stripe-subscriptions schema profile. An active or trialing subscription can
// supply the customer identifier for an account without a profile-level ID.
func (s *Store) StripeCustomer(ctx context.Context, userID string) (string, error) {
	var id sql.NullString
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT "stripeCustomerId" FROM "user" WHERE "id"=?`), userID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", auth.ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if id.Valid && id.String != "" {
		return id.String, nil
	}
	err = s.db.QueryRowContext(ctx, s.bind(`SELECT "stripeCustomerId" FROM "subscription" WHERE "referenceId"=? AND "status" IN ('active','trialing') AND "stripeCustomerId" IS NOT NULL ORDER BY "id" LIMIT 1`), userID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", auth.ErrNotFound
	}
	return id.String, err
}
