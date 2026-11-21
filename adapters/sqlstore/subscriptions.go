package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	auth "github.com/FineStack/finestack-auth"
	billing "github.com/FineStack/finestack-auth/plugins/stripe"
)

var _ billing.SubscriptionStore = (*Store)(nil)

const subscriptionFields = `"id","plan","referenceId","stripeCustomerId","stripeSubscriptionId","status","periodStart","periodEnd","trialStart","trialEnd","cancelAtPeriodEnd","cancelAt","canceledAt","endedAt","seats","billingInterval","stripeScheduleId"`

func (s *Store) CheckSubscriptionSchema(ctx context.Context) error {
	for _, q := range []string{`SELECT ` + subscriptionFields + ` FROM "subscription" WHERE 1=0`, `SELECT "stripeCustomerId" FROM "user" WHERE 1=0`} {
		rows, err := s.db.QueryContext(ctx, s.bind(q))
		if err != nil {
			return err
		}
		if err = rows.Close(); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) billingTransaction(ctx context.Context, userID, token string, now time.Time, action func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if token == "" {
		err = s.lockAccount(ctx, tx, userID)
	} else {
		err = s.lockActiveAccount(ctx, tx, userID, token, now)
	}
	if errors.Is(err, auth.ErrNotFound) {
		return billing.ErrCheckoutSession
	}
	if err != nil {
		return err
	}
	if err := action(tx); err != nil {
		return err
	}
	return tx.Commit()
}

type checkoutQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) checkoutAttempt(ctx context.Context, db checkoutQuerier, owner string) (billing.CheckoutAttempt, error) {
	var a billing.CheckoutAttempt
	var data []byte
	err := db.QueryRowContext(ctx, s.bind(`SELECT "value" FROM "verification" WHERE "identifier"=?`), "stripe-checkout:"+owner).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return a, auth.ErrNotFound
	}
	if err != nil {
		return a, err
	}
	err = json.Unmarshal(data, &a)
	return a, err
}
func (s *Store) FindStripeCheckout(ctx context.Context, owner, id string) (billing.CheckoutAttempt, error) {
	a, err := s.checkoutAttempt(ctx, s.db, owner)
	if err == nil && (id != a.ID || owner != a.Owner) {
		return billing.CheckoutAttempt{}, auth.ErrNotFound
	}
	return a, err
}
func (s *Store) ReserveStripeCheckout(ctx context.Context, owner, token string, want billing.CheckoutAttempt, now time.Time) (billing.CheckoutAttempt, error) {
	var result billing.CheckoutAttempt
	if token == "" {
		return result, billing.ErrCheckoutSession
	}
	err := s.billingTransaction(ctx, owner, token, now, func(tx *sql.Tx) error {
		a, err := s.checkoutAttempt(ctx, tx, owner)
		if err == nil {
			if now.Unix() >= a.Expires {
				return billing.ErrCheckoutReconcile
			}
			if a.Customer != "" {
				if err := s.checkCustomerOwner(ctx, tx, owner, a.Customer); err != nil {
					return err
				}
			}
			if a.Owner != owner || a.Plan != want.Plan || a.Price != want.Price || a.Interval != want.Interval || a.SuccessURL != want.SuccessURL || a.CancelURL != want.CancelURL {
				return billing.ErrPendingCheckout
			}
			result = a
			return nil
		}
		if !errors.Is(err, auth.ErrNotFound) {
			return err
		}
		var existing bool
		err = tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "subscription" WHERE "referenceId"=? AND "status" NOT IN ('canceled','incomplete_expired'))`), owner).Scan(&existing)
		if err != nil {
			return err
		}
		if existing {
			return billing.ErrExistingSubscription
		}
		var customer sql.NullString
		err = tx.QueryRowContext(ctx, s.bind(`SELECT "stripeCustomerId" FROM "user" WHERE "id"=?`), owner).Scan(&customer)
		if err != nil {
			return err
		}
		if customer.String != "" {
			if err := s.checkCustomerOwner(ctx, tx, owner, customer.String); err != nil {
				return err
			}
		}
		want.ID, want.Owner, want.LocalSubscription, want.Customer = rand.Text(), owner, rand.Text(), customer.String
		// Stripe accepts expiries 30 minutes to 24 hours after creation.
		want.Expires = now.Add(23 * time.Hour).Unix()
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "subscription" ("id","plan","referenceId","stripeCustomerId","status","seats","billingInterval") VALUES(?,?,?,?,'incomplete',1,?)`), want.LocalSubscription, want.Plan, owner, customer, want.Interval)
		if err != nil {
			return err
		}
		data, err := json.Marshal(want)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`), want.ID, "stripe-checkout:"+owner, string(data), s.date(time.Unix(want.Expires, 0)), s.date(now), s.date(now))
		result = want
		return err
	})
	return result, err
}

// The per-owner row lock orders reservations and webhook writes across nodes.
// No SQL transaction encompasses a network call to Stripe.
func (s *Store) checkCustomerOwner(ctx context.Context, tx *sql.Tx, owner, customer string) error {
	var current sql.NullString
	if err := tx.QueryRowContext(ctx, s.bind(`SELECT "stripeCustomerId" FROM "user" WHERE "id"=?`), owner).Scan(&current); err != nil {
		return err
	}
	if current.String != customer {
		return billing.ErrCheckoutReconcile
	}
	var other bool
	if err := tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "user" WHERE "stripeCustomerId"=? AND "id"<>?)`), customer, owner).Scan(&other); err != nil {
		return err
	}
	if other {
		return billing.ErrCheckoutReconcile
	}
	return nil
}
func (s *Store) editCheckout(ctx context.Context, want billing.CheckoutAttempt, token string, now time.Time, action func(*sql.Tx, *billing.CheckoutAttempt) error) error {
	if token == "" {
		return billing.ErrCheckoutSession
	}
	return s.billingTransaction(ctx, want.Owner, token, now, func(tx *sql.Tx) error {
		a, err := s.checkoutAttempt(ctx, tx, want.Owner)
		if errors.Is(err, auth.ErrNotFound) || (err == nil && a.ID != want.ID) {
			return billing.ErrCheckoutReconcile
		}
		if err != nil {
			return err
		}
		if err := action(tx, &a); err != nil {
			return err
		}
		data, err := json.Marshal(a)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE "verification" SET "value"=?,"updatedAt"=? WHERE "id"=? AND "identifier"=?`), string(data), s.date(now), a.ID, "stripe-checkout:"+a.Owner)
		return err
	})
}
func (s *Store) BindStripeCheckoutCustomer(ctx context.Context, want billing.CheckoutAttempt, token, customer string, now time.Time) error {
	return s.editCheckout(ctx, want, token, now, func(tx *sql.Tx, a *billing.CheckoutAttempt) error {
		var actual sql.NullString
		if err := tx.QueryRowContext(ctx, s.bind(`SELECT "stripeCustomerId" FROM "user" WHERE "id"=?`), a.Owner).Scan(&actual); err != nil {
			return err
		}
		if (actual.String != "" && actual.String != customer) || (a.Customer != "" && a.Customer != customer) || customer == "" {
			return billing.ErrCheckoutReconcile
		}
		_, err := tx.ExecContext(ctx, s.bind(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`), customer, a.Owner)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE "subscription" SET "stripeCustomerId"=? WHERE "id"=? AND "referenceId"=? AND "status"='incomplete'`), customer, a.LocalSubscription, a.Owner)
		if err != nil {
			return err
		}
		a.Customer = customer
		return s.checkCustomerOwner(ctx, tx, a.Owner, customer)
	})
}
func (s *Store) SaveStripeCheckoutResult(ctx context.Context, want billing.CheckoutAttempt, token, id, url string, now time.Time) error {
	return s.editCheckout(ctx, want, token, now, func(tx *sql.Tx, a *billing.CheckoutAttempt) error {
		if a.Customer == "" || a.Customer != want.Customer || (a.CheckoutID != "" && a.CheckoutID != id) {
			return billing.ErrCheckoutReconcile
		}
		a.CheckoutID, a.CheckoutURL = id, url
		return nil
	})
}
func (s *Store) stripeDate(unix int64) any {
	if unix <= 0 {
		return nil
	}
	return s.date(time.Unix(unix, 0))
}
func (s *Store) ApplyStripeCheckout(ctx context.Context, want billing.CheckoutAttempt, id, remote, status string, start, end, trialStart, trialEnd int64) error {
	return s.billingTransaction(ctx, want.Owner, "", time.Now(), func(tx *sql.Tx) error {
		a, err := s.checkoutAttempt(ctx, tx, want.Owner)
		if errors.Is(err, auth.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if a.ID != want.ID {
			return nil
		}
		if a.LocalSubscription != want.LocalSubscription || a.Customer != want.Customer || (a.CheckoutID != "" && a.CheckoutID != id) {
			return billing.ErrCheckoutReconcile
		}
		var customer sql.NullString
		if err := tx.QueryRowContext(ctx, s.bind(`SELECT "stripeCustomerId" FROM "user" WHERE "id"=?`), a.Owner).Scan(&customer); err != nil {
			return err
		}
		if customer.String == "" || customer.String != a.Customer {
			return billing.ErrCheckoutReconcile
		}
		var remoteID any
		if remote != "" {
			remoteID = remote
		}
		result, err := tx.ExecContext(ctx, s.bind(`UPDATE "subscription" SET "stripeSubscriptionId"=?,"status"=?,"periodStart"=?,"periodEnd"=?,"trialStart"=?,"trialEnd"=? WHERE "id"=? AND "referenceId"=? AND "stripeCustomerId"=? AND "status"='incomplete'`), remoteID, status, s.stripeDate(start), s.stripeDate(end), s.stripeDate(trialStart), s.stripeDate(trialEnd), a.LocalSubscription, a.Owner, a.Customer)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return billing.ErrCheckoutReconcile
		}
		_, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=?`), a.ID, "stripe-checkout:"+a.Owner)
		return err
	})
}
func (s *Store) ListStripeSubscriptions(ctx context.Context, owner, token string, now time.Time) ([]billing.Subscription, error) {
	result := []billing.Subscription{}
	if token == "" {
		return nil, billing.ErrCheckoutSession
	}
	err := s.billingTransaction(ctx, owner, token, now, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, s.bind(`SELECT `+subscriptionFields+` FROM "subscription" WHERE "referenceId"=? AND "status" IN ('active','trialing') ORDER BY "id"`), owner)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r billing.Subscription
			if err := rows.Scan(&r.ID, &r.Plan, &r.ReferenceID, &r.CustomerID, &r.SubscriptionID, &r.Status, &r.PeriodStart, &r.PeriodEnd, &r.TrialStart, &r.TrialEnd, &r.CancelAtPeriodEnd, &r.CancelAt, &r.CanceledAt, &r.EndedAt, &r.Seats, &r.Interval, &r.ScheduleID); err != nil {
				return err
			}
			result = append(result, r)
		}
		return rows.Err()
	})
	return result, err
}
