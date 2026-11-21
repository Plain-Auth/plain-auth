package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	billing "github.com/Stonewrit/stonewrit-auth/plugins/stripe"
)

var _ billing.SubscriptionStore = (*Store)(nil)

const subscriptionFields = `"id","plan","referenceId","stripeCustomerId","stripeSubscriptionId","status","periodStart","periodEnd","trialStart","trialEnd","cancelAtPeriodEnd","cancelAt","canceledAt","endedAt","seats","billingInterval","stripeScheduleId"`

func (s *Store) CheckSubscriptionSchema(ctx context.Context) error {
	for _, q := range []string{`SELECT t.` + strings.ReplaceAll(subscriptionFields, ",", ",t.") + ` FROM "subscription" t WHERE 1=0`, `SELECT u."stripeCustomerId" FROM "user" u WHERE 1=0`} {
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
	if org, ok := billing.OrganizationFromContext(ctx); ok {
		err = s.lockStripeOrganization(ctx, tx, org, userID, token, now)
	} else if token == "" {
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
	if err := s.distinctStripeReference(ctx, tx, userID, ""); err != nil {
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
	err := db.QueryRowContext(ctx, s.bind(`SELECT "value" FROM "verification" WHERE "identifier"=?`), stripeOwnerKey(ctx, "checkout", owner)).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return a, auth.ErrNotFound
	}
	if err != nil {
		return a, err
	}
	err = json.Unmarshal(data, &a)
	return a, err
}
func (s *Store) PendingStripeCheckout(ctx context.Context, owner string) (billing.CheckoutAttempt, error) {
	return s.checkoutAttempt(ctx, s.db, owner)
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
	if want.Seats < 0 || want.Seats > math.MaxInt32 {
		return result, billing.ErrInvalidSeatQuantity
	}
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
			if a.Owner != owner || a.Plan != want.Plan || a.Price != want.Price || a.AutomaticSeats != want.AutomaticSeats || !a.AutomaticSeats && a.Quantity() != want.Quantity() || a.Interval != want.Interval || a.SuccessURL != want.SuccessURL || a.CancelURL != want.CancelURL {
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
		if want.AutomaticSeats {
			scope, ok := billing.OrganizationFromContext(ctx)
			if !ok || want.OrganizationID != owner || scope.ID != owner {
				return billing.ErrOrganizationBillingAccess
			}
			want.Seats, err = s.organizationSeatCount(ctx, tx, owner)
			if err != nil {
				return err
			}
			if want.Seats < 1 || want.Seats > math.MaxInt32 {
				return billing.ErrInvalidSeatQuantity
			}
		}
		if (want.AutomaticSeats || want.Quantity() > 1) && !want.PriceVerified {
			return billing.ErrCheckoutPriceCheck
		}
		var customer sql.NullString
		err = tx.QueryRowContext(ctx, s.bind(`SELECT "stripeCustomerId" FROM `+billingTable(ctx)+` WHERE "id"=?`), owner).Scan(&customer)
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
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "subscription" ("id","plan","referenceId","stripeCustomerId","status","seats","billingInterval") VALUES(?,?,?,?,'incomplete',?,?)`), want.LocalSubscription, want.Plan, owner, customer, want.Quantity(), want.Interval)
		if err != nil {
			return err
		}
		data, err := json.Marshal(want)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`), want.ID, stripeOwnerKey(ctx, "checkout", owner), string(data), s.date(time.Unix(want.Expires, 0)), s.date(now), s.date(now))
		result = want
		return err
	})
	return result, err
}

// The per-owner row lock orders reservations and webhook writes across nodes.
// No SQL transaction encompasses a network call to Stripe.
func (s *Store) checkCustomerOwner(ctx context.Context, tx *sql.Tx, owner, customer string) error {
	var current sql.NullString
	if err := tx.QueryRowContext(ctx, s.bind(`SELECT "stripeCustomerId" FROM `+billingTable(ctx)+` WHERE "id"=?`), owner).Scan(&current); err != nil {
		return err
	}
	if err := s.distinctStripeReference(ctx, tx, owner, customer); err != nil {
		return err
	}
	if current.String != customer {
		return billing.ErrCheckoutReconcile
	}
	var other bool
	if err := tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM `+billingTable(ctx)+` WHERE "stripeCustomerId"=? AND "id"<>?)`), customer, owner).Scan(&other); err != nil {
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
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE "verification" SET "value"=?,"updatedAt"=? WHERE "id"=? AND "identifier"=?`), string(data), s.date(now), a.ID, stripeOwnerKey(ctx, "checkout", a.Owner))
		return err
	})
}
func (s *Store) BindStripeCheckoutCustomer(ctx context.Context, want billing.CheckoutAttempt, token, customer string, now time.Time) error {
	return s.editCheckout(ctx, want, token, now, func(tx *sql.Tx, a *billing.CheckoutAttempt) error {
		var actual sql.NullString
		if err := tx.QueryRowContext(ctx, s.bind(`SELECT "stripeCustomerId" FROM `+billingTable(ctx)+` WHERE "id"=?`), a.Owner).Scan(&actual); err != nil {
			return err
		}
		if (actual.String != "" && actual.String != customer) || (a.Customer != "" && a.Customer != customer) || customer == "" {
			return billing.ErrCheckoutReconcile
		}
		_, err := tx.ExecContext(ctx, s.bind(`UPDATE `+billingTable(ctx)+` SET "stripeCustomerId"=? WHERE "id"=?`), customer, a.Owner)
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
		if err := s.checkCustomerOwner(ctx, tx, a.Owner, a.Customer); err != nil {
			return err
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
	receipt := billing.CheckoutReceipt{RemoteID: remote, Status: status, PeriodStart: start, PeriodEnd: end, TrialStart: trialStart, TrialEnd: trialEnd}
	return s.applyStripeCheckout(ctx, want, "", id, receipt, time.Now())
}
func (s *Store) applyStripeCheckout(ctx context.Context, want billing.CheckoutAttempt, token, id string, receipt billing.CheckoutReceipt, now time.Time) error {
	remote, status := receipt.RemoteID, receipt.Status
	return s.billingTransaction(ctx, want.Owner, token, now, func(tx *sql.Tx) error {
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
		if a.LocalSubscription != want.LocalSubscription || a.Quantity() != want.Quantity() || a.Customer != want.Customer || (a.CheckoutID != "" && a.CheckoutID != id) {
			return billing.ErrCheckoutReconcile
		}
		var customer sql.NullString
		if err := tx.QueryRowContext(ctx, s.bind(`SELECT "stripeCustomerId" FROM `+billingTable(ctx)+` WHERE "id"=?`), a.Owner).Scan(&customer); err != nil {
			return err
		}
		if customer.String == "" || customer.String != a.Customer {
			return billing.ErrCheckoutReconcile
		}
		var bound sql.NullString
		if err := tx.QueryRowContext(ctx, s.bind(`SELECT "stripeSubscriptionId" FROM "subscription" WHERE "id"=? AND "referenceId"=? AND "stripeCustomerId"=?`), a.LocalSubscription, a.Owner, a.Customer).Scan(&bound); err != nil {
			return err
		}
		if bound.Valid {
			if remote != "" && remote != bound.String {
				return billing.ErrCheckoutReconcile
			}
			// A lifecycle webhook may complete while Checkout retrieves Stripe.
			return s.settleBoundSubscription(ctx, tx, a, id, bound.String)
		}
		if remote != "" {
			r, cursor, err := s.subscriptionRevision(ctx, tx, billing.SubscriptionIdentity{CustomerID: a.Customer, RemoteID: remote})
			if err != nil {
				return err
			}
			if r.Owner != a.Owner || (r.LocalID != "" && r.LocalID != a.LocalSubscription) {
				return billing.ErrCheckoutReconcile
			}
			if cursor.Terminal != "" {
				// Checkout may have fetched its snapshot before a signed terminal event.
				status = cursor.Terminal
			}
		}
		if status == "" {
			return billing.ErrCheckoutReconcile
		}
		var remoteID any
		if remote != "" {
			remoteID = remote
		}
		result, err := tx.ExecContext(ctx, s.bind(`UPDATE "subscription" SET "stripeSubscriptionId"=?,"status"=?,"periodStart"=?,"periodEnd"=?,"trialStart"=?,"trialEnd"=? WHERE "id"=? AND "referenceId"=? AND "stripeCustomerId"=? AND "status"='incomplete'`), remoteID, status, s.stripeDate(receipt.PeriodStart), s.stripeDate(receipt.PeriodEnd), s.stripeDate(receipt.TrialStart), s.stripeDate(receipt.TrialEnd), a.LocalSubscription, a.Owner, a.Customer)
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
		return s.finishCheckout(ctx, tx, a, id, remote != "", now)
	})
}
func (s *Store) ListStripeSubscriptions(ctx context.Context, owner, token string, now time.Time) ([]billing.Subscription, error) {
	result := []billing.Subscription{}
	if token == "" {
		return nil, billing.ErrCheckoutSession
	}
	err := s.billingTransaction(ctx, owner, token, now, func(tx *sql.Tx) error {
		query := `SELECT ` + subscriptionFields + ` FROM "subscription" WHERE "referenceId"=? AND "status" IN ('active','trialing')`
		args := []any{owner}
		if _, ok := billing.OrganizationFromContext(ctx); ok {
			var customer sql.NullString
			if err := tx.QueryRowContext(ctx, s.bind(`SELECT "stripeCustomerId" FROM "organization" WHERE "id"=?`), owner).Scan(&customer); err != nil {
				return err
			}
			if !customer.Valid || customer.String == "" {
				return nil
			}
			if err := s.checkCustomerOwner(ctx, tx, owner, customer.String); err != nil {
				return err
			}
			query += ` AND "stripeCustomerId"=?`
			args = append(args, customer.String)
		}
		rows, err := tx.QueryContext(ctx, s.bind(query+` ORDER BY "id"`), args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanStripeSubscription(rows)
			if err != nil {
				return err
			}
			result = append(result, r)
		}
		return rows.Err()
	})
	return result, err
}

func scanStripeSubscription(row rowScanner) (billing.Subscription, error) {
	var r billing.Subscription
	err := row.Scan(&r.ID, &r.Plan, &r.ReferenceID, &r.CustomerID, &r.SubscriptionID, &r.Status,
		&r.PeriodStart, &r.PeriodEnd, &r.TrialStart, &r.TrialEnd, &r.CancelAtPeriodEnd, &r.CancelAt,
		&r.CanceledAt, &r.EndedAt, &r.Seats, &r.Interval, &r.ScheduleID)
	return r, err
}

func (s *Store) ManagedStripeSubscription(ctx context.Context, owner, token, providerID string, now time.Time) (billing.Subscription, error) {
	var sub billing.Subscription
	if token == "" {
		return sub, billing.ErrCheckoutSession
	}
	err := s.billingTransaction(ctx, owner, token, now, func(tx *sql.Tx) error {
		query := `SELECT ` + subscriptionFields + ` FROM "subscription" WHERE "referenceId"=?`
		args := []any{owner}
		if providerID == "" {
			query += ` AND "status" IN ('active','trialing')`
		} else {
			query += ` AND "stripeSubscriptionId"=?`
			args = append(args, providerID)
		}
		r, err := scanStripeSubscription(tx.QueryRowContext(ctx, s.bind(query+` ORDER BY "id" LIMIT 1`), args...))
		if errors.Is(err, sql.ErrNoRows) {
			return auth.ErrNotFound
		}
		if err != nil {
			return err
		}
		if r.CustomerID == nil || *r.CustomerID == "" || r.SubscriptionID == nil || *r.SubscriptionID == "" {
			return auth.ErrNotFound
		}
		if err := s.checkCustomerOwner(ctx, tx, owner, *r.CustomerID); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "subscription" WHERE "stripeSubscriptionId"=?`), *r.SubscriptionID).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return billing.ErrCheckoutReconcile
		}
		sub = r
		return nil
	})
	return sub, err
}
