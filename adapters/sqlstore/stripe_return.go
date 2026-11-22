package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	billing "github.com/Plain-Auth/plain-auth/plugins/stripe"
)

var _ billing.CheckoutReturnStore = (*Store)(nil)

func (s *Store) finishCheckout(ctx context.Context, tx *sql.Tx, a billing.CheckoutAttempt, checkoutID string, completed bool, now time.Time) error {
	if completed && a.ReturnURL != "" {
		if checkoutID == "" {
			return billing.ErrCheckoutReconcile
		}
		ownerKey := stripeOwnerKey(ctx, "return", a.Owner)
		if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier"=? AND "expiresAt"<=?`), ownerKey, s.date(now)); err != nil {
			return err
		}
		// Keep the owner and final callback for replay. The hosted payment URL
		// and the original idempotency parameters are no longer needed.
		record := billing.CheckoutAttempt{OrganizationID: a.OrganizationID, ActorID: a.ActorID, ID: a.ID, Owner: a.Owner, LocalSubscription: a.LocalSubscription, Customer: a.Customer, SuccessURL: a.SuccessURL, CheckoutID: checkoutID}
		retention := 7 * 24 * time.Hour
		if a.RetainCompletion {
			retention = 45 * 24 * time.Hour
			record.SettledAt = now.Unix()
		}
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`), stripeRecordID("return", checkoutID), ownerKey, string(raw), s.date(now.Add(retention)), s.date(now), s.date(now)); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=?`), a.ID, stripeOwnerKey(ctx, "checkout", a.Owner))
	return err
}

func (s *Store) FindStripeCheckoutReturn(ctx context.Context, owner, token, checkoutID string, now time.Time) (billing.CheckoutReturn, error) {
	var found billing.CheckoutReturn
	if token == "" {
		return found, billing.ErrCheckoutSession
	}
	err := s.billingTransaction(ctx, owner, token, now, func(tx *sql.Tx) error {
		a, err := s.checkoutAttempt(ctx, tx, owner)
		if err != nil && !errors.Is(err, auth.ErrNotFound) {
			return err
		}
		if errors.Is(err, auth.ErrNotFound) || a.CheckoutID != checkoutID || a.ReturnURL == "" {
			record, err := s.settledStripeCheckout(ctx, tx, owner, checkoutID, now)
			if err != nil {
				return err
			}
			if record == nil || record.SettledAt != 0 && !now.Before(time.Unix(record.SettledAt, 0).Add(7*24*time.Hour)) {
				return auth.ErrNotFound
			}
			a = *record
			found.Settled = true
		}
		if a.Owner != owner || a.CheckoutID != checkoutID || a.Customer == "" {
			return auth.ErrNotFound
		}
		if err := s.checkCustomerOwner(ctx, tx, owner, a.Customer); err != nil {
			return err
		}
		var remote sql.NullString
		if err := tx.QueryRowContext(ctx, s.bind(`SELECT "stripeSubscriptionId" FROM "subscription" WHERE "id"=? AND "referenceId"=? AND "stripeCustomerId"=?`), a.LocalSubscription, owner, a.Customer).Scan(&remote); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return auth.ErrNotFound
			}
			return err
		}
		found.BoundSubscriptionID, found.Attempt = remote.String, a
		return nil
	})
	return found, err
}

func (s *Store) ApplyStripeCheckoutReturn(ctx context.Context, a billing.CheckoutAttempt, token, checkoutID string, receipt billing.CheckoutReceipt, now time.Time) error {
	if token == "" {
		return billing.ErrCheckoutSession
	}
	if checkoutID == "" || a.CheckoutID != checkoutID || a.ReturnURL == "" || receipt.RemoteID == "" {
		return billing.ErrCheckoutReconcile
	}
	return s.applyStripeCheckout(ctx, a, token, checkoutID, receipt, now)
}

func (s *Store) settledStripeCheckout(ctx context.Context, db rowQuerier, owner, checkoutID string, now time.Time) (*billing.CheckoutAttempt, error) {
	var raw []byte
	err := db.QueryRowContext(ctx, s.bind(`SELECT "value" FROM "verification" WHERE "id"=? AND "identifier"=? AND "expiresAt">?`), stripeRecordID("return", checkoutID), stripeOwnerKey(ctx, "return", owner), s.date(now)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var a billing.CheckoutAttempt
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, err
	}
	if a.Owner != owner || a.CheckoutID != checkoutID || a.Customer == "" {
		return nil, billing.ErrCheckoutReconcile
	}
	return &a, nil
}

// A prior receipt authenticates a redelivery even after the original purchase
// binding expires. Either path must still identify the same customer and local row.
func (s *Store) stripeCheckoutDelivery(ctx context.Context, db stripeCatalog, key billing.SubscriptionIdentity) (confirmed, repeated bool, err error) {
	want := key.ConfirmedCheckout
	if want == nil || want.ID == "" || want.CheckoutID == "" || key.Owner == "" || key.LocalID == "" || key.NoticeType != "checkout.session.completed" {
		return false, false, billing.ErrCheckoutReconcile
	}
	prior, _, err := s.readSubscriptionReceipt(ctx, db, key)
	if err != nil || prior != nil {
		return prior != nil, prior != nil, err
	}
	bound, err := s.settledStripeCheckout(ctx, db, key.Owner, want.CheckoutID, time.Now())
	if err != nil || bound == nil {
		return false, false, err
	}
	if bound.ID != want.ID || bound.LocalSubscription != key.LocalID || bound.Customer != key.CustomerID || bound.ActorID != want.ActorID || bound.OrganizationID != want.OrganizationID {
		return false, false, billing.ErrCheckoutReconcile
	}
	_, _, err = s.subscriptionRevision(ctx, db, billing.SubscriptionIdentity{Owner: key.Owner, LocalID: key.LocalID, RemoteID: key.RemoteID, CustomerID: key.CustomerID})
	return err == nil, false, err
}

func (s *Store) ConfirmStripeCheckoutDelivery(ctx context.Context, key billing.SubscriptionIdentity) (bool, error) {
	ok, _, err := s.stripeCheckoutDelivery(ctx, s.db, key)
	return ok, err
}
