package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	billing "github.com/Stonewrit/stonewrit-auth/plugins/stripe"
	sdk "github.com/stripe/stripe-go/v87"
)

type stripeUpdateReceipt struct {
	EventID, Fingerprint string
	Subscription         billing.Subscription
	Kind                 sdk.EventType `json:",omitempty"`
	Update               bool          `json:",omitempty"`
	Transition           bool          `json:",omitempty"`
	Claimed              bool          `json:",omitempty"`
	CreatedPlan          *billing.Plan `json:",omitempty"`
}

func (s *Store) subscriptionEventReceipt(ctx context.Context, tx *sql.Tx, key billing.SubscriptionIdentity, r billing.SubscriptionRevision, c billing.SubscriptionChange) (*stripeUpdateReceipt, error) {
	if key.UpdateFingerprint == "" || key.EventID == "" {
		return nil, nil
	}
	known := r.LocalID != "" || c.Metadata["subscriptionId"] != ""
	m := &stripeUpdateReceipt{EventID: key.EventID, Fingerprint: key.UpdateFingerprint, Kind: key.NoticeType}
	switch key.NoticeType {
	case sdk.EventTypeCheckoutSessionCompleted:
		// The calling transaction has already matched the signed purchase or its event receipt.
		if key.ConfirmedCheckout == nil {
			return nil, billing.ErrCheckoutReconcile
		}
	case sdk.EventTypeCustomerSubscriptionCreated:
		// Checkout creates a local row before Stripe creates the subscription.
		if known || key.CreatedPlan == nil || c.Plan == "" {
			return nil, nil
		}
		m.Transition = true
		m.CreatedPlan = key.CreatedPlan
	case sdk.EventTypeCustomerSubscriptionDeleted:
		if r.LocalID == "" {
			return nil, nil
		}
	case "", sdk.EventTypeCustomerSubscriptionUpdated:
		if !known {
			return nil, nil
		}
		m.Update = key.NotifyUpdate || key.NoticeType == ""
		if key.NotifyCancellation && c.Status == "active" && (c.CancelAtPeriodEnd || c.CancelAt != 0) {
			id := r.LocalID
			if id == "" {
				id = c.Metadata["subscriptionId"]
			}
			var flag sql.NullBool
			var cancelAt sql.NullTime
			if err := tx.QueryRowContext(ctx, s.bind(`SELECT "cancelAtPeriodEnd","cancelAt" FROM "subscription" WHERE "id"=? AND "referenceId"=? AND "stripeCustomerId"=?`), id, r.Owner, key.CustomerID).Scan(&flag, &cancelAt); err != nil {
				return nil, err
			}
			m.Transition = !flag.Bool && !cancelAt.Valid
		}
		if !m.Transition && !m.Update {
			return nil, nil
		}
	default:
		return nil, billing.ErrCheckoutReconcile
	}
	return m, nil
}

// This row shares the existing event retention period and owner cleanup.
// Only the committed local projection is retained, never the Stripe payload.
func (s *Store) saveSubscriptionUpdate(ctx context.Context, tx *sql.Tx, key billing.SubscriptionIdentity, owner string, now time.Time, receipt *stripeUpdateReceipt) error {
	row, err := s.stripeDeliverySubscription(ctx, tx, key, owner)
	if err != nil {
		return err
	}
	receipt.Subscription = row
	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	// A redelivery after the 45-day deduplication period may reuse the ID.
	id := stripeRecordID("subscription-update-receipt", key.EventID)
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "expiresAt"<=?`), id, s.date(now)); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`), id, stripeOwnerKey(ctx, "event", owner), string(data), s.date(now.Add(45*24*time.Hour)), s.date(now), s.date(now))
	return err
}

func (s *Store) readSubscriptionReceipt(ctx context.Context, db stripeCatalog, key billing.SubscriptionIdentity) (*stripeUpdateReceipt, []byte, error) {
	if key.EventID == "" || key.UpdateFingerprint == "" {
		return nil, nil, billing.ErrCheckoutReconcile
	}
	var id string
	var raw []byte
	err := db.QueryRowContext(ctx, s.bind(`SELECT "identifier","value" FROM "verification" WHERE "id"=? AND "expiresAt">?`), stripeRecordID("subscription-update-receipt", key.EventID), s.date(time.Now())).Scan(&id, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var receipt stripeUpdateReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return nil, nil, err
	}
	row := receipt.Subscription
	if receipt.EventID != key.EventID || receipt.Fingerprint != key.UpdateFingerprint || row.CustomerID == nil || *row.CustomerID != key.CustomerID || row.SubscriptionID == nil || *row.SubscriptionID != key.RemoteID || id != stripeOwnerKey(ctx, "event", row.ReferenceID) {
		return nil, nil, billing.ErrCheckoutReconcile
	}
	r, _, err := s.subscriptionRevision(ctx, db, billing.SubscriptionIdentity{RemoteID: key.RemoteID, CustomerID: key.CustomerID})
	if err != nil {
		return nil, nil, err
	}
	if r.Owner == "" || r.LocalID == "" {
		return nil, nil, nil
	}
	if r.Owner != row.ReferenceID || r.LocalID != row.ID || key.Owner != "" && (key.Owner != row.ReferenceID || key.LocalID != row.ID) {
		return nil, nil, billing.ErrCheckoutReconcile
	}
	kind := receipt.Kind
	if kind == "" {
		kind = sdk.EventTypeCustomerSubscriptionUpdated
		receipt.Update = true
	}
	expected := key.NoticeType
	if expected == "" {
		expected = sdk.EventTypeCustomerSubscriptionUpdated
	}
	if kind != expected {
		return nil, nil, billing.ErrCheckoutReconcile
	}
	return &receipt, raw, nil
}

func (s *Store) ReadStripeSubscriptionUpdate(ctx context.Context, key billing.SubscriptionIdentity) (*billing.Subscription, error) {
	m, _, err := s.readSubscriptionReceipt(ctx, s.db, key)
	if err != nil || m == nil || !m.Update {
		return nil, err
	}
	return &m.Subscription, nil
}

func (s *Store) ReadStripeSubscriptionNotification(ctx context.Context, key billing.SubscriptionIdentity) (*billing.SubscriptionNotification, error) {
	m, original, err := s.readSubscriptionReceipt(ctx, s.db, key)
	if err != nil || m == nil {
		return nil, err
	}
	result := &billing.SubscriptionNotification{Subscription: m.Subscription, Update: m.Update, CreatedPlan: m.CreatedPlan}
	if m.Transition && !m.Claimed {
		m.Claimed = true
		raw, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		// Atomically claim this transition. A duplicate delivery can still
		// invoke its per-delivery update hook without repeating the transition.
		res, err := s.db.ExecContext(ctx, s.bind(`UPDATE "verification" SET "value"=? WHERE "id"=? AND "identifier"=? AND "value"=? AND "expiresAt">?`), string(raw), stripeRecordID("subscription-update-receipt", key.EventID), stripeOwnerKey(ctx, "event", m.Subscription.ReferenceID), string(original), s.date(time.Now()))
		if err != nil {
			return nil, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, err
		}
		result.Transition = n == 1
	}
	return result, nil
}

func (s *Store) stripeDeliverySubscription(ctx context.Context, tx *sql.Tx, key billing.SubscriptionIdentity, owner string) (billing.Subscription, error) {
	query := s.bind(`SELECT ` + subscriptionFields + ` FROM "subscription" WHERE "stripeSubscriptionId"=? AND "referenceId"=? AND "stripeCustomerId"=?`)
	row, err := scanStripeSubscription(tx.QueryRowContext(ctx, query, key.RemoteID, owner, key.CustomerID))
	if err != nil {
		return row, err
	}
	if row.ReferenceID != owner || row.SubscriptionID == nil || *row.SubscriptionID != key.RemoteID || row.CustomerID == nil || *row.CustomerID != key.CustomerID {
		return row, billing.ErrCheckoutReconcile
	}
	return row, nil
}
