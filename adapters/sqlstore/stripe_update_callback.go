package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	billing "github.com/Stonewrit/stonewrit-auth/plugins/stripe"
)

type stripeUpdateReceipt struct {
	EventID, Fingerprint string
	Subscription         billing.Subscription
}

// This row shares the existing event retention period and owner cleanup.
// Only the committed local projection is retained, never the Stripe payload.
func (s *Store) saveSubscriptionUpdate(ctx context.Context, tx *sql.Tx, key billing.SubscriptionIdentity, owner string, now time.Time) error {
	query := s.bind(`SELECT ` + subscriptionFields + ` FROM "subscription" WHERE "stripeSubscriptionId"=? AND "referenceId"=? AND "stripeCustomerId"=?`)
	row, err := scanStripeSubscription(tx.QueryRowContext(ctx, query, key.RemoteID, owner, key.CustomerID))
	if err != nil {
		return err
	}
	if row.ReferenceID != owner || row.SubscriptionID == nil || *row.SubscriptionID != key.RemoteID || row.CustomerID == nil || *row.CustomerID != key.CustomerID {
		return billing.ErrCheckoutReconcile
	}
	receipt := stripeUpdateReceipt{EventID: key.EventID, Fingerprint: key.UpdateFingerprint, Subscription: row}
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

func (s *Store) ReadStripeSubscriptionUpdate(ctx context.Context, key billing.SubscriptionIdentity) (*billing.Subscription, error) {
	if key.EventID == "" || key.UpdateFingerprint == "" {
		return nil, billing.ErrCheckoutReconcile
	}
	var id string
	var raw []byte
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT "identifier","value" FROM "verification" WHERE "id"=? AND "expiresAt">?`), stripeRecordID("subscription-update-receipt", key.EventID), s.date(time.Now())).Scan(&id, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var receipt stripeUpdateReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return nil, err
	}
	row := receipt.Subscription
	if receipt.EventID != key.EventID || receipt.Fingerprint != key.UpdateFingerprint || row.CustomerID == nil || *row.CustomerID != key.CustomerID || row.SubscriptionID == nil || *row.SubscriptionID != key.RemoteID || id != stripeOwnerKey(ctx, "event", row.ReferenceID) {
		return nil, billing.ErrCheckoutReconcile
	}
	r, _, err := s.subscriptionRevision(ctx, s.db, billing.SubscriptionIdentity{RemoteID: key.RemoteID, CustomerID: key.CustomerID})
	if err != nil {
		return nil, err
	}
	if r.Owner == "" || r.LocalID == "" {
		return nil, nil
	}
	if r.Owner != row.ReferenceID || r.LocalID != row.ID {
		return nil, billing.ErrCheckoutReconcile
	}
	return &row, nil
}
