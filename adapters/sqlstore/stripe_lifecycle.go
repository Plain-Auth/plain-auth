package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	billing "github.com/Stonewrit/stonewrit-auth/plugins/stripe"
)

var _ billing.SubscriptionLifecycleStore = (*Store)(nil)

type stripeCatalog interface {
	checkoutQuerier
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type stripeCursor struct {
	Version  string
	Terminal string
}

func stripeRecordID(purpose, value string) string {
	sum := sha256.Sum256([]byte("stripe-" + purpose + ":" + value))
	return hex.EncodeToString(sum[:18]) // fits the canonical 36-character MySQL ID
}

func (s *Store) subscriptionRevision(ctx context.Context, db stripeCatalog, key billing.SubscriptionIdentity) (billing.SubscriptionRevision, stripeCursor, error) {
	var r billing.SubscriptionRevision
	var cursor stripeCursor
	owners, err := db.QueryContext(ctx, s.bind(`SELECT "id","stripeCustomerId" FROM `+billingTable(ctx)+` WHERE "stripeCustomerId"=? LIMIT 2`), key.CustomerID)
	if err != nil {
		return r, cursor, err
	}
	for owners.Next() {
		if r.Owner != "" {
			owners.Close()
			return r, cursor, billing.ErrCheckoutReconcile
		}
		var customer string
		if err := owners.Scan(&r.Owner, &customer); err != nil {
			owners.Close()
			return r, cursor, err
		}
		if customer != key.CustomerID {
			owners.Close()
			return r, cursor, billing.ErrCheckoutReconcile
		}
	}
	err = owners.Err()
	owners.Close()
	if err != nil {
		return r, cursor, err
	}
	if r.Owner != "" {
		if err := s.distinctStripeReference(ctx, db, r.Owner, key.CustomerID); err != nil {
			return r, cursor, err
		}
	}
	rows, err := db.QueryContext(ctx, s.bind(`SELECT "id","referenceId","stripeCustomerId","stripeSubscriptionId" FROM "subscription" WHERE "stripeSubscriptionId"=? LIMIT 2`), key.RemoteID)
	if err != nil {
		return r, cursor, err
	}
	defer rows.Close()
	for rows.Next() {
		var owner, remote string
		var customer sql.NullString
		if r.LocalID != "" {
			return r, cursor, billing.ErrCheckoutReconcile
		}
		if err := rows.Scan(&r.LocalID, &owner, &customer, &remote); err != nil {
			return r, cursor, err
		}
		if (r.Owner != "" && owner != r.Owner) || customer.String != key.CustomerID || remote != key.RemoteID {
			return r, cursor, billing.ErrCheckoutReconcile
		}
	}
	if err := rows.Err(); err != nil {
		return r, cursor, err
	}
	if key.Owner != "" && (r.Owner != key.Owner || r.LocalID != key.LocalID) {
		return r, cursor, billing.ErrCheckoutReconcile
	}
	if r.Owner == "" {
		r.Skip = true
		return r, cursor, nil
	}
	var raw []byte
	var identifier string
	err = db.QueryRowContext(ctx, s.bind(`SELECT "identifier","value" FROM "verification" WHERE "id"=?`), stripeRecordID("subscription", key.RemoteID)).Scan(&identifier, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return r, cursor, nil
	}
	if err != nil {
		return r, cursor, err
	}
	if identifier != stripeOwnerKey(ctx, "sync", r.Owner) {
		return r, cursor, billing.ErrCheckoutReconcile
	}
	if err := json.Unmarshal(raw, &cursor); err != nil {
		return r, cursor, err
	}
	r.Version = cursor.Version
	if key.EventID != "" {
		if cursor.Terminal != "" {
			r.Skip = true
			return r, cursor, nil
		}
		var receivedRemote, receivedBy string
		err = db.QueryRowContext(ctx, s.bind(`SELECT "identifier","value" FROM "verification" WHERE "id"=? AND "expiresAt">?`), stripeRecordID("event", key.EventID), s.date(time.Now())).Scan(&receivedBy, &receivedRemote)
		if err == nil {
			if receivedBy != stripeOwnerKey(ctx, "event", r.Owner) || receivedRemote != key.RemoteID {
				return r, cursor, billing.ErrCheckoutReconcile
			}
			r.Skip = true
		} else if !errors.Is(err, sql.ErrNoRows) {
			return r, cursor, err
		}
	}
	return r, cursor, nil
}

func (s *Store) ReadStripeSubscriptionRevision(ctx context.Context, key billing.SubscriptionIdentity) (billing.SubscriptionRevision, error) {
	r, _, err := s.subscriptionRevision(ctx, s.db, key)
	return r, err
}

func (s *Store) ApplyStripeSubscriptionChange(ctx context.Context, key billing.SubscriptionIdentity, before billing.SubscriptionRevision, c billing.SubscriptionChange) error {
	if before.Owner == "" {
		return billing.ErrCheckoutReconcile
	}
	return s.billingTransaction(ctx, before.Owner, key.SessionToken, time.Now(), func(tx *sql.Tx) error {
		r, cursor, err := s.subscriptionRevision(ctx, tx, key)
		if err != nil || r.Skip {
			return err
		}
		if before.Version != r.Version || before.LocalID != r.LocalID || before.Owner != r.Owner {
			return billing.ErrStripeRevisionChanged
		}
		if cursor.Terminal != "" && c.Status != "canceled" && c.Status != "incomplete_expired" {
			return billing.ErrCheckoutReconcile
		}
		if err := s.applyCurrentSubscription(ctx, tx, key, r, c); err != nil {
			return err
		}
		if c.Deleted || c.Status == "canceled" || c.Status == "incomplete_expired" {
			cursor.Terminal = c.Status
		}
		cursor.Version = rand.Text()
		data, err := json.Marshal(cursor)
		if err != nil {
			return err
		}
		id := stripeRecordID("subscription", key.RemoteID)
		currentTime := time.Now().UTC()
		now := s.date(currentTime)
		if key.EventID != "" {
			identifier := stripeOwnerKey(ctx, "event", r.Owner)
			if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier"=? AND "expiresAt"<=?`), identifier, now); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), stripeRecordID("event", key.EventID), identifier, key.RemoteID, s.date(currentTime.Add(45*24*time.Hour)), now, now); err != nil {
				return err
			}
		}
		if before.Version != "" {
			_, err = tx.ExecContext(ctx, s.bind(`UPDATE "verification" SET "value"=?,"updatedAt"=? WHERE "id"=?`), string(data), now, id)
		} else {
			// Keep the terminal fence for the lifetime of the customer mapping.
			until := s.date(time.Unix(1<<31-1, 0)) // maximum portable MySQL TIMESTAMP
			_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`), id, stripeOwnerKey(ctx, "sync", r.Owner), string(data), until, now, now)
		}
		return err
	})
}

func (s *Store) applyCurrentSubscription(ctx context.Context, tx *sql.Tx, key billing.SubscriptionIdentity, r billing.SubscriptionRevision, c billing.SubscriptionChange) error {
	meta := c.Metadata
	org, isOrg := billing.OrganizationFromContext(ctx)
	if isOrg {
		if (meta["customerType"] != "" && meta["customerType"] != "organization") || (meta["organizationId"] != "" && meta["organizationId"] != org.ID) ||
			(meta["userId"] != "" && meta["organizationId"] == "" && meta["referenceId"] == "") {
			return billing.ErrCheckoutReconcile
		}
	} else if (meta["customerType"] != "" && meta["customerType"] != "user") || meta["organizationId"] != "" || (meta["userId"] != "" && meta["userId"] != r.Owner) {
		return billing.ErrCheckoutReconcile
	}
	if meta["referenceId"] != "" && meta["referenceId"] != r.Owner {
		return billing.ErrCheckoutReconcile
	}
	id := r.LocalID
	claim := meta["subscriptionId"]
	if id != "" && claim != "" && claim != id {
		return billing.ErrCheckoutReconcile
	}
	if id == "" && (claim != "" || meta["checkoutAttemptId"] != "") {
		// An unbound checkout row can only be claimed using the exact
		// server-authored reservation. Never guess from the owner's other rows.
		a, err := s.checkoutAttempt(ctx, tx, r.Owner)
		if errors.Is(err, auth.ErrNotFound) {
			return billing.ErrCheckoutReconcile
		}
		if err != nil {
			return err
		}
		actor := r.Owner
		if isOrg {
			actor = a.ActorID
		}
		if a.ID != meta["checkoutAttemptId"] || a.LocalSubscription != claim || a.Customer != key.CustomerID || a.Owner != r.Owner || meta["userId"] != actor || meta["referenceId"] != r.Owner {
			return billing.ErrCheckoutReconcile
		}
		var current sql.NullString
		if err = tx.QueryRowContext(ctx, s.bind(`SELECT "stripeSubscriptionId" FROM "subscription" WHERE "id"=? AND "referenceId"=? AND "stripeCustomerId"=?`), claim, r.Owner, key.CustomerID).Scan(&current); err != nil {
			return err
		}
		if current.Valid && current.String != key.RemoteID {
			return billing.ErrCheckoutReconcile
		}
		id = claim
	}
	if id == "" {
		if c.Deleted || c.Plan == "" {
			return nil
		}
		id = rand.Text()
		if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO "subscription" ("id","plan","referenceId","stripeCustomerId","stripeSubscriptionId","status") VALUES(?,?,?,?,?,?)`), id, c.Plan, r.Owner, key.CustomerID, key.RemoteID, c.Status); err != nil {
			return err
		}
	}
	status := c.Status
	if c.Plan == "" && !c.Deleted && status != "canceled" && status != "incomplete_expired" {
		// The old plan cannot grant entitlements after the provider moves a
		// known subscription to an unconfigured or ambiguous set of prices.
		status = "unmapped"
	}
	update := s.bind(`UPDATE "subscription" SET
		"stripeSubscriptionId"=?, "plan"=COALESCE(?, "plan"), "status"=?,
		"periodStart"=COALESCE(?, "periodStart"), "periodEnd"=COALESCE(?, "periodEnd"),
		"trialStart"=COALESCE(?, "trialStart"), "trialEnd"=COALESCE(?, "trialEnd"),
		"cancelAtPeriodEnd"=?, "cancelAt"=?, "canceledAt"=?, "endedAt"=?,
		"seats"=COALESCE(?, "seats"), "billingInterval"=COALESCE(?, "billingInterval"), "stripeScheduleId"=?
		WHERE "id"=? AND "referenceId"=? AND "stripeCustomerId"=?`)
	_, err := tx.ExecContext(ctx, update,
		key.RemoteID, sql.NullString{String: c.Plan, Valid: c.Plan != ""}, status,
		s.stripeDate(c.PeriodStart), s.stripeDate(c.PeriodEnd), s.stripeDate(c.TrialStart), s.stripeDate(c.TrialEnd),
		c.CancelAtPeriodEnd, s.stripeDate(c.CancelAt), s.stripeDate(c.CanceledAt), s.stripeDate(c.EndedAt),
		sql.NullInt64{Int64: c.Seats, Valid: c.Seats > 0}, sql.NullString{String: c.Interval, Valid: c.Interval != ""}, sql.NullString{String: c.ScheduleID, Valid: c.ScheduleID != ""},
		id, r.Owner, key.CustomerID,
	)
	return err
}

// SettleReconciledCheckout releases a matching reservation after an earlier
// lifecycle event bound its row. Preserve the newer canonical Stripe state.
func (s *Store) SettleReconciledCheckout(ctx context.Context, want billing.CheckoutAttempt, checkoutID, remoteID string) (bool, error) {
	var settled bool
	err := s.billingTransaction(ctx, want.Owner, "", time.Now(), func(tx *sql.Tx) error {
		a, err := s.checkoutAttempt(ctx, tx, want.Owner)
		if errors.Is(err, auth.ErrNotFound) || (err == nil && a.ID != want.ID) {
			settled = true
			return nil
		}
		if err != nil {
			return err
		}
		if a.LocalSubscription != want.LocalSubscription || a.Customer != want.Customer || (a.CheckoutID != "" && a.CheckoutID != checkoutID) {
			return billing.ErrCheckoutReconcile
		}
		if err := s.checkCustomerOwner(ctx, tx, a.Owner, a.Customer); err != nil {
			return err
		}
		var remote sql.NullString
		if err := tx.QueryRowContext(ctx, s.bind(`SELECT "stripeSubscriptionId" FROM "subscription" WHERE "id"=? AND "referenceId"=? AND "stripeCustomerId"=?`), a.LocalSubscription, a.Owner, a.Customer).Scan(&remote); err != nil {
			return err
		}
		if !remote.Valid {
			return nil
		}
		if remoteID != "" && remoteID != remote.String {
			return billing.ErrCheckoutReconcile
		}
		settled = true
		return s.settleBoundSubscription(ctx, tx, a, checkoutID, remote.String)
	})
	return settled, err
}

func (s *Store) settleBoundSubscription(ctx context.Context, tx *sql.Tx, a billing.CheckoutAttempt, checkoutID, remote string) error {
	key := billing.SubscriptionIdentity{RemoteID: remote, CustomerID: a.Customer, LocalID: a.LocalSubscription, Owner: a.Owner}
	if _, _, err := s.subscriptionRevision(ctx, tx, key); err != nil {
		return err
	}
	return s.finishCheckout(ctx, tx, a, checkoutID, true, time.Now())
}
