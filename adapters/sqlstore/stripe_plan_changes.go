package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
)

// A direct plan change is one verification row per subscription, owned by
// the billing reference, like a scheduled change.
func (s *Store) planChangeRecord(ctx context.Context, tx *sql.Tx, owner, remote string) (billing.PlanChange, error) {
	var record billing.PlanChange
	var data []byte
	err := tx.QueryRowContext(ctx, s.bind(`SELECT "value" FROM "verification" WHERE "id"=? AND "identifier"=?`), stripeRecordID("plan-change", remote), stripeOwnerKey(ctx, "sync", owner)).Scan(&data)
	if err != nil {
		return record, err
	}
	err = json.Unmarshal(data, &record)
	if err == nil && (record.Owner != owner || record.Subscription != remote || record.ID == "") {
		return record, billing.ErrCheckoutReconcile
	}
	return record, err
}

// planChangeOwner requires the local row to still hold the plan the change
// was computed from, with no cancellation or schedule pending.
func (s *Store) planChangeOwner(ctx context.Context, tx *sql.Tx, c billing.PlanChange) error {
	if err := s.checkCustomerOwner(ctx, tx, c.Owner, c.Customer); err != nil {
		return err
	}
	var match, count int
	const query = `SELECT COUNT(*), COALESCE(SUM(CASE
		WHEN "id"=? AND "referenceId"=? AND "stripeCustomerId"=? AND "status" IN ('active','trialing')
		AND "plan"=? AND "billingInterval"=? AND "seats"=? AND "cancelAt" IS NULL AND COALESCE("cancelAtPeriodEnd",?)=?
		AND "stripeScheduleId" IS NULL
		THEN 1 ELSE 0 END),0) FROM "subscription" WHERE "stripeSubscriptionId"=?`
	err := tx.QueryRowContext(ctx, s.bind(query), c.LocalID, c.Owner, c.Customer, c.CurrentPlan, c.CurrentInterval, c.CurrentSeats, false, false, c.Subscription).Scan(&count, &match)
	if err == nil && (count != 1 || match != 1) {
		return billing.ErrCheckoutReconcile
	}
	return err
}

// ReserveStripePlanChange stores a direct change under the owner lock
// before it is sent, so every server retrying it shares one idempotency key
// and a different change waits until the first is settled or stale.
func (s *Store) ReserveStripePlanChange(ctx context.Context, token string, want billing.PlanChange, now time.Time) (billing.PlanChange, error) {
	var result billing.PlanChange
	if token == "" {
		return result, billing.ErrCheckoutSession
	}
	err := s.billingTransaction(ctx, want.Owner, token, now, func(tx *sql.Tx) error {
		if err := s.planChangeOwner(ctx, tx, want); err != nil {
			return err
		}
		schedule, err := s.scheduleRecord(ctx, tx, want.Owner, want.Subscription)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		// A schedule reservation not yet bound may still create a schedule
		// under its key, which Stripe honors for a day. A bound one's
		// schedule is refused by the caller while Stripe shows it attached,
		// and is otherwise released.
		if err == nil && schedule.Schedule == "" && schedule.End > now.Unix() && now.Before(time.Unix(schedule.Created, 0).Add(24*time.Hour)) {
			return billing.ErrPendingSchedule
		}
		key, identifier := stripeRecordID("plan-change", want.Subscription), stripeOwnerKey(ctx, "sync", want.Owner)
		record, err := s.planChangeRecord(ctx, tx, want.Owner, want.Subscription)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			// Stripe keeps an idempotent result for 24 hours, so an older key
			// is never reused.
			if record.SameRequest(want) && now.Before(time.Unix(record.Created, 0).Add(billing.PlanChangeReuse)) {
				record.Started = now.Unix()
				data, err := json.Marshal(record)
				if err != nil {
					return err
				}
				_, err = tx.ExecContext(ctx, s.bind(`UPDATE "verification" SET "value"=?,"updatedAt"=? WHERE "id"=? AND "identifier"=?`), string(data), s.date(now), key, identifier)
				result = record
				return err
			}
			if now.Before(time.Unix(record.Started, 0).Add(billing.PlanChangeHold)) {
				return billing.ErrPendingSchedule
			}
			if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=?`), key, identifier); err != nil {
				return err
			}
		}
		want.ID, want.Created, want.Started = rand.Text(), now.Unix(), now.Unix()
		data, err := json.Marshal(want)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`),
			key, identifier, string(data), s.date(now.Add(24*time.Hour)), s.date(now), s.date(now))
		result = want
		return err
	})
	return result, err
}

// ReleaseStripePlanChange removes the stored change for the target once
// Stripe holds it or refused it.
func (s *Store) ReleaseStripePlanChange(ctx context.Context, token string, target billing.PlanChange, now time.Time) (bool, error) {
	if token == "" {
		return false, billing.ErrCheckoutSession
	}
	var released bool
	err := s.billingTransaction(ctx, target.Owner, token, now, func(tx *sql.Tx) error {
		record, err := s.planChangeRecord(ctx, tx, target.Owner, target.Subscription)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if !record.Targets(target) {
			return nil
		}
		_, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=?`), stripeRecordID("plan-change", target.Subscription), stripeOwnerKey(ctx, "sync", target.Owner))
		released = err == nil
		return err
	})
	return released, err
}

// openPlanChange reports a direct change sent within PlanChangeHold, which
// a new schedule must wait for.
func (s *Store) openPlanChange(ctx context.Context, tx *sql.Tx, owner, remote string, now time.Time) (bool, error) {
	record, err := s.planChangeRecord(ctx, tx, owner, remote)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return now.Before(time.Unix(record.Started, 0).Add(billing.PlanChangeHold)), nil
}
