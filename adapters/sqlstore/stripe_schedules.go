package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	billing "github.com/Stonewrit/stonewrit-auth/plugins/stripe"
)

func (s *Store) scheduleRecord(ctx context.Context, tx *sql.Tx, owner, remote string) (billing.ScheduleChange, error) {
	var record billing.ScheduleChange
	var data []byte
	err := tx.QueryRowContext(ctx, s.bind(`SELECT "value" FROM "verification" WHERE "id"=? AND "identifier"=?`), stripeRecordID("schedule-change", remote), stripeOwnerKey(ctx, "sync", owner)).Scan(&data)
	if err != nil {
		return record, err
	}
	err = json.Unmarshal(data, &record)
	if err == nil && (record.Owner != owner || record.Subscription != remote || record.ID == "") {
		return record, billing.ErrCheckoutReconcile
	}
	return record, err
}

// The account lock and the unique receipt serialize competing destinations;
// Stripe operations run after the SQL transaction commits.
func (s *Store) ReserveStripeSchedule(ctx context.Context, token string, want billing.ScheduleChange, attached string, now time.Time) (billing.ScheduleChange, error) {
	var result billing.ScheduleChange
	if token == "" {
		return result, billing.ErrCheckoutSession
	}
	err := s.billingTransaction(ctx, want.Owner, token, now, func(tx *sql.Tx) error {
		if err := s.scheduleOwner(ctx, tx, want, attached); err != nil {
			return err
		}
		record, err := s.scheduleRecord(ctx, tx, want.Owner, want.Subscription)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		key := stripeRecordID("schedule-change", want.Subscription)
		if err == nil && record.End <= now.Unix() && attached == "" {
			if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=?`), key); err != nil {
				return err
			}
			record = billing.ScheduleChange{}
		}
		if record.ID != "" {
			if record.LocalID != want.LocalID || record.Customer != want.Customer {
				return billing.ErrCheckoutReconcile
			}
			// A release can succeed at Stripe before the application receives
			// its response. Only provider proof of that release retires this key.
			if attached == "" && record.Schedule != "" {
				result = record
				return nil
			}
			if record.Item != want.Item || record.Current != want.Current || record.Target != want.Target ||
				record.Start != want.Start || record.End != want.End || (attached != "" && record.Schedule != "" && attached != record.Schedule) {
				return billing.ErrPendingSchedule
			}
			// Stripe only promises to retain idempotency results for 24 hours.
			if record.Schedule == "" && now.Sub(time.Unix(record.Created, 0)) >= 23*time.Hour {
				return billing.ErrCheckoutReconcile
			}
			result = record
			return nil
		}
		if attached != "" {
			return billing.ErrPendingSchedule
		}
		want.ID, want.Created = rand.Text(), now.Unix()
		data, err := json.Marshal(want)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`),
			key, stripeOwnerKey(ctx, "sync", want.Owner), string(data), s.date(time.Unix(want.End, 0).Add(24*time.Hour)), s.date(now), s.date(now))
		result = want
		return err
	})
	return result, err
}

func (s *Store) scheduleOwner(ctx context.Context, tx *sql.Tx, a billing.ScheduleChange, schedule string) error {
	if err := s.checkCustomerOwner(ctx, tx, a.Owner, a.Customer); err != nil {
		return err
	}
	var match, count int
	const query = `SELECT COUNT(*), COALESCE(SUM(CASE
		WHEN "id"=? AND "referenceId"=? AND "stripeCustomerId"=? AND "status"='active'
		AND "plan"=? AND "billingInterval"=? AND "seats"=1 AND "periodStart"=? AND "periodEnd"=?
		AND "cancelAt" IS NULL AND COALESCE("cancelAtPeriodEnd",?)=?
		AND ("stripeScheduleId" IS NULL OR "stripeScheduleId"=?)
		THEN 1 ELSE 0 END),0) FROM "subscription" WHERE "stripeSubscriptionId"=?`
	err := tx.QueryRowContext(ctx, s.bind(query), a.LocalID, a.Owner, a.Customer, a.CurrentPlan, a.CurrentInterval,
		s.date(time.Unix(a.Start, 0)), s.date(time.Unix(a.End, 0)), false, false, schedule, a.Subscription).Scan(&count, &match)
	if err == nil && (count != 1 || match != 1) {
		return billing.ErrCheckoutReconcile
	}
	return err
}

func (s *Store) BindStripeSchedule(ctx context.Context, token string, a billing.ScheduleChange, schedule string, now time.Time) error {
	if token == "" {
		return billing.ErrCheckoutSession
	}
	return s.billingTransaction(ctx, a.Owner, token, now, func(tx *sql.Tx) error {
		if err := s.scheduleOwner(ctx, tx, a, schedule); err != nil {
			return err
		}
		record, err := s.scheduleRecord(ctx, tx, a.Owner, a.Subscription)
		if errors.Is(err, sql.ErrNoRows) {
			return billing.ErrCheckoutReconcile
		}
		if err != nil {
			return err
		}
		if schedule == "" || record.ID != a.ID || (record.Schedule != "" && record.Schedule != schedule) || now.Unix() >= record.End {
			return billing.ErrCheckoutReconcile
		}
		if record.Schedule == schedule {
			return nil
		}
		record.Schedule = schedule
		data, err := json.Marshal(record)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE "verification" SET "value"=?,"updatedAt"=? WHERE "id"=?`), string(data), s.date(now), stripeRecordID("schedule-change", a.Subscription))
		return err
	})
}

func (s *Store) ForgetStripeSchedule(ctx context.Context, owner, token, remote, schedule string, now time.Time) error {
	if token == "" {
		return billing.ErrCheckoutSession
	}
	return s.billingTransaction(ctx, owner, token, now, func(tx *sql.Tx) error {
		record, err := s.scheduleRecord(ctx, tx, owner, remote)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if schedule == "" || schedule != record.Schedule {
			return nil
		}
		_, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=?`), stripeRecordID("schedule-change", remote), stripeOwnerKey(ctx, "sync", owner))
		return err
	})
}
