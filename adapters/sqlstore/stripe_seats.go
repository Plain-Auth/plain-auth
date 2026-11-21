package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"time"

	billing "github.com/Stonewrit/stonewrit-auth/plugins/stripe"
)

const seatsDue = "stripe-org-seats:due:"
const seatsIdle = "stripe-org-seats:idle:"

type seatState struct {
	Organization, LocalID, Customer, Subscription, Plan, Price, BasePrice, Proration string
	Revision                                                                         int64
	Work                                                                             *billing.SeatAdjustment
	Suspended                                                                        bool
	Due                                                                              bool `json:"-"`
}

func (s *Store) organizationSeatCount(ctx context.Context, tx *sql.Tx, group string) (int64, error) {
	var n int64
	err := tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "member" WHERE "organizationId"=`+s.exactSQLValue("?")), group).Scan(&n)
	return n, err
}

func (s *Store) seatState(ctx context.Context, tx *sql.Tx, group string) (*seatState, error) {
	var raw []byte
	var identifier string
	err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "identifier","value" FROM "verification" WHERE "id"=? AND "identifier" IN (?,?)`), stripeRecordID("seats", group), seatsDue+group, seatsIdle+group).Scan(&identifier, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out seatState
	if err = json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out.Organization != group {
		return nil, billing.ErrSeatReconciliation
	}
	out.Due = identifier == seatsDue+group
	return &out, nil
}

func (s *Store) saveSeats(ctx context.Context, tx *sql.Tx, state *seatState, due, create bool) error {
	key := seatsIdle
	if due {
		key = seatsDue
	}
	key += state.Organization
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	now := s.date(time.Now().UTC())
	id := stripeRecordID("seats", state.Organization)
	if create {
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`), id, key, string(raw), s.date(time.Unix(1<<31-1, 0)), now, now)
	} else {
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE "verification" SET "identifier"=?,"value"=?,"updatedAt"=? WHERE "id"=?`), key, string(raw), now, id)
	}
	return err
}

func (s *Store) dirtyOrganizationSeats(ctx context.Context, tx *sql.Tx, group string) error {
	state, err := s.seatState(ctx, tx, group)
	if err != nil || state == nil {
		return err
	}
	state.Revision++
	return s.saveSeats(ctx, tx, state, !state.Suspended, false)
}

func (s *Store) dirtyDeletedMemberSeats(ctx context.Context, tx *sql.Tx, user string) error {
	rows, err := tx.QueryContext(ctx, s.bind(`SELECT "organizationId" FROM "member" WHERE "userId"=? ORDER BY "organizationId"`), user)
	if err != nil {
		return err
	}
	var groups []string
	for rows.Next() {
		var group string
		if err = rows.Scan(&group); err != nil {
			rows.Close()
			return err
		}
		groups = append(groups, group)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, group := range groups {
		// Serialize with first-time webhook enrollment even if no outbox exists yet.
		if err = s.lockOrganization(ctx, tx, group); err != nil {
			return err
		}
		if err = s.dirtyOrganizationSeats(ctx, tx, group); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) observeOrganizationSeats(ctx context.Context, tx *sql.Tx, group, id string, key billing.SubscriptionIdentity, c billing.SubscriptionChange) error {
	state, err := s.seatState(ctx, tx, group)
	if err != nil {
		return err
	}
	eligible := c.ManagedSeatPrice != "" && (c.Status == "active" || c.Status == "trialing") && !c.Deleted
	if !eligible {
		if state == nil || state.LocalID != id || !c.Deleted && (c.Status == "active" || c.Status == "trialing") && state.Plan == c.Plan {
			return nil
		}
		if c.Deleted || c.Status == "canceled" || c.Status == "incomplete_expired" || c.Plan != "" && c.Plan != state.Plan {
			// An old job is always bound to its original subscription and item.
			_, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=?`), stripeRecordID("seats", group))
			return err
		}
		// Preserve the idempotency key across a temporary billing interruption.
		state.Suspended = true
		return s.saveSeats(ctx, tx, state, false, false)
	}
	if state != nil && state.LocalID != id {
		return billing.ErrSeatReconciliation
	}
	create := state == nil
	if create {
		state = &seatState{Organization: group, LocalID: id, Customer: key.CustomerID, Subscription: key.RemoteID, Revision: 1}
	}
	if state.Customer != key.CustomerID || state.Subscription != key.RemoteID {
		return billing.ErrSeatReconciliation
	}
	oldBase := state.BasePrice
	if oldBase == "" {
		oldBase = state.Price
	}
	if state.Work != nil && (state.Price != c.ManagedSeatPrice || oldBase != c.ManagedBasePrice) {
		return billing.ErrSeatReconciliation
	}
	state.Suspended = false
	state.Plan, state.Price, state.BasePrice, state.Proration = c.Plan, c.ManagedSeatPrice, c.ManagedBasePrice, c.SeatProration
	count, err := s.organizationSeatCount(ctx, tx, group)
	if err != nil {
		return err
	}
	return s.saveSeats(ctx, tx, state, state.Work != nil || count != c.Seats, create)
}

// DiscoverStripeSeats enrolls already-confirmed organization subscriptions when
// an operator enables seat billing for an existing price. Membership and
// webhook writers use the same organization lock.
func (s *Store) DiscoverStripeSeats(ctx context.Context, plan billing.Plan, limit int) error {
	concat := `? || o."id"`
	if s.dialect == "mysql" {
		concat = `CONCAT(?,o."id")`
	}
	fields := ` FROM "subscription" b JOIN "organization" o ON o."id"=` + s.exactSQLValue(`b."referenceId"`) + ` AND o."stripeCustomerId"=` + s.exactSQLValue(`b."stripeCustomerId"`) + `
		WHERE b."status" IN ('active','trialing') AND b."plan"=? AND b."stripeSubscriptionId" IS NOT NULL`
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT DISTINCT o."id"`+fields+`
		AND NOT EXISTS(SELECT 1 FROM "verification" v WHERE v."identifier" IN (`+concat+`,`+concat+`))
		ORDER BY o."id" LIMIT ?`), plan.Name, seatsDue, seatsIdle, limit)
	if err != nil {
		return err
	}
	var groups []string
	for rows.Next() {
		var group string
		if err = rows.Scan(&group); err != nil {
			rows.Close()
			return err
		}
		groups = append(groups, group)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, group := range groups {
		if err := s.enrollSeatPlan(ctx, group, plan, fields); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) enrollSeatPlan(ctx context.Context, group string, plan billing.Plan, fields string) error {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.lockOrganization(ctx, tx, group); err != nil {
		return err
	}
	state, err := s.seatState(ctx, tx, group)
	if err != nil || state != nil {
		return err
	}
	state = &seatState{Organization: group, Plan: plan.Name, Price: plan.SeatPriceID, BasePrice: plan.PriceID, Proration: plan.ProrationBehavior, Revision: 1}
	var ref string
	err = tx.QueryRowContext(ctx, s.bind(`SELECT b."id",b."referenceId",b."stripeCustomerId",b."stripeSubscriptionId"`+fields+` AND o."id"=? ORDER BY b."id" LIMIT 1`), plan.Name, group).Scan(&state.LocalID, &ref, &state.Customer, &state.Subscription)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if ref != group {
		return billing.ErrSeatReconciliation
	}
	// The worker independently checks uniqueness, customer ownership, the live
	// licensed item and its price before preparing any provider mutation.
	if err := s.saveSeats(ctx, tx, state, true, true); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DueStripeSeatGroups(ctx context.Context, limit int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT "value" FROM "verification" WHERE "identifier" LIKE ? ORDER BY "updatedAt","id" LIMIT ?`), seatsDue+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var groups []string
	for rows.Next() {
		var raw []byte
		var state seatState
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &state); err != nil {
			return nil, err
		}
		groups = append(groups, state.Organization)
	}
	return groups, rows.Err()
}

func (s *Store) currentSeatTarget(ctx context.Context, tx *sql.Tx, state *seatState) error {
	key := billing.SubscriptionIdentity{Owner: state.Organization, LocalID: state.LocalID, CustomerID: state.Customer, RemoteID: state.Subscription}
	revision, cursor, err := s.subscriptionRevision(ctx, tx, key)
	if err != nil {
		return err
	}
	if revision.Skip || cursor.Terminal != "" {
		return billing.ErrSeatReconciliation
	}
	var total, match int
	exact := s.exactSQLValue("?")
	err = tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*),COALESCE(SUM(CASE WHEN "id"=`+exact+` AND "plan"=`+exact+` THEN 1 ELSE 0 END),0)
	FROM "subscription" WHERE "referenceId"=`+exact+` AND "status" IN ('active','trialing')`), state.LocalID, state.Plan, state.Organization).Scan(&total, &match)
	if err == nil && (total != 1 || match != 1) {
		return billing.ErrSeatReconciliation
	}
	return err
}

func (s *Store) ClaimStripeSeats(ctx context.Context, group string) (*billing.SeatAdjustment, error) {
	var result *billing.SeatAdjustment
	err := s.billingTransaction(ctx, group, "", time.Now(), func(tx *sql.Tx) error {
		state, err := s.seatState(ctx, tx, group)
		if err != nil || state == nil || state.Suspended || !state.Due {
			return err
		}
		if err = s.currentSeatTarget(ctx, tx, state); err != nil {
			return err
		}
		if state.Work == nil || state.Work.Item == "" && time.Since(time.Unix(state.Work.Started, 0)) >= 23*time.Hour {
			count, err := s.organizationSeatCount(ctx, tx, group)
			if err != nil {
				return err
			}
			if count < 0 || count > math.MaxInt32 {
				return billing.ErrInvalidSeatQuantity
			}
			state.Work = &billing.SeatAdjustment{ID: rand.Text(), Organization: group, LocalID: state.LocalID, Customer: state.Customer, Subscription: state.Subscription, Plan: state.Plan, Price: state.Price, BasePrice: state.BasePrice, Proration: state.Proration, Revision: state.Revision, Quantity: count, Started: time.Now().Unix()}
		}
		result = state.Work
		return s.saveSeats(ctx, tx, state, true, false)
	})
	return result, err
}

// RequeueStripeSeats places failures behind every organization already waiting,
// even if timestamps are equal or worker clocks differ. Fresh cron processes
// read the same order; the immutable provider operation is left in place.
func (s *Store) RequeueStripeSeats(ctx context.Context, group string) error {
	var last time.Time
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT "updatedAt" FROM "verification" WHERE "identifier" LIKE ? ORDER BY "updatedAt" DESC LIMIT 1`), seatsDue+"%").Scan(&last)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	next := time.Now().UTC()
	if lower := last.Add(time.Millisecond); lower.After(next) {
		next = lower
	}
	_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "verification" SET "updatedAt"=? WHERE "id"=? AND "identifier"=?`), s.date(next), stripeRecordID("seats", group), seatsDue+group)
	return err
}

func (s *Store) PrepareStripeSeats(ctx context.Context, job billing.SeatAdjustment, item string) (bool, error) {
	current := false
	err := s.billingTransaction(ctx, job.Organization, "", time.Now(), func(tx *sql.Tx) error {
		state, err := s.seatState(ctx, tx, job.Organization)
		if err != nil || state == nil || state.Suspended || state.Work == nil || state.Work.ID != job.ID {
			return err
		}
		if err = s.currentSeatTarget(ctx, tx, state); err != nil {
			return err
		}
		if item == "" || state.Work.Item != "" && state.Work.Item != item {
			return billing.ErrSeatReconciliation
		}
		state.Work.Item = item
		current = true
		return s.saveSeats(ctx, tx, state, true, false)
	})
	return current, err
}

func (s *Store) FinishStripeSeats(ctx context.Context, job billing.SeatAdjustment) error {
	return s.billingTransaction(ctx, job.Organization, "", time.Now(), func(tx *sql.Tx) error {
		state, err := s.seatState(ctx, tx, job.Organization)
		if err != nil || state == nil || state.Suspended || state.Work == nil || state.Work.ID != job.ID {
			return err
		}
		// A worker which only observed a no-op cannot finish another worker's
		// already prepared (and possibly in-flight) external mutation.
		if state.Work.Item != job.Item {
			return nil
		}
		if err = s.currentSeatTarget(ctx, tx, state); err != nil {
			return err
		}
		count, err := s.organizationSeatCount(ctx, tx, job.Organization)
		if err != nil {
			return err
		}
		state.Work = nil
		return s.saveSeats(ctx, tx, state, state.Revision != job.Revision || count != job.Quantity, false)
	})
}
