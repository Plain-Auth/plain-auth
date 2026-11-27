package stripe

import (
	"context"
	"errors"
	"fmt"
	"time"

	sdk "github.com/stripe/stripe-go/v87"
)

var ErrManagedSeatPlanChange = billingError(409, "AUTOMATIC_SEAT_PLAN_CHANGE_UNAVAILABLE", "Plan changes for membership-based subscriptions are unavailable")
var ErrSeatReconciliation = errors.New("stripe: verify automatic seat state before retrying")

// SeatAdjustment is the immutable provider operation shared by all workers.
// Item is persisted before the first POST and is reused on retry.
type SeatAdjustment struct {
	ID, Organization, LocalID, Customer, Subscription, Plan, Price, BasePrice, Proration, Item string
	Revision, Quantity, Started                                                                int64
}

type SeatStore interface {
	SubscriptionLifecycleStore
	DiscoverStripeSeats(ctx context.Context, plan Plan, limit int) error
	DueStripeSeatGroups(ctx context.Context, limit int) ([]string, error)
	ClaimStripeSeats(ctx context.Context, group string) (*SeatAdjustment, error)
	PrepareStripeSeats(ctx context.Context, job SeatAdjustment, item string) (bool, error)
	FinishStripeSeats(ctx context.Context, job SeatAdjustment) error
	RequeueStripeSeats(ctx context.Context, group string) error
}

// SeatWorker processes committed membership changes. Multiple processes can
// share a database. Run it under the service's shutdown context.
type SeatWorker struct {
	store         SeatStore
	subscriptions *subscriptions
}

func NewSeatWorker(store SeatStore, options SubscriptionOptions) (*SeatWorker, error) {
	if store == nil {
		return nil, errors.New("stripe: seat worker requires a store")
	}
	s, err := configureSubscriptions(&options)
	if err != nil {
		return nil, err
	}
	// Loaded plans are read on each pass, and need no organization options:
	// the worker runs no Checkout or callbacks.
	if s.loadPlans != nil {
		return &SeatWorker{store, s}, nil
	}
	for _, p := range s.plans {
		if p.SeatPriceID != "" {
			return &SeatWorker{store, s}, nil
		}
	}
	return nil, errors.New("stripe: seat worker requires a membership-based plan")
}

// Run retries pending adjustments until cancellation. onError receives failures
// without preventing other organizations from being processed.
func (w *SeatWorker) Run(ctx context.Context, interval time.Duration, onError func(error)) error {
	if interval <= 0 {
		return errors.New("stripe: seat worker interval must be positive")
	}
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := w.SyncOnce(ctx, 100); err != nil && onError != nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// SyncOnce handles one pending adjustment per selected organization.
func (w *SeatWorker) SyncOnce(ctx context.Context, limit int) error {
	if limit < 1 || limit > 1000 {
		return errors.New("stripe: seat worker batch size must be 1 through 1000")
	}
	subs := w.subscriptions
	if subs.loadPlans != nil {
		catalog, err := subs.loadCatalog(ctx)
		if err != nil {
			return err
		}
		view := *subs
		view.planCatalog = catalog
		subs = &view
	}
	// A pass with no membership plan does nothing: queued seat work waits
	// until one returns.
	seats := false
	for _, plan := range subs.plans {
		seats = seats || plan.SeatPriceID != ""
	}
	if !seats {
		return nil
	}
	var failures []error
	for _, plan := range subs.plans {
		if plan.SeatPriceID != "" {
			if err := w.store.DiscoverStripeSeats(ctx, plan, limit); err != nil {
				failures = append(failures, err)
			}
		}
	}
	groups, err := w.store.DueStripeSeatGroups(ctx, limit)
	if err != nil {
		return errors.Join(append(failures, err)...)
	}
	for _, group := range groups {
		if err := ctx.Err(); err != nil {
			return err
		}
		scoped := context.WithValue(ctx, organizationScopeKey{}, OrganizationScope{ID: group})
		if err := w.syncGroup(scoped, subs, group); err != nil {
			failures = append(failures, fmt.Errorf("organization %s: %w", group, errors.Join(err, w.store.RequeueStripeSeats(ctx, group))))
		}
	}
	return errors.Join(failures...)
}

func (w *SeatWorker) syncGroup(ctx context.Context, s *subscriptions, group string) error {
	job, err := w.store.ClaimStripeSeats(ctx, group)
	if err != nil || job == nil {
		return err
	}
	plan := s.plans[job.Plan]
	if plan.SeatPriceID == "" || plan.SeatPriceID != job.Price {
		return ErrSeatReconciliation
	}
	if job.BasePrice == "" && plan.PriceID != job.Price && plan.AnnualPriceID != "" && job.Item == "" {
		// A confirmed historical subscription can lack a stored interval. Refresh
		// it from Stripe first. The next poll can prepare a price-bound mutation.
		_, err := s.reconcile(ctx, w.store, SubscriptionIdentity{RemoteID: job.Subscription, CustomerID: job.Customer, Owner: group, LocalID: job.LocalID}, nil, false)
		return err
	}
	basePrice := job.BasePrice
	if basePrice == "" {
		basePrice = job.Price
	} // older single-item operations
	if s.prices[basePrice].plan != plan.Name {
		return ErrSeatReconciliation
	}
	sub, err := s.client.V1Subscriptions.Retrieve(ctx, job.Subscription, nil)
	if err != nil {
		return err
	}
	if sub == nil || sub.ID != job.Subscription || sub.Customer == nil || sub.Customer.ID != job.Customer {
		return ErrSeatReconciliation
	}
	if sub.Status != sdk.SubscriptionStatusActive && sub.Status != sdk.SubscriptionStatusTrialing || sub.Schedule != nil || sub.PendingUpdate != nil || sub.PauseCollection != nil {
		return ErrSeatReconciliation
	}
	_, item := s.membershipItems(sub, plan, basePrice)
	if item == nil || job.Item != "" && job.Item != item.ID {
		return ErrSeatReconciliation
	}
	if job.Item != "" || item.Quantity != job.Quantity {
		deadline := time.Unix(job.Started, 0).Add(23 * time.Hour)
		if time.Now().Before(deadline) {
			current, err := w.store.PrepareStripeSeats(ctx, *job, item.ID)
			if err != nil || !current {
				return err
			}
			job.Item = item.ID
			postCtx, cancel := context.WithDeadline(ctx, deadline)
			params := &sdk.SubscriptionUpdateParams{Items: []*sdk.SubscriptionUpdateItemParams{{ID: sdk.String(item.ID), Quantity: sdk.Int64(job.Quantity)}}, ProrationBehavior: sdk.String(job.Proration)}
			params.SetIdempotencyKey("plainauth-seat-" + job.ID)
			_, err = s.client.V1Subscriptions.Update(postCtx, job.Subscription, params)
			cancel()
			if err != nil {
				return err
			}
		} else if item.Quantity != job.Quantity {
			return ErrSeatReconciliation
		}
	}
	// A webhook may have raced the request. Use the normal revision check
	// before recording the latest provider state or acknowledging the outbox.
	sub, err = s.reconcile(ctx, w.store, SubscriptionIdentity{RemoteID: job.Subscription, CustomerID: job.Customer, Owner: group, LocalID: job.LocalID}, nil, false)
	if err != nil {
		return err
	}
	_, confirmed := s.membershipItems(sub, plan, basePrice)
	if confirmed == nil || confirmed.ID != item.ID || confirmed.Quantity != job.Quantity {
		return ErrSeatReconciliation
	}
	return w.store.FinishStripeSeats(ctx, *job)
}
