package stripe

import (
	"context"
	"encoding/json"
	"errors"

	auth "github.com/Stonewrit/stonewrit-auth"
	sdk "github.com/stripe/stripe-go/v87"
)

// SubscriptionIdentity identifies a provider resource and, for browser operations,
// the exact owner and local row authorized by the host.
type SubscriptionIdentity struct {
	RemoteID, CustomerID, Owner, LocalID string
	EventID                              string
	// Purchase links an immutable Checkout receipt to its original reservation.
	Purchase *CheckoutPurchase `json:"-"`
	// SessionToken accompanies a browser-authorized synchronization and is never persisted.
	SessionToken string `json:"-"`
}

// SubscriptionRevision records the mapping and version before a Stripe read.
type SubscriptionRevision struct {
	Version, Owner, LocalID string
	Skip                    bool
}

// SubscriptionChange describes a current Stripe subscription or signed deletion.
type SubscriptionChange struct {
	Plan, Interval, Status, ScheduleID                                                 string
	Metadata                                                                           map[string]string
	Seats, PeriodStart, PeriodEnd, TrialStart, TrialEnd, CancelAt, CanceledAt, EndedAt int64
	CancelAtPeriodEnd, Deleted                                                         bool
}

// SubscriptionLifecycleStore adds webhook reconciliation to a checkout store.
// A changed revision asks the caller to retrieve Stripe's current state again.
type SubscriptionLifecycleStore interface {
	ReadStripeSubscriptionRevision(context.Context, SubscriptionIdentity) (SubscriptionRevision, error)
	ApplyStripeSubscriptionChange(context.Context, SubscriptionIdentity, SubscriptionRevision, SubscriptionChange) error
	SettleReconciledCheckout(context.Context, CheckoutAttempt, string, string) (bool, error)
}

var ErrStripeRevisionChanged = errors.New("stripe: subscription changed while reading provider state")

func (s *subscriptions) handleSubscriptionEvent(c auth.EndpointContext, event sdk.Event) error {
	switch event.Type {
	case sdk.EventTypeCustomerSubscriptionCreated, sdk.EventTypeCustomerSubscriptionUpdated, sdk.EventTypeCustomerSubscriptionDeleted:
	default:
		return nil
	}
	store, ok := c.Store().(SubscriptionLifecycleStore)
	if !ok || event.Account != "" || event.Context != "" {
		return nil
	}
	if event.Data == nil || event.ID == "" {
		return errors.New("stripe: invalid subscription event")
	}
	var sub sdk.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
		return err
	}
	if sub.Object != "subscription" || sub.ID == "" || sub.Customer == nil || sub.Customer.ID == "" || sub.Livemode != event.Livemode {
		return ErrCheckoutReconcile
	}
	deleted := event.Type == sdk.EventTypeCustomerSubscriptionDeleted
	key := SubscriptionIdentity{RemoteID: sub.ID, CustomerID: sub.Customer.ID, EventID: event.ID}
	_, err := s.reconcile(c.Request.Context(), store, key, &sub, deleted)
	return err
}

// refreshManagedSubscription synchronizes only the account-bound row selected
// by the management endpoint. It propagates Stripe's resource_missing error.
func (s *subscriptions) refreshManagedSubscription(c auth.EndpointContext, local Subscription, token string) (*sdk.Subscription, error) {
	if local.CustomerID == nil || local.SubscriptionID == nil || local.ID == "" || local.ReferenceID == "" {
		return nil, ErrCheckoutReconcile
	}
	key := SubscriptionIdentity{RemoteID: *local.SubscriptionID, CustomerID: *local.CustomerID, Owner: local.ReferenceID, LocalID: local.ID, SessionToken: token}
	store, ok := c.Store().(SubscriptionLifecycleStore)
	if !ok {
		return nil, errors.New("stripe: store does not support subscription reconciliation")
	}
	return s.reconcile(c.Request.Context(), store, key, nil, false)
}

var errCheckoutAlreadyBound = errors.New("stripe: a concurrent event already bound this checkout")

func (s *subscriptions) reconcile(ctx context.Context, store SubscriptionLifecycleStore, key SubscriptionIdentity, eventObject *sdk.Subscription, deleted bool) (*sdk.Subscription, error) {
	for range 4 {
		before, err := store.ReadStripeSubscriptionRevision(ctx, key)
		if err != nil || before.Skip {
			return nil, err
		}
		if purchase := key.Purchase; purchase != nil && before.LocalID != "" && key.EventID == "" {
			if before.Owner != purchase.Attempt.Owner || before.LocalID != purchase.Attempt.LocalSubscription {
				return nil, ErrCheckoutReconcile
			}
			// The matching subscription is already synchronized. A late Checkout
			// return settles the reservation without overwriting webhook state.
			return nil, errCheckoutAlreadyBound
		}
		sub := eventObject
		if !deleted {
			sub, err = s.client.V1Subscriptions.Retrieve(ctx, key.RemoteID, nil)
			if err != nil {
				return nil, err
			}
		}
		if sub == nil || sub.ID != key.RemoteID || sub.Customer == nil || sub.Customer.ID != key.CustomerID || (eventObject != nil && sub.Livemode != eventObject.Livemode) {
			return nil, ErrCheckoutReconcile
		}
		if !deleted && before.LocalID == "" && key.Purchase == nil {
			key.Purchase, err = s.purchaseForSubscription(ctx, store, before.Owner, sub, eventObject)
			if err != nil {
				return nil, err
			}
		}
		change := s.subscriptionChange(sub, deleted)
		if purchase := key.Purchase; purchase != nil {
			a := purchase.Attempt
			if before.Owner != a.Owner || before.LocalID != "" && before.LocalID != a.LocalSubscription || sub.Livemode != purchase.Live {
				return nil, ErrCheckoutReconcile
			}
			change.Metadata, err = purchase.claims(sub.Metadata)
			if err != nil {
				return nil, err
			}
		}
		if change.Status == "" {
			return nil, ErrCheckoutReconcile
		}
		err = store.ApplyStripeSubscriptionChange(ctx, key, before, change)
		if !errors.Is(err, ErrStripeRevisionChanged) {
			return sub, err
		}
	}
	return nil, ErrStripeRevisionChanged
}

func (s *subscriptions) subscriptionChange(sub *sdk.Subscription, deleted bool) SubscriptionChange {
	change := SubscriptionChange{Deleted: deleted, Status: string(sub.Status), Metadata: sub.Metadata, TrialStart: sub.TrialStart, TrialEnd: sub.TrialEnd,
		CancelAtPeriodEnd: sub.CancelAtPeriodEnd, CancelAt: sub.CancelAt, CanceledAt: sub.CanceledAt, EndedAt: sub.EndedAt}
	if deleted {
		change.Status = "canceled"
	} else if sub.Schedule != nil {
		change.ScheduleID = sub.Schedule.ID
	}
	if sub.Items == nil || len(sub.Items.Data) != 1 || sub.Items.HasMore {
		return change
	}
	item := sub.Items.Data[0]
	if item == nil || item.Price == nil || item.Quantity <= 0 {
		return change
	}
	change.PeriodStart, change.PeriodEnd, change.Seats = item.CurrentPeriodStart, item.CurrentPeriodEnd, item.Quantity
	if price, ok := s.prices[item.Price.ID]; ok && (item.Price.Recurring == nil || string(item.Price.Recurring.Interval) == price.interval) {
		change.Plan, change.Interval = price.plan, price.interval
	}
	return change
}
