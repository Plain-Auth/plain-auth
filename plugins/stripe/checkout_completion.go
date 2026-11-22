package stripe

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"

	auth "github.com/Plain-Auth/plain-auth"
	sdk "github.com/stripe/stripe-go/v87"
)

// SubscriptionComplete carries the signed Checkout event, the retrieved provider
// subscription and the local record and plan committed for this delivery.
type SubscriptionComplete struct {
	SubscriptionEvent
	Plan    Plan
	Request *http.Request
}

// CheckoutCompletionStore checks a signed delivery against the original settled
// purchase or a prior receipt for the exact event. Apply must recheck that proof
// under the owner lock and return the local result after commit.
type CheckoutCompletionStore interface {
	SubscriptionLifecycleStore
	ConfirmStripeCheckoutDelivery(context.Context, SubscriptionIdentity) (bool, error)
	ApplyStripeCheckoutDelivery(context.Context, SubscriptionIdentity, SubscriptionRevision, SubscriptionChange) (*Subscription, error)
}

// Each authenticated delivery synchronizes the provider's current subscription.
// Ordinary subscription events retain their existing event-ID deduplication.
type checkoutDelivery struct {
	CheckoutCompletionStore
	local *Subscription
}

func (d *checkoutDelivery) ReadStripeSubscriptionRevision(ctx context.Context, key SubscriptionIdentity) (SubscriptionRevision, error) {
	key.EventID = ""
	return d.CheckoutCompletionStore.ReadStripeSubscriptionRevision(ctx, key)
}

func (d *checkoutDelivery) ApplyStripeSubscriptionChange(ctx context.Context, key SubscriptionIdentity, before SubscriptionRevision, change SubscriptionChange) error {
	var err error
	d.local, err = d.ApplyStripeCheckoutDelivery(ctx, key, before, change)
	return err
}

func (s *subscriptions) observeCheckoutCompletion(c auth.EndpointContext, event sdk.Event) error {
	if event.Data == nil || event.ID == "" {
		return ErrCheckoutReconcile
	}
	var session sdk.CheckoutSession
	if err := json.Unmarshal(event.Data.Raw, &session); err != nil {
		return err
	}
	if session.Mode != sdk.CheckoutSessionModeSubscription || session.Metadata["checkoutAttemptId"] == "" {
		return nil
	}
	if session.Object != "checkout.session" || session.ID == "" || session.ClientReferenceID == "" ||
		session.Customer == nil || session.Customer.ID == "" || session.Subscription == nil || session.Subscription.ID == "" ||
		session.Metadata["subscriptionId"] == "" || session.Livemode != event.Livemode {
		return ErrCheckoutReconcile
	}
	attempt := CheckoutAttempt{
		ID: session.Metadata["checkoutAttemptId"], Owner: session.ClientReferenceID, LocalSubscription: session.Metadata["subscriptionId"],
		Customer: session.Customer.ID, CheckoutID: session.ID, OrganizationID: session.Metadata["organizationId"],
	}
	if attempt.OrganizationID != "" {
		attempt.ActorID = session.Metadata["userId"]
	}
	if !checkoutMatches(attempt, &session) {
		return ErrCheckoutReconcile
	}
	fingerprint, err := updateFingerprint(event.Data.Raw)
	if err != nil {
		return err
	}
	key := SubscriptionIdentity{
		Owner: attempt.Owner, LocalID: attempt.LocalSubscription, CustomerID: attempt.Customer, RemoteID: session.Subscription.ID,
		EventID: event.ID, NoticeType: event.Type, UpdateFingerprint: fingerprint, ConfirmedCheckout: &attempt,
	}
	ctx := c.Request.Context()
	delivery := &checkoutDelivery{CheckoutCompletionStore: c.Store().(CheckoutCompletionStore)}
	confirmed, err := delivery.ConfirmStripeCheckoutDelivery(ctx, key)
	if err != nil || !confirmed {
		return err
	}
	remote, err := s.reconcile(ctx, delivery, key, &sdk.Subscription{Livemode: event.Livemode}, false)
	if err != nil || delivery.local == nil {
		return err
	}
	plan, known := s.plans[delivery.local.Plan]
	if !known {
		return nil
	}
	if plan.FreeTrial != nil && plan.FreeTrial.OnTrialStart != nil && remote.TrialStart != 0 && remote.TrialEnd != 0 {
		ok, err := callSubscriptionHook(c, event, *delivery.local, "trial start", remote, func(p SubscriptionEvent) error {
			return plan.FreeTrial.OnTrialStart(ctx, p.Subscription)
		})
		if err != nil || !ok {
			return err
		}
	}
	if s.onComplete == nil {
		return nil
	}
	_, err = callSubscriptionHook(c, event, *delivery.local, "completion", remote, func(p SubscriptionEvent) error {
		plan.MeteredPriceIDs = slices.Clone(plan.MeteredPriceIDs)
		if plan.FreeTrial != nil {
			trial := *plan.FreeTrial
			plan.FreeTrial = &trial
		}
		return s.onComplete(ctx, SubscriptionComplete{SubscriptionEvent: p, Plan: plan, Request: webhookRequest(c.Request)})
	})
	return err
}
