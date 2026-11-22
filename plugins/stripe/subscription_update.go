package stripe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	auth "github.com/Stonewrit/stonewrit-auth"
	sdk "github.com/stripe/stripe-go/v87"
)

// SubscriptionEvent contains the signed provider snapshot and the local record
// committed for its event. They can differ when Stripe delivers an older update.
type SubscriptionEvent struct {
	Event              sdk.Event
	StripeSubscription *sdk.Subscription
	Subscription       Subscription
}

type SubscriptionUpdate = SubscriptionEvent

type SubscriptionCreated struct {
	SubscriptionEvent
	Plan Plan
}

type SubscriptionCancellation struct {
	SubscriptionEvent
	CancellationDetails *sdk.SubscriptionCancellationDetails
}

type SubscriptionNotification struct {
	Subscription       Subscription
	Transition, Update bool
	CreatedPlan        *Plan
	TrialStatus        string
}

// SubscriptionNotificationStore returns the committed local snapshot. Transition
// is true for at most one reader of a creation or cancellation transition.
type SubscriptionNotificationStore interface {
	SubscriptionUpdateStore
	ReadStripeSubscriptionNotification(context.Context, SubscriptionIdentity) (*SubscriptionNotification, error)
}

// SubscriptionUpdateStore saves the local result atomically with the event in
// ApplyStripeSubscriptionChange when UpdateFingerprint is set. Reading it must
// validate the event, customer and subscription binding, including on a retry.
type SubscriptionUpdateStore interface {
	SubscriptionLifecycleStore
	ReadStripeSubscriptionUpdate(context.Context, SubscriptionIdentity) (*Subscription, error)
}

func updateFingerprint(raw json.RawMessage) (string, error) {
	// Equivalent signed JSON may arrive with different spacing or member order.
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value map[string]any
	if err := d.Decode(&value); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func (s *subscriptions) selectSubscriptionHooks(key *SubscriptionIdentity, kind sdk.EventType, sub *sdk.Subscription, organization bool) bool {
	switch kind {
	case sdk.EventTypeCustomerSubscriptionCreated:
		if s.onCreated == nil {
			return false
		}
	case sdk.EventTypeCustomerSubscriptionDeleted:
		if s.onDeleted == nil {
			return false
		}
	case sdk.EventTypeCustomerSubscriptionUpdated:
		key.NotifyUpdate = s.onUpdate != nil
		key.NotifyCancellation = s.onCancel != nil && sub.Status == sdk.SubscriptionStatusActive && (sub.CancelAtPeriodEnd || sub.CancelAt != 0)
		if s.observeTrialTransitions && (sub.Status == sdk.SubscriptionStatusActive || sub.Status == sdk.SubscriptionStatusIncompleteExpired) {
			plan := s.plans[s.subscriptionChange(sub, false, organization).Plan]
			if trialHook(plan, string(sub.Status)) != nil {
				key.TrialPlan, key.TrialStatus = plan.Name, string(sub.Status)
			}
		}
		if !key.NotifyUpdate && !key.NotifyCancellation && key.TrialStatus == "" {
			return false
		}
	}
	key.NoticeType = kind
	return true
}

func (s *subscriptions) dispatchSubscriptionHooks(c auth.EndpointContext, store SubscriptionLifecycleStore, key SubscriptionIdentity, event sdk.Event) error {
	ctx := c.Request.Context()
	if event.Type == sdk.EventTypeCustomerSubscriptionUpdated && !key.NotifyCancellation && key.TrialStatus == "" {
		row, err := store.(SubscriptionUpdateStore).ReadStripeSubscriptionUpdate(ctx, key)
		if err != nil || row == nil {
			return err
		}
		_, err = callSubscriptionHook(c, event, *row, "update", nil, func(p SubscriptionEvent) error { return s.onUpdate(ctx, p) })
		return err
	}
	notice, err := store.(SubscriptionNotificationStore).ReadStripeSubscriptionNotification(ctx, key)
	if err != nil || notice == nil {
		return err
	}
	switch event.Type {
	case sdk.EventTypeCustomerSubscriptionCreated:
		if notice.Transition {
			if notice.CreatedPlan == nil {
				return ErrCheckoutReconcile
			}
			_, err = callSubscriptionHook(c, event, notice.Subscription, "creation", nil, func(p SubscriptionEvent) error { return s.onCreated(ctx, SubscriptionCreated{p, *notice.CreatedPlan}) })
		}
	case sdk.EventTypeCustomerSubscriptionDeleted:
		_, err = callSubscriptionHook(c, event, notice.Subscription, "deletion", nil, func(p SubscriptionEvent) error { return s.onDeleted(ctx, p) })
	case sdk.EventTypeCustomerSubscriptionUpdated:
		if notice.Transition && s.onCancel != nil {
			ok, err := callSubscriptionHook(c, event, notice.Subscription, "cancellation", nil, func(p SubscriptionEvent) error {
				return s.onCancel(ctx, SubscriptionCancellation{p, p.StripeSubscription.CancellationDetails})
			})
			if err != nil || !ok {
				return err
			}
		}
		if notice.Update && s.onUpdate != nil {
			ok, err := callSubscriptionHook(c, event, notice.Subscription, "update", nil, func(p SubscriptionEvent) error { return s.onUpdate(ctx, p) })
			if err != nil || !ok {
				return err
			}
		}
		if hook := trialHook(s.plans[notice.Subscription.Plan], notice.TrialStatus); hook != nil {
			_, err = callSubscriptionHook(c, event, notice.Subscription, "trial transition", nil, func(p SubscriptionEvent) error {
				return hook(ctx, TrialTransition{Subscription: p.Subscription, Request: webhookRequest(c.Request)})
			})
		}
	}
	return err
}

func callSubscriptionHook(c auth.EndpointContext, event sdk.Event, row Subscription, name string, provider *sdk.Subscription, hook func(SubscriptionEvent) error) (ok bool, err error) {
	// Keep the signed event and pointer fields independent of other host hooks.
	source := SubscriptionEvent{Event: event, Subscription: row, StripeSubscription: provider}
	raw, err := json.Marshal(source)
	if err != nil {
		return false, err
	}
	var payload SubscriptionEvent
	if err := json.Unmarshal(raw, &payload); err != nil {
		return false, err
	}
	if payload.StripeSubscription == nil {
		if err := json.Unmarshal(payload.Event.Data.Raw, &payload.StripeSubscription); err != nil {
			return false, err
		}
	}
	defer func() {
		if recover() != nil || !ok {
			c.Auth.Logger().ErrorContext(c.Request.Context(), "Stripe subscription "+name+" callback failed", "event_id", event.ID)
		}
	}()
	return hook(payload) == nil, nil
}
