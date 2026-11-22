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

// SubscriptionUpdate contains the signed provider snapshot and the local record
// committed for its event. They can differ when Stripe delivers an older update.
type SubscriptionUpdate struct {
	Event              sdk.Event
	StripeSubscription *sdk.Subscription
	Subscription       Subscription
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

func (s *subscriptions) notifySubscriptionUpdate(c auth.EndpointContext, event sdk.Event, provider *sdk.Subscription, row Subscription) error {
	// Give each host hook its own event. SDK envelopes contain maps and pointers.
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	var copied sdk.Event
	if err := json.Unmarshal(raw, &copied); err != nil {
		return err
	}
	ctx := c.Request.Context()
	failed := true
	defer func() {
		if recover() != nil || failed {
			// Host errors and panics can contain customer or payment details.
			c.Auth.Logger().ErrorContext(ctx, "Stripe subscription update callback failed", "event_id", event.ID)
		}
	}()
	failed = s.onUpdate(ctx, SubscriptionUpdate{Event: copied, StripeSubscription: provider, Subscription: row}) != nil
	return nil
}
