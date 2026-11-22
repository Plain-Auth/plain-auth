package stripe

import (
	"context"
	"errors"

	auth "github.com/Stonewrit/stonewrit-auth"
	sdk "github.com/stripe/stripe-go/v87"
)

// CheckoutPurchase identifies the reserved line read from the signed or
// SDK-retrieved Checkout Session. The subscription itself may already have changed.
type CheckoutPurchase struct {
	CheckoutID, RemoteID, Price, SeatPrice string
	Quantity                               int64
	Live                                   bool
	Attempt                                CheckoutAttempt
}

func (s *subscriptions) checkoutPurchase(ctx context.Context, a CheckoutAttempt, id, remote string, live bool, session *sdk.CheckoutSession) (*CheckoutPurchase, error) {
	if id == "" || a.CheckoutID != "" && a.CheckoutID != id {
		return nil, ErrCheckoutReconcile
	}
	// A signed event can include price IDs without the recurring details.
	// Retrieve the expanded receipt before deciding its billing mode.
	if session == nil || session.LineItems == nil || (a.Metered || len(a.MeteredPriceIDs) > 0) && !a.matchesLines(session.LineItems.Data) {
		params := &sdk.CheckoutSessionRetrieveParams{}
		params.AddExpand("line_items")
		var err error
		session, err = s.client.V1CheckoutSessions.Retrieve(ctx, id, params)
		if err != nil {
			return nil, err
		}
	}
	if session == nil || session.ID != id || !checkoutMatches(a, session) || session.Livemode != live || session.Mode != sdk.CheckoutSessionModeSubscription ||
		session.Status != sdk.CheckoutSessionStatusComplete || session.PaymentStatus != sdk.CheckoutSessionPaymentStatusPaid && session.PaymentStatus != sdk.CheckoutSessionPaymentStatusNoPaymentRequired ||
		session.Subscription == nil || session.Subscription.ID != remote || session.LineItems == nil {
		return nil, ErrCheckoutReconcile
	}
	if session.LineItems.HasMore && len(a.MeteredPriceIDs) > 0 {
		params := &sdk.CheckoutSessionListLineItemsParams{Session: sdk.String(id)}
		params.Limit = sdk.Int64(maxRecurringLines)
		items := s.client.V1CheckoutSessions.ListLineItems(ctx, params)
		if err := items.Err(); err != nil {
			return nil, err
		}
		session.LineItems.Data, session.LineItems.HasMore = items.Data(), items.Meta().HasMore
	}
	if session.LineItems.HasMore || !a.matchesLines(session.LineItems.Data) {
		return nil, ErrCheckoutReconcile
	}
	return &CheckoutPurchase{CheckoutID: id, RemoteID: remote, Price: a.Price, SeatPrice: a.SeatPrice, Quantity: a.Quantity(), Live: live, Attempt: a}, nil
}

// PendingCheckoutStore can recover the local purchase when subscription metadata
// has been removed before the first signed event arrives.
type PendingCheckoutStore interface {
	PendingStripeCheckout(context.Context, string) (CheckoutAttempt, error)
}

func (s *subscriptions) purchaseForSubscription(ctx context.Context, store SubscriptionLifecycleStore, owner string, sub, event *sdk.Subscription) (*CheckoutPurchase, error) {
	attemptID := sub.Metadata["checkoutAttemptId"]
	if attemptID == "" && event != nil {
		attemptID = event.Metadata["checkoutAttemptId"]
	}
	if attemptID != "" {
		checkoutStore, ok := store.(SubscriptionStore)
		if !ok {
			return nil, nil
		}
		a, err := checkoutStore.FindStripeCheckout(ctx, owner, attemptID)
		if err != nil || a.Seats == 0 {
			return nil, err
		}
		return s.checkoutPurchase(ctx, a, a.CheckoutID, sub.ID, sub.Livemode, nil)
	}
	pending, ok := store.(PendingCheckoutStore)
	if !ok {
		return nil, nil
	}
	a, err := pending.PendingStripeCheckout(ctx, owner)
	if errors.Is(err, auth.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if a.Seats == 0 || a.Customer != sub.Customer.ID {
		return nil, nil
	}
	if a.CheckoutID == "" {
		return nil, ErrCheckoutReconcile
	}
	params := &sdk.CheckoutSessionRetrieveParams{}
	params.AddExpand("line_items")
	session, err := s.client.V1CheckoutSessions.Retrieve(ctx, a.CheckoutID, params)
	if err != nil {
		return nil, err
	}
	if session == nil || !checkoutMatches(a, session) {
		return nil, ErrCheckoutReconcile
	}
	if session.Status == sdk.CheckoutSessionStatusExpired || session.Subscription != nil && session.Subscription.ID != sub.ID {
		return nil, nil
	}
	return s.checkoutPurchase(ctx, a, a.CheckoutID, sub.ID, sub.Livemode, session)
}

func (p *CheckoutPurchase) claims(current map[string]string) (map[string]string, error) {
	a := p.Attempt
	claims := map[string]string{"userId": a.creator(), "referenceId": a.Owner, "subscriptionId": a.LocalSubscription, "checkoutAttemptId": a.ID, "customerType": "user", "organizationId": a.OrganizationID}
	if a.OrganizationID != "" {
		claims["customerType"] = "organization"
	}
	for field, want := range claims {
		if got := current[field]; got != "" && got != want {
			return nil, ErrCheckoutReconcile
		}
	}
	return claims, nil
}
