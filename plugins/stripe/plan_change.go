package stripe

import (
	"context"
	"slices"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	sdk "github.com/stripe/stripe-go/v87"
)

var (
	errAlreadySubscribed         = billingError(400, "ALREADY_SUBSCRIBED_PLAN", "You're already subscribed to this plan")
	ErrPendingSchedule           = billingError(409, "SUBSCRIPTION_PENDING_CHANGE", "Resolve the pending subscription change before switching plans")
	errUnsupportedScheduledSeats = billingError(409, "UNSUPPORTED_SCHEDULE_QUANTITY", "Scheduled changes require one seat")
	errUnsupportedItem           = billingError(409, "UNSUPPORTED_SUBSCRIPTION_ITEM", "Plan changes require the subscription's configured recurring items")
)

// changePlan opens the customer confirmation page for a single-item
// subscription, and otherwise changes the items directly. The
// authoritative price only changes when Stripe confirms it and the
// subscription is reconciled.
func (s *subscriptions) changePlan(c auth.EndpointContext, selection billingSelection, local Subscription, to Plan, interval, target, returnURL string, quantity int64) (any, error) {
	_, ok := c.Store().(SubscriptionManagementStore)
	if !ok || local.SubscriptionID == nil {
		return nil, ErrExistingSubscription
	}
	from := s.plans[local.Plan]
	if selection.organization {
		if from.SeatPriceID != "" || to.SeatPriceID != "" {
			current := from.PriceID
			if local.Interval != nil && *local.Interval == "year" {
				current = from.AnnualPriceID
			}
			if from.Name == to.Name && current == target && local.Status == "active" {
				return nil, errAlreadySubscribed
			}
			return nil, ErrManagedSeatPlanChange
		}
	}
	ctx := c.Request.Context()
	scheduled, _ := c.Body["scheduleAtPeriodEnd"].(bool)
	var sourcePrice subscriptionPrice
	var sourceQuantity int64
	checkOwner := func() (Subscription, error) {
		row, err := recheckManaged(c, selection, local)
		if err != nil {
			return row, err
		}
		if row.Status != "active" && row.Status != "trialing" {
			return row, ErrExistingSubscription
		}
		if row.CancelAt != nil || (!scheduled && row.ScheduleID != nil) || (row.CancelAtPeriodEnd != nil && *row.CancelAtPeriodEnd) {
			return row, ErrPendingSchedule
		}
		if sourceQuantity > 0 && (row.Plan != sourcePrice.plan || row.Interval == nil || *row.Interval != sourcePrice.interval || row.Seats == nil || *row.Seats != sourceQuantity) {
			return row, ErrCheckoutReconcile
		}
		return row, nil
	}
	if _, err := checkOwner(); err != nil {
		return nil, err
	}
	sub, err := s.currentManaged(c, selection, local)
	if err != nil {
		return nil, err
	}
	if sub.Status != sdk.SubscriptionStatusActive && sub.Status != sdk.SubscriptionStatusTrialing {
		return nil, ErrExistingSubscription
	}
	if (!scheduled && sub.Schedule != nil) || sub.PendingUpdate != nil || sub.CancelAtPeriodEnd || sub.CancelAt != 0 || sub.PauseCollection != nil {
		return nil, ErrPendingSchedule
	}
	b, ok := s.currentBasket(sub, selection.organization)
	if !ok {
		return nil, errUnsupportedItem
	}
	// A scheduled change rewrites one licensed item, as the schedule flow
	// verifies a single-item phase. Another runtime also rewrites line
	// items into the scheduled phase.
	if scheduled && (b.metered || len(b.extras) > 0 || len(to.extras()) > 0) {
		return nil, errUnsupportedItem
	}
	if scheduled && b.base.Quantity != 1 {
		return nil, errUnsupportedScheduledSeats
	}
	sourcePrice, sourceQuantity = b.plan, b.seats
	if sub.Status == sdk.SubscriptionStatusActive && b.plan.plan == to.Name && b.base.Price.ID == target && (b.metered || b.base.Quantity == quantity) &&
		(b.base.CurrentPeriodEnd == 0 || b.base.CurrentPeriodEnd > time.Now().Unix()) {
		// A direct change that reached Stripe while its response was lost
		// is complete: its retry succeeds without a second update.
		if store, ok := c.Store().(PlanChangeStore); ok {
			done, err := store.ReleaseStripePlanChange(ctx, selection.session.Session.Token, PlanChange{Owner: selection.reference, Subscription: sub.ID, Plan: to.Name, Interval: interval, Quantity: quantity}, time.Now().UTC())
			if err != nil {
				return nil, err
			}
			if done {
				disable, _ := c.Body["disableRedirect"].(bool)
				return map[string]any{"url": returnURL, "redirect": !disable}, nil
			}
		}
		return nil, errAlreadySubscribed
	}
	t := CheckoutAttempt{Price: target, Interval: interval, Seats: quantity, MeteredPriceIDs: slices.Clone(to.MeteredPriceIDs), LineItems: slices.Clone(to.LineItems)}
	if err := s.prepareCheckoutPrices(ctx, &t); err != nil {
		return nil, err
	}
	if scheduled && t.Metered {
		return nil, errUnsupportedItem
	}
	if _, err := checkOwner(); err != nil {
		return nil, err
	}

	if scheduled {
		return s.scheduleChange(c, selection, local, sub, b.base, target, returnURL)
	}
	if len(b.extras) > 0 || t.hasExtras() {
		return s.updatePlanItems(c, selection, local, sub, b, to, t, quantity, returnURL)
	}
	confirm := &sdk.BillingPortalSessionCreateFlowDataSubscriptionUpdateConfirmItemParams{ID: sdk.String(b.base.ID), Price: sdk.String(target)}
	if !t.Metered {
		confirm.Quantity = sdk.Int64(quantity)
	}
	params := &sdk.BillingPortalSessionCreateParams{
		Customer: sdk.String(sub.Customer.ID), ReturnURL: sdk.String(returnURL),
		FlowData: &sdk.BillingPortalSessionCreateFlowDataParams{
			Type: sdk.String("subscription_update_confirm"),
			AfterCompletion: &sdk.BillingPortalSessionCreateFlowDataAfterCompletionParams{
				Type: sdk.String("redirect"), Redirect: &sdk.BillingPortalSessionCreateFlowDataAfterCompletionRedirectParams{ReturnURL: sdk.String(returnURL)},
			},
			SubscriptionUpdateConfirm: &sdk.BillingPortalSessionCreateFlowDataSubscriptionUpdateConfirmParams{
				Subscription: sdk.String(sub.ID),
				Items:        []*sdk.BillingPortalSessionCreateFlowDataSubscriptionUpdateConfirmItemParams{confirm},
			},
		},
	}
	portal, err := s.client.V1BillingPortalSessions.Create(ctx, params)
	if err != nil {
		return nil, providerManagementError(err)
	}
	// Stripe's own unusable answer is a 502; see cancel.
	if portal == nil || portal.Customer != sub.Customer.ID || portal.URL == "" {
		return nil, billingError(502, "UNABLE_TO_CREATE_BILLING_PORTAL", "Stripe did not return a billing portal for this customer")
	}
	if _, err := checkOwner(); err != nil {
		return nil, err
	}
	disable, _ := c.Body["disableRedirect"].(bool)
	return map[string]any{"url": portal.URL, "redirect": !disable}, nil
}

func (s *subscriptions) verifyPriceInterval(ctx context.Context, target, interval string) error {
	price, err := s.client.V1Prices.Retrieve(ctx, target, nil)
	if err != nil {
		return providerManagementError(err)
	}
	if price == nil || price.ID != target || !price.Active || !licensedAtInterval(price, interval) {
		return errUnsupportedItem
	}
	return nil
}

func (s *subscriptions) licensedPrice(p *sdk.Price) bool {
	price, _ := s.priceOf(p)
	return p != nil && licensedAtInterval(p, price.interval)
}

func licensedAtInterval(p *sdk.Price, interval string) bool {
	return recurringAtInterval(p, interval, sdk.PriceRecurringUsageTypeLicensed)
}

// recurringAtInterval accepts only a monthly or yearly price with an
// interval count of one, where another runtime accepts any recurring price:
// a plan models a month and a year, and the interval drives the list, plan
// changes and Checkout's same-interval rule.
func recurringAtInterval(p *sdk.Price, interval string, usage sdk.PriceRecurringUsageType) bool {
	return (interval == "month" || interval == "year") && p != nil && p.Recurring != nil &&
		string(p.Recurring.Interval) == interval && p.Recurring.IntervalCount == 1 &&
		p.Recurring.UsageType == usage
}
