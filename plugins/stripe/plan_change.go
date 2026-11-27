package stripe

import (
	"context"
	"math"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	sdk "github.com/stripe/stripe-go/v87"
)

var (
	errAlreadySubscribed         = billingError(400, "ALREADY_SUBSCRIBED_PLAN", "You're already subscribed to this plan")
	ErrPendingSchedule           = billingError(409, "SUBSCRIPTION_PENDING_CHANGE", "Resolve the pending subscription change before switching plans")
	errUnsupportedScheduledSeats = billingError(409, "UNSUPPORTED_SCHEDULE_QUANTITY", "Scheduled changes require one seat")
	errUnsupportedItem           = billingError(409, "UNSUPPORTED_SUBSCRIPTION_ITEM", "Plan changes require one configured licensed recurring item")
)

// changePlan opens the customer confirmation page. The authoritative price only
// changes when Stripe confirms it and the subscription is reconciled.
func (s *subscriptions) changePlan(c auth.EndpointContext, selection billingSelection, local Subscription, to Plan, interval, target, returnURL string, quantity int64) (any, error) {
	_, ok := c.Store().(SubscriptionManagementStore)
	if !ok || local.SubscriptionID == nil {
		return nil, ErrExistingSubscription
	}
	from := s.plans[local.Plan]
	if len(from.extras()) > 0 || len(to.extras()) > 0 {
		return nil, errUnsupportedItem
	}
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
	if sub.Items == nil || sub.Items.HasMore || len(sub.Items.Data) != 1 {
		return nil, errUnsupportedItem
	}
	item := sub.Items.Data[0]
	if item == nil || item.ID == "" || item.Quantity < 1 || item.Quantity > math.MaxInt32 || !s.licensedPrice(item.Price) {
		return nil, errUnsupportedItem
	}
	if scheduled && item.Quantity != 1 {
		return nil, errUnsupportedScheduledSeats
	}
	sourcePrice, _ = s.priceOf(item.Price)
	sourceQuantity = item.Quantity
	if sub.Status == sdk.SubscriptionStatusActive && item.Price.ID == target && item.Quantity == quantity && (item.CurrentPeriodEnd == 0 || item.CurrentPeriodEnd > time.Now().Unix()) {
		return nil, errAlreadySubscribed
	}
	if err := s.verifyPriceInterval(ctx, target, interval); err != nil {
		return nil, err
	}
	if _, err := checkOwner(); err != nil {
		return nil, err
	}

	if scheduled {
		return s.scheduleChange(c, selection, local, sub, item, target, returnURL)
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
				Items: []*sdk.BillingPortalSessionCreateFlowDataSubscriptionUpdateConfirmItemParams{
					{ID: sdk.String(item.ID), Price: sdk.String(target), Quantity: sdk.Int64(quantity)},
				},
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
