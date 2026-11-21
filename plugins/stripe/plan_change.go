package stripe

import (
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	sdk "github.com/stripe/stripe-go/v87"
)

var (
	errAlreadySubscribed = billingError(400, "ALREADY_SUBSCRIBED_PLAN", "You're already subscribed to this plan")
	ErrPendingSchedule   = billingError(409, "SUBSCRIPTION_PENDING_CHANGE", "Resolve the pending subscription change before switching plans")
	errUnsupportedItem   = billingError(409, "UNSUPPORTED_SUBSCRIPTION_ITEM", "Plan changes require one configured single-seat recurring item")
)

// changePlan opens the customer confirmation page. The authoritative price only
// changes when Stripe confirms it and the subscription is reconciled.
func (s *subscriptions) changePlan(c auth.EndpointContext, selection billingSelection, local Subscription, target, returnURL string) (any, error) {
	_, ok := c.Store().(SubscriptionManagementStore)
	if !ok || local.SubscriptionID == nil {
		return nil, ErrExistingSubscription
	}
	ctx := c.Request.Context()
	scheduled, _ := c.Body["scheduleAtPeriodEnd"].(bool)
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
	if item == nil || item.ID == "" || item.Quantity != 1 || !s.singleSeatPrice(item.Price) {
		return nil, errUnsupportedItem
	}
	if sub.Status == sdk.SubscriptionStatusActive && item.Price.ID == target && (item.CurrentPeriodEnd == 0 || item.CurrentPeriodEnd > time.Now().Unix()) {
		return nil, errAlreadySubscribed
	}
	price, err := s.client.V1Prices.Retrieve(ctx, target, nil)
	if err != nil {
		return nil, providerManagementError(err)
	}
	if price == nil || price.ID != target || !price.Active || !s.singleSeatPrice(price) {
		return nil, errUnsupportedItem
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
					{ID: sdk.String(item.ID), Price: sdk.String(target), Quantity: sdk.Int64(1)},
				},
			},
		},
	}
	portal, err := s.client.V1BillingPortalSessions.Create(ctx, params)
	if err != nil {
		return nil, providerManagementError(err)
	}
	if portal == nil || portal.Customer != sub.Customer.ID || portal.URL == "" {
		return nil, billingError(502, "UNABLE_TO_CREATE_BILLING_PORTAL", "Stripe did not return a billing portal for this customer")
	}
	if _, err := checkOwner(); err != nil {
		return nil, err
	}
	disable, _ := c.Body["disableRedirect"].(bool)
	return map[string]any{"url": portal.URL, "redirect": !disable}, nil
}

func (s *subscriptions) singleSeatPrice(p *sdk.Price) bool {
	if p == nil || p.Recurring == nil {
		return false
	}
	def, known := s.prices[p.ID]
	return known && string(p.Recurring.Interval) == def.interval && p.Recurring.IntervalCount == 1 &&
		p.Recurring.UsageType == sdk.PriceRecurringUsageTypeLicensed
}
