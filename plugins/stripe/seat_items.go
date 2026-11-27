package stripe

import (
	"context"
	"errors"

	sdk "github.com/stripe/stripe-go/v87"
)

// A reservation predating separate seat prices has a single immutable line.
func (a CheckoutAttempt) checkoutLines() []*sdk.CheckoutSessionCreateLineItemParams {
	base := &sdk.CheckoutSessionCreateLineItemParams{Price: sdk.String(a.Price), Quantity: sdk.Int64(a.Quantity())}
	if a.Metered {
		base.Quantity = nil
	}
	lines := []*sdk.CheckoutSessionCreateLineItemParams{base}
	if a.SeatPrice != "" {
		base.Quantity = sdk.Int64(1)
		lines = append(lines, &sdk.CheckoutSessionCreateLineItemParams{Price: sdk.String(a.SeatPrice), Quantity: sdk.Int64(a.Quantity())})
	}
	for _, item := range a.extras() {
		line := &sdk.CheckoutSessionCreateLineItemParams{Price: sdk.String(item.Price)}
		if item.Quantity > 0 {
			line.Quantity = sdk.Int64(item.Quantity)
		}
		lines = append(lines, line)
	}
	return lines
}

// extras returns the reservation's items after the base.
func (a CheckoutAttempt) extras() []LineItem {
	return Plan{MeteredPriceIDs: a.MeteredPriceIDs, LineItems: a.LineItems}.extras()
}

func (a CheckoutAttempt) hasExtras() bool {
	return len(a.MeteredPriceIDs) > 0 || len(a.LineItems) > 0
}

func (a CheckoutAttempt) matchesLines(actual []*sdk.LineItem) bool {
	want := a.checkoutLines()
	if len(actual) != len(want) {
		return false
	}
	purchased := make(map[string]*sdk.LineItem, len(actual))
	for _, line := range actual {
		if line == nil || line.Price == nil || line.Price.ID == "" || purchased[line.Price.ID] != nil {
			return false
		}
		purchased[line.Price.ID] = line
	}
	for _, expected := range want {
		line := purchased[*expected.Price]
		if line == nil {
			return false
		}
		if expected.Quantity == nil {
			if !recurringAtInterval(line.Price, a.Interval, sdk.PriceRecurringUsageTypeMetered) {
				return false
			}
			continue
		}
		if line.Quantity != *expected.Quantity || line.Price.Recurring != nil && line.Price.Recurring.UsageType == sdk.PriceRecurringUsageTypeMetered {
			return false
		}
		if a.hasExtras() && !licensedAtInterval(line.Price, a.Interval) {
			return false
		}
	}
	return true
}

func (a CheckoutAttempt) matchesMeteredPrice(price *sdk.Price) bool {
	return price != nil && price.ID == a.Price && recurringAtInterval(price, a.Interval, sdk.PriceRecurringUsageTypeMetered)
}

func (s *subscriptions) prepareCheckoutPrices(ctx context.Context, a *CheckoutAttempt) error {
	if a.AutomaticSeats {
		if err := s.verifyCheckoutPrices(ctx, *a); err != nil {
			return err
		}
		a.PriceVerified = true
		return nil
	}
	price, err := s.checkoutPrice(ctx, a.Price)
	if err != nil {
		return err
	}
	a.Metered = a.matchesMeteredPrice(price)
	if !a.Metered && !licensedAtInterval(price, a.Interval) {
		return billingError(409, errUnsupportedItem.Code, "Checkout requires an active recurring price with the selected interval")
	}
	if a.Metered && a.hasExtras() {
		return billingError(409, errUnsupportedItem.Code, "Metered add-ons require a licensed base price")
	}
	for _, item := range a.extras() {
		addon, err := s.checkoutPrice(ctx, item.Price)
		if err != nil {
			return err
		}
		if item.Quantity == 0 && !recurringAtInterval(addon, a.Interval, sdk.PriceRecurringUsageTypeMetered) {
			return billingError(409, errUnsupportedItem.Code, "Each add-on must be a metered price with the selected billing interval")
		}
		if item.Quantity > 0 && !licensedAtInterval(addon, a.Interval) {
			return billingError(409, errUnsupportedItem.Code, "Each fixed-quantity line item must be a licensed price with the selected billing interval")
		}
	}
	a.PriceVerified = true
	return nil
}

func (s *subscriptions) verifyCheckoutPrices(ctx context.Context, a CheckoutAttempt) error {
	for _, line := range a.checkoutLines() {
		if err := s.verifyPriceInterval(ctx, *line.Price, a.Interval); err != nil {
			if a.SeatPrice != "" && errors.Is(err, errUnsupportedItem) {
				return billingError(409, errUnsupportedItem.Code, "Organization base and seat prices must be active licensed prices with the selected billing interval")
			}
			return err
		}
	}
	return nil
}

// membershipItems resolves by configured price, independent of provider ordering.
// The base determines the billing period. Only the seat item may change quantity.
func (s *subscriptions) membershipItems(sub *sdk.Subscription, plan Plan, basePrice string) (base, seat *sdk.SubscriptionItem) {
	price := s.prices[basePrice]
	if price.plan != plan.Name || sub == nil || sub.Items == nil || sub.Items.HasMore || plan.SeatPriceID == "" {
		return nil, nil
	}
	for _, item := range sub.Items.Data {
		if item == nil || item.ID == "" || item.Quantity < 0 || !licensedAtInterval(item.Price, price.interval) {
			return nil, nil
		}
		isBase, isSeat := item.Price.ID == basePrice, item.Price.ID == plan.SeatPriceID
		if !isBase && !isSeat || isBase && base != nil || isSeat && seat != nil {
			return nil, nil
		}
		if isBase {
			base = item
		}
		if isSeat {
			seat = item
		}
	}
	if base == nil || seat == nil || basePrice != plan.SeatPriceID && (base.Quantity != 1 || base.ID == seat.ID) {
		return nil, nil
	}
	return base, seat
}
