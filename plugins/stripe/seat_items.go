package stripe

import (
	"context"
	"errors"

	sdk "github.com/stripe/stripe-go/v87"
)

// A reservation predating separate seat prices has a single immutable line.
func (a CheckoutAttempt) checkoutLines() []*sdk.CheckoutSessionCreateLineItemParams {
	base := &sdk.CheckoutSessionCreateLineItemParams{Price: sdk.String(a.Price), Quantity: sdk.Int64(a.Quantity())}
	lines := []*sdk.CheckoutSessionCreateLineItemParams{base}
	if a.SeatPrice != "" {
		base.Quantity = sdk.Int64(1)
		lines = append(lines, &sdk.CheckoutSessionCreateLineItemParams{Price: sdk.String(a.SeatPrice), Quantity: sdk.Int64(a.Quantity())})
	}
	return lines
}

func (a CheckoutAttempt) matchesLines(actual []*sdk.LineItem) bool {
	want := a.checkoutLines()
	if len(actual) != len(want) {
		return false
	}
	purchased := make(map[string]int64, len(actual))
	for _, line := range actual {
		if line == nil || line.Price == nil || line.Price.ID == "" {
			return false
		}
		if _, duplicate := purchased[line.Price.ID]; duplicate {
			return false
		}
		purchased[line.Price.ID] = line.Quantity
	}
	for _, expected := range want {
		if count, ok := purchased[*expected.Price]; !ok || count != *expected.Quantity {
			return false
		}
	}
	return true
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
