package stripe

import (
	"context"
	"errors"
	"math"
	"slices"
	"strings"

	sdk "github.com/stripe/stripe-go/v87"
)

// A subscription Checkout accepts at most twenty recurring price lines.
const maxRecurringLines = 20

func (s *planCatalog) validateMeteredAddons() error {
	reserved := make(map[string]bool)
	for _, plan := range s.plans {
		for _, id := range []string{plan.PriceID, plan.AnnualPriceID, plan.SeatPriceID} {
			reserved[id] = true
		}
	}
	for _, plan := range s.plans {
		if len(plan.MeteredPriceIDs) > 0 && len(plan.LineItems) > 0 {
			return errors.New("stripe: set LineItems or MeteredPriceIDs, not both")
		}
		extras := plan.extras()
		if len(extras) == 0 {
			continue
		}
		// Extra items need a manually quantified base: seat updates and
		// membership matching verify an exact base and seat basket.
		if plan.SeatPriceID != "" || len(extras) >= maxRecurringLines {
			if len(plan.LineItems) > 0 {
				return errors.New("stripe: line items require a manually quantified base and at most 19 items")
			}
			return errors.New("stripe: metered add-ons require a manually quantified base and at most 19 add-ons")
		}
		for i, item := range extras {
			if !strings.HasPrefix(item.Price, "price_") || len(item.Price) <= len("price_") || reserved[item.Price] || item.Quantity < 0 || item.Quantity > math.MaxInt32 ||
				slices.ContainsFunc(extras[:i], func(prior LineItem) bool { return prior.Price == item.Price }) {
				if len(plan.LineItems) > 0 {
					return errors.New("stripe: each line item must name a distinct price separate from all base and seat prices, with a quantity from 0 to 2147483647")
				}
				return errors.New("stripe: each metered add-on must identify a distinct price separate from all base and seat prices")
			}
		}
		s.hasMeteredAddons = true
	}
	return nil
}

func (s *subscriptions) checkoutPrice(ctx context.Context, id string) (*sdk.Price, error) {
	price, err := s.client.V1Prices.Retrieve(ctx, id, nil)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, billingError(502, "STRIPE_PRICE_UNAVAILABLE", "Could not retrieve the configured checkout price")
	}
	if price == nil || price.ID != id || !price.Active {
		return nil, billingError(409, errUnsupportedItem.Code, "Checkout requires active configured prices")
	}
	return price, nil
}

// matchesAddonSubscription requires exactly the base plus one item per
// configured extra: metered ones metered at the interval, fixed ones
// licensed at the interval with a quantity of at least one, which may
// change.
func matchesAddonSubscription(items *sdk.SubscriptionItemList, base *sdk.SubscriptionItem, extras []LineItem, interval string) bool {
	if items.HasMore || len(items.Data) != len(extras)+1 || base.Quantity <= 0 || !licensedAtInterval(base.Price, interval) {
		return false
	}
	prices := make(map[string]bool, len(items.Data))
	ids := make(map[string]bool, len(items.Data))
	for _, item := range items.Data {
		if item == nil || item.Price == nil || item.ID == "" || ids[item.ID] || prices[item.Price.ID] {
			return false
		}
		prices[item.Price.ID], ids[item.ID] = true, true
		if item == base {
			continue
		}
		at := slices.IndexFunc(extras, func(extra LineItem) bool { return extra.Price == item.Price.ID })
		if at < 0 {
			return false
		}
		if extras[at].Quantity == 0 && !recurringAtInterval(item.Price, interval, sdk.PriceRecurringUsageTypeMetered) ||
			extras[at].Quantity > 0 && (item.Quantity < 1 || !licensedAtInterval(item.Price, interval)) {
			return false
		}
	}
	return true
}

// Expanded subscription items may be truncated. Request the complete supported
// basket in one response, using the already verified provider subscription ID.
func (s *subscriptions) readAllSubscriptionItems(ctx context.Context, sub *sdk.Subscription) error {
	params := &sdk.SubscriptionItemListParams{Subscription: sdk.String(sub.ID)}
	params.Limit = sdk.Int64(maxRecurringLines)
	items := s.client.V1SubscriptionItems.List(ctx, params)
	if err := items.Err(); err != nil {
		return err
	}
	for _, item := range items.Data() {
		if item == nil || item.Subscription != sub.ID {
			return ErrCheckoutReconcile
		}
	}
	sub.Items.Data, sub.Items.HasMore = items.Data(), items.Meta().HasMore
	return nil
}
