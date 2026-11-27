package stripe

import (
	"context"
	"errors"
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
		if len(plan.MeteredPriceIDs) == 0 {
			continue
		}
		if plan.SeatPriceID != "" || len(plan.MeteredPriceIDs) >= maxRecurringLines {
			return errors.New("stripe: metered add-ons require a manually quantified base and at most 19 add-ons")
		}
		for i, id := range plan.MeteredPriceIDs {
			if !strings.HasPrefix(id, "price_") || len(id) <= len("price_") || reserved[id] || slices.Contains(plan.MeteredPriceIDs[:i], id) {
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

func matchesAddonSubscription(items *sdk.SubscriptionItemList, base *sdk.SubscriptionItem, addons []string, interval string) bool {
	if items.HasMore || len(items.Data) != len(addons)+1 || base.Quantity <= 0 || !licensedAtInterval(base.Price, interval) {
		return false
	}
	prices := make(map[string]bool, len(items.Data))
	ids := make(map[string]bool, len(items.Data))
	for _, item := range items.Data {
		if item == nil || item.Price == nil || item.ID == "" || ids[item.ID] || prices[item.Price.ID] {
			return false
		}
		prices[item.Price.ID], ids[item.ID] = true, true
		if item != base && (!slices.Contains(addons, item.Price.ID) || !recurringAtInterval(item.Price, interval, sdk.PriceRecurringUsageTypeMetered)) {
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
