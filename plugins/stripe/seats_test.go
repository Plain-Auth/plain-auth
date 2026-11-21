package stripe

import (
	"testing"

	sdk "github.com/stripe/stripe-go/v87"
)

func TestMembershipPriceConfiguration(t *testing.T) {
	for _, behavior := range []string{"", "create_prorations", "always_invoice", "none", "invalid"} {
		plan := Plan{Name: "team", PriceID: "price_seat", SeatPriceID: "price_seat", ProrationBehavior: behavior}
		s, err := configureSubscriptions(&SubscriptionOptions{Client: sdk.NewClient("sk_test"), Plans: []Plan{plan}})
		if behavior == "invalid" {
			if err == nil {
				t.Fatal("accepted unknown proration policy")
			}
			continue
		}
		want := behavior
		if want == "" {
			want = "create_prorations"
		}
		if err != nil || s.plans["team"].ProrationBehavior != want {
			t.Fatal("incorrect seat proration", behavior, err)
		}
	}
	for _, plan := range []Plan{{Name: "invalid", PriceID: "price_base", SeatPriceID: "invalid"}, {Name: "year", PriceID: "price_seat", SeatPriceID: "price_seat", AnnualPriceID: "price_annual"}} {
		if _, err := configureSubscriptions(&SubscriptionOptions{Client: sdk.NewClient("sk_test"), Plans: []Plan{plan}}); err == nil {
			t.Fatal("accepted unsupported seat plan", plan.Name)
		}
	}
}

func TestManagedItemsRequireBothConfiguredPrices(t *testing.T) {
	plan := Plan{Name: "team", PriceID: "price_base", SeatPriceID: "price_member"}
	s, err := configureSubscriptions(&SubscriptionOptions{Client: sdk.NewClient("sk_test"), Plans: []Plan{plan}})
	if err != nil {
		t.Fatal(err)
	}
	item := func(id, price string, quantity int64) *sdk.SubscriptionItem {
		return &sdk.SubscriptionItem{ID: id, Quantity: quantity, Price: &sdk.Price{ID: price, Recurring: &sdk.PriceRecurring{Interval: sdk.PriceRecurringIntervalMonth, IntervalCount: 1, UsageType: sdk.PriceRecurringUsageTypeLicensed}}}
	}
	base, seat := item("si_base", plan.PriceID, 1), item("si_member", plan.SeatPriceID, 4)
	for _, items := range [][]*sdk.SubscriptionItem{{base, seat}, {seat, base}} {
		change := s.subscriptionChange(&sdk.Subscription{Status: sdk.SubscriptionStatusActive, Items: &sdk.SubscriptionItemList{Data: items}}, false, true)
		if change.Plan != plan.Name || change.Seats != 4 || change.ManagedBasePrice != plan.PriceID || change.ManagedSeatPrice != plan.SeatPriceID {
			t.Fatal("incorrectly resolved two configured line items", change)
		}
	}
	metered := item("si_member", plan.SeatPriceID, 4)
	metered.Price.Recurring.UsageType = sdk.PriceRecurringUsageTypeMetered
	for _, items := range [][]*sdk.SubscriptionItem{{base}, {seat}, {seat, seat}, {base, base}, {base, seat, seat}, {base, metered}, {base, item("si_base", plan.SeatPriceID, 4)}, {item("si_base", plan.PriceID, 2), seat}, {base, item("si_other", "price_other", 4)}} {
		change := s.subscriptionChange(&sdk.Subscription{Status: sdk.SubscriptionStatusActive, Items: &sdk.SubscriptionItemList{Data: items}}, false, true)
		if change.Plan != "" || change.ManagedSeatPrice != "" {
			t.Fatal("ambiguous provider items granted the managed plan", change)
		}
	}
	purchase := CheckoutAttempt{Price: plan.PriceID, SeatPrice: plan.SeatPriceID, Seats: 4}
	line := func(price string, quantity int64) *sdk.LineItem {
		return &sdk.LineItem{Price: &sdk.Price{ID: price}, Quantity: quantity}
	}
	if !purchase.matchesLines([]*sdk.LineItem{line(plan.SeatPriceID, 4), line(plan.PriceID, 1)}) {
		t.Fatal("valid reversed receipt rejected")
	}
	for _, lines := range [][]*sdk.LineItem{{line(plan.PriceID, 1)}, {line(plan.PriceID, 1), line(plan.PriceID, 1)}, {line(plan.SeatPriceID, 1), line(plan.PriceID, 4)}, {line(plan.PriceID, 1), line(plan.SeatPriceID, 4), line("price_other", 1)}} {
		if purchase.matchesLines(lines) {
			t.Fatal("nonmatching two-item receipt accepted")
		}
	}
}
