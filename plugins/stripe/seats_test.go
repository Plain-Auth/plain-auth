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
	annualSeats := Plan{Name: "yearly", PriceID: "price_base", AnnualPriceID: "price_year", SeatPriceID: "price_year"}
	if _, err := configureSubscriptions(&SubscriptionOptions{Client: sdk.NewClient("sk_test"), Plans: []Plan{annualSeats}}); err != nil {
		t.Fatal("yearly seat price must identify its own plan", err)
	}
	foreign := Plan{Name: "other", PriceID: "price_other", SeatPriceID: "price_year"}
	if _, err := configureSubscriptions(&SubscriptionOptions{Client: sdk.NewClient("sk_test"), Plans: []Plan{annualSeats, foreign}}); err == nil {
		t.Fatal("another plan reused an annual seat-only price as a separate seat")
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

func TestManagedSubscriptionIntervals(t *testing.T) {
	plan := Plan{Name: "team", PriceID: "price_base", AnnualPriceID: "price_annual", SeatPriceID: "price_member"}
	s, err := configureSubscriptions(&SubscriptionOptions{Client: sdk.NewClient("sk_test"), Plans: []Plan{plan}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, base, baseInterval, seatInterval, want string
		count                                        int64
	}{
		{"monthly", plan.PriceID, "month", "month", "month", 1},
		{"annual", plan.AnnualPriceID, "year", "year", "year", 1},
		{"monthly seat on annual base", plan.AnnualPriceID, "year", "month", "", 1},
		{"annual seat on monthly base", plan.PriceID, "month", "year", "", 1},
		{"wrong base interval", plan.AnnualPriceID, "month", "month", "", 1},
		{"two-year seat", plan.AnnualPriceID, "year", "year", "", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := func(id, price, interval string, count int64) *sdk.SubscriptionItem {
				return &sdk.SubscriptionItem{ID: id, Quantity: 1, Price: &sdk.Price{ID: price, Recurring: &sdk.PriceRecurring{Interval: sdk.PriceRecurringInterval(interval), IntervalCount: count, UsageType: sdk.PriceRecurringUsageTypeLicensed}}}
			}
			state := s.subscriptionChange(&sdk.Subscription{Status: sdk.SubscriptionStatusActive, Items: &sdk.SubscriptionItemList{Data: []*sdk.SubscriptionItem{item("si_seat", plan.SeatPriceID, tc.seatInterval, tc.count), item("si_base", tc.base, tc.baseInterval, 1)}}}, false, true)
			if state.Interval != tc.want || (state.ManagedBasePrice == tc.base) != (tc.want != "") || (state.Plan == plan.Name) != (tc.want != "") {
				t.Fatal("provider intervals granted the wrong managed plan", state)
			}
		})
	}
}
