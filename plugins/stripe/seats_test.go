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
	for _, plan := range []Plan{{Name: "multi", PriceID: "price_base", SeatPriceID: "price_seat"}, {Name: "year", PriceID: "price_seat", SeatPriceID: "price_seat", AnnualPriceID: "price_annual"}} {
		if _, err := configureSubscriptions(&SubscriptionOptions{Client: sdk.NewClient("sk_test"), Plans: []Plan{plan}}); err == nil {
			t.Fatal("accepted unsupported seat plan", plan.Name)
		}
	}
}
