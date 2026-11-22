package stripe

import (
	sdk "github.com/stripe/stripe-go/v87"
	"testing"
)

func TestSubscriptionPriceIsUnambiguous(t *testing.T) {
	for _, plans := range [][]Plan{
		{{Name: "basic", PriceID: "price_month", AnnualPriceID: "price_month"}},
		{{Name: "basic", PriceID: "price_base", AnnualPriceID: "price_shared"}, {Name: "pro", PriceID: "price_shared"}},
	} {
		if _, err := configureSubscriptions(&SubscriptionOptions{Client: sdk.NewClient("sk_test_fixture"), Plans: plans}); err == nil {
			t.Fatal("accepted an ambiguous price configuration")
		}
	}
}

func TestFreeTrialRequiresPositiveDays(t *testing.T) {
	for _, days := range []int64{-1, 0, 1, 14} {
		plan := Plan{Name: "basic", PriceID: "price_basic", FreeTrial: &FreeTrial{Days: days}}
		config, err := configureSubscriptions(&SubscriptionOptions{Client: sdk.NewClient("sk_test_fixture"), Plans: []Plan{plan}})
		if (err != nil) != (days < 1) {
			t.Fatalf("%d configured trial days: %v", days, err)
		}
		if err == nil {
			plan.FreeTrial.Days = 100
			if config.plans["basic"].FreeTrial.Days != days {
				t.Fatal("configured trial duration changed with caller memory")
			}
		}
	}
}
