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
