package stripe

import (
	"fmt"
	"slices"
	"testing"

	sdk "github.com/stripe/stripe-go/v87"
)

func TestMeteredAddonConfiguration(t *testing.T) {
	addons := make([]string, maxRecurringLines-1)
	for i := range addons {
		addons[i] = fmt.Sprintf("price_usage_%d", i)
	}
	base := Plan{Name: "base", PriceID: "price_licensed", AnnualPriceID: "price_annual", MeteredPriceIDs: addons}
	configure := func(plans ...Plan) (*subscriptions, error) {
		return configureSubscriptions(&SubscriptionOptions{Client: sdk.NewClient("sk_test_config"), Plans: plans})
	}
	configured, err := configure(base)
	if err != nil || !configured.hasMeteredAddons {
		t.Fatal("valid nineteen-add-on plan", err)
	}
	for _, invalid := range [][]string{
		append(slices.Clone(addons), "price_over_limit"),
		{"price_same", "price_same"}, {"price_licensed"}, {"price_annual"}, {"price_seat"}, {"meter_wrong_kind"}, {"price_"},
	} {
		plan := base
		plan.MeteredPriceIDs = invalid
		if _, err := configure(plan, Plan{Name: "other", PriceID: "price_other", SeatPriceID: "price_seat"}); err == nil {
			t.Fatalf("accepted conflicting or invalid add-on configuration: %v", invalid)
		}
	}
	base.SeatPriceID = "price_member"
	if _, err := configure(base); err == nil {
		t.Fatal("accepted unsupported automatic member seats plus metered add-ons")
	}
	addons[0] = "price_drift"
	if configured.plans["base"].MeteredPriceIDs[0] != "price_usage_0" {
		t.Fatal("host mutation changed the installed add-on configuration")
	}
}
