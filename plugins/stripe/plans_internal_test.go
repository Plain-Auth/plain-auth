package stripe

import (
	"slices"
	"testing"

	sdk "github.com/stripe/stripe-go/v87"
)

// Every plan reports its effective proration behavior: the configured
// value, or create_prorations when unset.
func TestPlanProrationDefaults(t *testing.T) {
	plans := map[string]Plan{
		"licensed": {Name: "pro", PriceID: "price_pro"},
		"metered":  {Name: "pro", PriceID: "price_pro", MeteredPriceIDs: []string{"price_usage"}},
		"seats":    {Name: "pro", PriceID: "price_pro", SeatPriceID: "price_pro"},
	}
	for kind, plan := range plans {
		for _, behavior := range []string{"", "create_prorations", "always_invoice", "none"} {
			plan.ProrationBehavior = behavior
			s, err := configureSubscriptions(&SubscriptionOptions{Client: sdk.NewClient("sk_test"), Plans: []Plan{plan}})
			want := behavior
			if want == "" {
				want = "create_prorations"
			}
			if err != nil || s.plans["pro"].ProrationBehavior != want {
				t.Error("a plan reported the wrong proration behavior", kind, behavior, err)
			}
		}
	}
}

// A plan's clone shares no slice with the installed plan.
func TestPlanCloneIsolatesRetiredPrices(t *testing.T) {
	installed := Plan{Name: "pro", PriceID: "price_pro", RetiredPriceIDs: []string{"price_v2", "price_v1"}}
	copied := installed.clone()
	slices.Sort(copied.RetiredPriceIDs)
	if installed.RetiredPriceIDs[0] != "price_v2" {
		t.Fatal("a clone changed the installed plan's retired prices", installed.RetiredPriceIDs)
	}
}
