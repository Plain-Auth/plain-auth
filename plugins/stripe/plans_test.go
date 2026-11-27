package stripe_test

import (
	"math"
	"strings"
	"testing"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	stripeplugin "github.com/Plain-Org/plain-auth/plugins/stripe"
	stripesdk "github.com/stripe/stripe-go/v87"
)

// Plan limits must be JSON values of at most 8 KiB.
func TestPlanMetadataConfiguration(t *testing.T) {
	const message = "stripe: plan limits must be JSON values of at most 8 KiB"
	start := func(limits map[string]any) error {
		_, err := authn.New(authn.Options{Store: memory.New(), BaseURL: "http://auth.test", Secret: "test-secret-0123456789-abcdefghijk",
			Plugins: []authn.Plugin{stripeplugin.New(stripeplugin.Options{WebhookSecret: "whsec_local", Subscriptions: &stripeplugin.SubscriptionOptions{
				Client: stripesdk.NewClient("sk_test_local"), Plans: []stripeplugin.Plan{{Name: "pro", PriceID: "price_pro", Limits: limits, Group: "core"}}}})}})
		return err
	}
	// {"k":"..."} marshals to eight bytes around the value.
	for name, limits := range map[string]map[string]any{
		"function": {"bad": func() {}}, "nan": {"nan": math.NaN()}, "over 8 KiB": {"k": strings.Repeat("a", 8<<10-8+1)},
	} {
		if err := start(limits); err == nil || err.Error() != message {
			t.Error("invalid plan limits were accepted", name, err)
		}
	}
	if err := start(map[string]any{"k": strings.Repeat("a", 8<<10-8)}); err != nil && err.Error() == message {
		t.Error("limits of exactly 8 KiB were refused")
	}
}

// Every plan's proration behavior is checked at startup: licensed, metered
// add-on and membership plans accept the three Stripe values or none, and
// refuse any other.
func TestPlanProrationBehavior(t *testing.T) {
	const message = "stripe: unknown proration behavior"
	plans := map[string]stripeplugin.Plan{
		"licensed": {Name: "pro", PriceID: "price_pro"},
		"metered":  {Name: "pro", PriceID: "price_pro", MeteredPriceIDs: []string{"price_usage"}},
		"seats":    {Name: "pro", PriceID: "price_pro", SeatPriceID: "price_pro"},
	}
	for kind, plan := range plans {
		for _, behavior := range []string{"", "create_prorations", "always_invoice", "none", "invalid"} {
			plan.ProrationBehavior = behavior
			_, err := authn.New(authn.Options{Store: memory.New(), BaseURL: "http://auth.test", Secret: "test-secret-0123456789-abcdefghijk",
				Plugins: []authn.Plugin{stripeplugin.New(stripeplugin.Options{WebhookSecret: "whsec_local",
					Organization:  &stripeplugin.OrganizationOptions{AuthorizeReference: func(stripeplugin.ReferenceAuthorization) bool { return true }},
					Subscriptions: &stripeplugin.SubscriptionOptions{Client: stripesdk.NewClient("sk_test_local"), Plans: []stripeplugin.Plan{plan}}})}})
			refused := err != nil && err.Error() == message
			if refused != (behavior == "invalid") {
				t.Error("a proration behavior was handled wrongly", kind, behavior, err)
			}
		}
	}
}

// Plan names are trimmed and compared in lowercase, and each needs a
// monthly price ID; an annual price ID is optional, and one price names
// exactly one plan and interval.
func TestPlanNamesAndPrices(t *testing.T) {
	start := func(plans ...stripeplugin.Plan) error {
		_, err := authn.New(authn.Options{Store: memory.New(), BaseURL: "http://auth.test", Secret: "test-secret-0123456789-abcdefghijk",
			Plugins: []authn.Plugin{stripeplugin.New(stripeplugin.Options{WebhookSecret: "whsec_local", Subscriptions: &stripeplugin.SubscriptionOptions{
				Client: stripesdk.NewClient("sk_test_local"), Plans: plans}})}})
		return err
	}
	const invalid = "stripe: invalid or duplicate subscription plan"
	const shared = "stripe: a recurring price must identify a single subscription plan and interval"
	for name, plans := range map[string][]stripeplugin.Plan{
		"empty name":     {{Name: "", PriceID: "price_a"}},
		"blank name":     {{Name: "   ", PriceID: "price_a"}},
		"duplicate name": {{Name: "Pro", PriceID: "price_a"}, {Name: "pro", PriceID: "price_b"}},
		"no price":       {{Name: "pro"}},
		"bare price":     {{Name: "pro", PriceID: "price_"}},
		"product":        {{Name: "pro", PriceID: "prod_x"}},
		"bare annual":    {{Name: "pro", PriceID: "price_a", AnnualPriceID: "price_"}},
		"legacy annual":  {{Name: "pro", PriceID: "price_a", AnnualPriceID: "plan_x"}},
	} {
		if err := start(plans...); err == nil || err.Error() != invalid {
			t.Error("an invalid plan was accepted", name, err)
		}
	}
	for name, plans := range map[string][]stripeplugin.Plan{
		"two plans":     {{Name: "pro", PriceID: "price_a"}, {Name: "team", PriceID: "price_a"}},
		"two intervals": {{Name: "pro", PriceID: "price_a", AnnualPriceID: "price_a"}},
	} {
		if err := start(plans...); err == nil || err.Error() != shared {
			t.Error("a shared price was accepted", name, err)
		}
	}
	if err := start(stripeplugin.Plan{Name: " Pro ", PriceID: "price_a", AnnualPriceID: "price_b"}); err != nil && (err.Error() == invalid || err.Error() == shared) {
		t.Error("a padded plan name was refused", err)
	}
}
