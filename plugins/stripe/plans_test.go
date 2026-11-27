package stripe_test

import (
	"context"
	"errors"
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

// A retired price must be a distinct price ID configured nowhere else, at
// most 100 per plan, and never on a membership-based plan.
func TestRetiredPriceConfiguration(t *testing.T) {
	start := func(plans ...stripeplugin.Plan) error {
		_, err := authn.New(authn.Options{Store: memory.New(), BaseURL: "http://auth.test", Secret: "test-secret-0123456789-abcdefghijk",
			Plugins: []authn.Plugin{stripeplugin.New(stripeplugin.Options{WebhookSecret: "whsec_local",
				Organization:  &stripeplugin.OrganizationOptions{AuthorizeReference: func(stripeplugin.ReferenceAuthorization) bool { return true }},
				Subscriptions: &stripeplugin.SubscriptionOptions{Client: stripesdk.NewClient("sk_test_local"), Plans: plans}})}})
		return err
	}
	const distinct = "stripe: each retired price must be a distinct price ID configured nowhere else"
	many := make([]string, 101)
	for i := range many {
		many[i] = "price_old_" + strings.Repeat("x", i+1)
	}
	for name, tc := range map[string]struct {
		plans []stripeplugin.Plan
		want  string
	}{
		"duplicate":  {[]stripeplugin.Plan{{Name: "pro", PriceID: "price_new", RetiredPriceIDs: []string{"price_old", "price_old"}}}, distinct},
		"other plan": {[]stripeplugin.Plan{{Name: "pro", PriceID: "price_new", RetiredPriceIDs: []string{"price_old"}}, {Name: "team", PriceID: "price_team", RetiredPriceIDs: []string{"price_old"}}}, distinct},
		"base":       {[]stripeplugin.Plan{{Name: "pro", PriceID: "price_new", RetiredPriceIDs: []string{"price_team"}}, {Name: "team", PriceID: "price_team"}}, distinct},
		"own base":   {[]stripeplugin.Plan{{Name: "pro", PriceID: "price_new", AnnualPriceID: "price_year", RetiredPriceIDs: []string{"price_year"}}}, distinct},
		"seat":       {[]stripeplugin.Plan{{Name: "pro", PriceID: "price_new", RetiredPriceIDs: []string{"price_member"}}, {Name: "team", PriceID: "price_team", SeatPriceID: "price_member"}}, distinct},
		"add-on":     {[]stripeplugin.Plan{{Name: "pro", PriceID: "price_new", MeteredPriceIDs: []string{"price_usage"}, RetiredPriceIDs: []string{"price_usage"}}}, distinct},
		"bare":       {[]stripeplugin.Plan{{Name: "pro", PriceID: "price_new", RetiredPriceIDs: []string{"price_"}}}, distinct},
		"product":    {[]stripeplugin.Plan{{Name: "pro", PriceID: "price_new", RetiredPriceIDs: []string{"prod_old"}}}, distinct},
		"over 100":   {[]stripeplugin.Plan{{Name: "pro", PriceID: "price_new", RetiredPriceIDs: many}}, "stripe: a plan retires at most 100 prices"},
		"seat plan":  {[]stripeplugin.Plan{{Name: "team", PriceID: "price_team", SeatPriceID: "price_team", RetiredPriceIDs: []string{"price_old"}}}, "stripe: a membership-based plan cannot retire prices"},
	} {
		if err := start(tc.plans...); err == nil || err.Error() != tc.want {
			t.Error("a retired price was handled wrongly", name, err)
		}
	}
	if err := start(stripeplugin.Plan{Name: "pro", PriceID: "price_new", RetiredPriceIDs: many[:100]}); err != nil && strings.Contains(err.Error(), "retire") {
		t.Error("100 retired prices were refused", err)
	}
}

// Subscriptions take Plans or LoadPlans, never both or neither, and a seat
// worker with loaded plans needs no organization options.
func TestPlanSources(t *testing.T) {
	const message = "stripe: subscriptions require a client and either Plans or LoadPlans"
	load := func(context.Context) ([]stripeplugin.Plan, error) { return nil, nil }
	pro := []stripeplugin.Plan{{Name: "pro", PriceID: "price_pro"}}
	for name, opts := range map[string]stripeplugin.SubscriptionOptions{
		"both":    {Client: stripesdk.NewClient("sk_test_local"), Plans: pro, LoadPlans: load},
		"neither": {Client: stripesdk.NewClient("sk_test_local")},
	} {
		_, err := authn.New(authn.Options{Store: memory.New(), BaseURL: "http://auth.test", Secret: "test-secret-0123456789-abcdefghijk",
			Plugins: []authn.Plugin{stripeplugin.New(stripeplugin.Options{WebhookSecret: "whsec_local", Subscriptions: &opts})}})
		if err == nil || err.Error() != message {
			t.Error("a plan source was accepted", name, err)
		}
	}
	worker, err := stripeplugin.NewSeatWorker(seatStoreStub{}, stripeplugin.SubscriptionOptions{Client: stripesdk.NewClient("sk_test_local"), LoadPlans: func(context.Context) ([]stripeplugin.Plan, error) {
		return pro, nil
	}})
	if err != nil {
		t.Fatal("a seat worker with loaded plans was refused", err)
	}
	// A pass whose loaded plans have no membership plan touches no store.
	if err := worker.SyncOnce(t.Context(), 10); err != nil {
		t.Fatal("a pass without membership plans failed", err)
	}
	failing, _ := stripeplugin.NewSeatWorker(seatStoreStub{}, stripeplugin.SubscriptionOptions{Client: stripesdk.NewClient("sk_test_local"), LoadPlans: func(context.Context) ([]stripeplugin.Plan, error) {
		return nil, errors.New("plans unavailable")
	}})
	if err := failing.SyncOnce(t.Context(), 10); err == nil {
		t.Fatal("a pass ignored a loader failure")
	}
}

// seatStoreStub satisfies the seat worker's store for a configuration check.
type seatStoreStub struct{ stripeplugin.SeatStore }

// A plan needs a price ID or a lookup key; keys are unique, trimmed and at
// most 200 bytes, and membership-based plans use price IDs.
func TestPlanLookupKeyConfiguration(t *testing.T) {
	start := func(plans ...stripeplugin.Plan) error {
		_, err := authn.New(authn.Options{Store: memory.New(), BaseURL: "http://auth.test", Secret: "test-secret-0123456789-abcdefghijk",
			Plugins: []authn.Plugin{stripeplugin.New(stripeplugin.Options{WebhookSecret: "whsec_local",
				Organization:  &stripeplugin.OrganizationOptions{AuthorizeReference: func(stripeplugin.ReferenceAuthorization) bool { return true }},
				Subscriptions: &stripeplugin.SubscriptionOptions{Client: stripesdk.NewClient("sk_test_local"), Plans: plans}})}})
		return err
	}
	const key = "stripe: invalid or duplicate price lookup key"
	for name, tc := range map[string]struct {
		plans []stripeplugin.Plan
		want  string
	}{
		"neither":        {[]stripeplugin.Plan{{Name: "pro"}}, "stripe: invalid or duplicate subscription plan"},
		"two plans":      {[]stripeplugin.Plan{{Name: "pro", LookupKey: "monthly"}, {Name: "team", LookupKey: "monthly"}}, key},
		"two intervals":  {[]stripeplugin.Plan{{Name: "pro", LookupKey: "pro", AnnualLookupKey: "pro"}}, key},
		"blank":          {[]stripeplugin.Plan{{Name: "pro", PriceID: "price_pro", AnnualLookupKey: " "}}, key},
		"padded":         {[]stripeplugin.Plan{{Name: "pro", LookupKey: " pro"}}, key},
		"too long":       {[]stripeplugin.Plan{{Name: "pro", LookupKey: strings.Repeat("k", 201)}}, key},
		"membership key": {[]stripeplugin.Plan{{Name: "team", PriceID: "price_team", SeatPriceID: "price_team", LookupKey: "team"}}, "stripe: a membership-based plan requires price IDs"},
	} {
		if err := start(tc.plans...); err == nil || err.Error() != tc.want {
			t.Error("a lookup key was handled wrongly", name, err)
		}
	}
	accepted := func(err error) bool {
		return err == nil || !strings.Contains(err.Error(), "lookup key") && !strings.Contains(err.Error(), "subscription plan")
	}
	if err := start(stripeplugin.Plan{Name: "pro", LookupKey: "pro_monthly", AnnualLookupKey: strings.Repeat("k", 200)}); !accepted(err) {
		t.Error("a key-only plan was refused", err)
	}
}
