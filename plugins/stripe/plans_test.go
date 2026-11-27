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
