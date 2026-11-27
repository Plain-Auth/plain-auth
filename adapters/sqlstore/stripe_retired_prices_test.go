package sqlstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

// A subscription on a retired price keeps its plan at the price's monthly
// or yearly interval; a retired price at another interval is unmapped; a
// purchase never sends a retired price; and a change to the same plan from
// a retired price moves it to the configured price.
func TestStripeRetiredPrices(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			ddl, err := schema.Generate(dialect, []string{"stripe-subscriptions"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			const secret = "whsec_retired_local"
			recurring := map[string]map[string]any{
				"price_pro_v2": {"interval": "month", "interval_count": 1, "usage_type": "licensed"},
				"price_pro_v1": {"interval": "month", "interval_count": 1, "usage_type": "licensed"},
				"price_pro_y1": {"interval": "year", "interval_count": 1, "usage_type": "licensed"},
				"price_pro_q1": {"interval": "month", "interval_count": 3, "usage_type": "licensed"},
			}
			var mu sync.Mutex
			price, period := "price_pro_v1", int64(1000)
			var checkouts, portals []url.Values
			subscription := func() map[string]any {
				return map[string]any{"object": "subscription", "id": "sub_retired", "customer": "cus_retired", "status": "active", "metadata": map[string]string{},
					"items": map[string]any{"object": "list", "has_more": false, "data": []any{map[string]any{"id": "si_retired", "quantity": 1,
						"price": map[string]any{"id": price, "object": "price", "active": true, "recurring": recurring[price]}, "current_period_start": period, "current_period_end": period + 1000}}}}
			}
			transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				if err := r.ParseForm(); err != nil {
					return nil, err
				}
				switch {
				case r.URL.Path == "/v1/subscriptions/sub_retired" && r.Method == "GET":
					return stripeJSON(200, subscription()), nil
				case strings.HasPrefix(r.URL.Path, "/v1/prices/"):
					id := strings.TrimPrefix(r.URL.Path, "/v1/prices/")
					return stripeJSON(200, map[string]any{"id": id, "object": "price", "active": true, "recurring": recurring[id]}), nil
				case r.URL.Path == "/v1/customers" && r.Method == "POST":
					return stripeJSON(200, map[string]any{"id": "cus_retired_buyer", "object": "customer", "metadata": map[string]string{"userId": r.PostForm.Get("metadata[userId]"), "customerType": "user"}}), nil
				case r.URL.Path == "/v1/checkout/sessions" && r.Method == "POST":
					checkouts = append(checkouts, r.PostForm)
					return stripeJSON(200, map[string]any{"id": "cs_retired", "object": "checkout.session", "url": "https://checkout.stripe.test/retired", "status": "open"}), nil
				case r.URL.Path == "/v1/billing_portal/sessions" && r.Method == "POST":
					portals = append(portals, r.PostForm)
					return stripeJSON(200, map[string]any{"id": "bps_retired", "object": "billing_portal.session", "customer": r.PostForm.Get("customer"), "url": "https://billing.stripe.test/retired"}), nil
				}
				return nil, fmt.Errorf("unexpected Stripe call %s %s", r.Method, r.URL.Path)
			})
			remote := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})))
			const origin = "https://billing.example"
			off := false
			a, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off,
				Plugins: []auth.Plugin{billing.New(billing.Options{WebhookSecret: secret, Subscriptions: &billing.SubscriptionOptions{Client: remote, Plans: []billing.Plan{
					{Name: "pro", PriceID: "price_pro_v2", RetiredPriceIDs: []string{"price_pro_v1", "price_pro_y1", "price_pro_q1"}},
				}}})}})
			if err != nil {
				t.Fatal(err)
			}
			hit, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: "retired", Email: "retired@example.test", Password: "local fixture password"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`), "cus_retired", hit.User.ID); err != nil {
				t.Fatal(err)
			}
			events := 0
			deliver := func(kind string) {
				t.Helper()
				events++
				mu.Lock()
				object := subscription()
				mu.Unlock()
				raw, _ := json.Marshal(map[string]any{"id": fmt.Sprintf("evt_retired_%d", events), "object": "event", "api_version": sdk.APIVersion, "created": events, "type": kind, "data": map[string]any{"object": object}})
				r := httptest.NewRequest("POST", origin+"/api/auth/stripe/webhook", bytes.NewReader(raw))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Stripe-Signature", webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: raw, Secret: secret}).Header)
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatal("webhook", kind, w.Code, w.Body.String())
				}
			}
			read := func() billing.Subscription {
				t.Helper()
				row, err := scanStripeSubscription(store.db.QueryRowContext(ctx, store.bind(`SELECT `+subscriptionFields+` FROM "subscription" WHERE "stripeSubscriptionId"=?`), "sub_retired"))
				if err != nil {
					t.Fatal(err)
				}
				return row
			}
			set := func(p string, at int64) {
				mu.Lock()
				price, period = p, at
				mu.Unlock()
			}

			// A monthly and a yearly retired price keep the plan.
			deliver("customer.subscription.created")
			if row := read(); row.Plan != "pro" || row.Status != "active" || row.Interval == nil || *row.Interval != "month" {
				t.Fatalf("a monthly retired price was not mapped: %+v", row)
			}
			set("price_pro_y1", 2000)
			deliver("customer.subscription.updated")
			if row := read(); row.Plan != "pro" || row.Status != "active" || *row.Interval != "year" {
				t.Fatalf("a yearly retired price was not mapped: %+v", row)
			}
			// A retired price at another interval is unmapped.
			set("price_pro_q1", 3000)
			deliver("customer.subscription.updated")
			if row := read(); row.Status != "unmapped" {
				t.Fatalf("a quarterly retired price kept the plan: %+v", row)
			}
			set("price_pro_v1", 4000)
			deliver("customer.subscription.updated")
			if row := read(); row.Status != "active" || *row.Interval != "month" {
				t.Fatalf("a monthly retired price was not mapped again: %+v", row)
			}
			call := func(body map[string]any) (int, map[string]any) {
				t.Helper()
				var src bytes.Buffer
				json.NewEncoder(&src).Encode(body)
				r := httptest.NewRequest("POST", origin+"/api/auth/subscription/upgrade", &src)
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "application/json")
				r.AddCookie(a.SessionCookie(hit.Token, true))
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var out map[string]any
				json.Unmarshal(w.Body.Bytes(), &out)
				return w.Code, out
			}
			// A change to the same plan from a retired price moves it to the
			// configured price instead of answering already subscribed.
			if status, out := call(map[string]any{"plan": "pro", "subscriptionId": "sub_retired", "returnUrl": "/billing", "disableRedirect": true}); status != 200 || out["url"] != "https://billing.stripe.test/retired" {
				t.Fatal("a change from a retired price was refused", status, out)
			}
			mu.Lock()
			form := portals[len(portals)-1]
			mu.Unlock()
			if form.Get("flow_data[subscription_update_confirm][items][0][price]") != "price_pro_v2" {
				t.Fatal("the change did not target the configured price", form)
			}
			// A new purchase sends only the configured price.
			other, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: "buyer", Email: "retired-buyer@example.test", Password: "local fixture password"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			hit = other
			if status, out := call(map[string]any{"plan": "pro", "successUrl": "/done", "cancelUrl": "/cancel", "disableRedirect": true}); status != 200 {
				t.Fatal("upgrade", status, out)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(checkouts) != 1 || checkouts[0].Get("line_items[0][price]") != "price_pro_v2" {
				t.Fatal("a purchase sent a retired price", checkouts)
			}
		})
	}
}
