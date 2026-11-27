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

// A plan's lookup key selects the active price holding it before each new
// purchase or plan change, ahead of its price ID; a pending purchase keeps
// its price across a key transfer and a lookup outage; a failed lookup for a
// new purchase answers 502, a key-only plan without a price 400, and a key
// resolving to another plan's price 409; and a subscription Stripe reports
// on the key's price maps to the plan.
func TestStripePriceLookupKeys(t *testing.T) {
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
			const secret = "whsec_lookup_local"
			intervals := map[string]string{"price_pro_1": "month", "price_pro_2": "month", "price_pro_year": "year", "price_plus": "month", "price_basic": "month", "price_pro_9": "month"}
			recurring := func(id string) map[string]any {
				return map[string]any{"interval": intervals[id], "interval_count": 1, "usage_type": "licensed"}
			}
			var mu sync.Mutex
			keys := map[string]string{"pro_monthly": "price_pro_1", "pro_annual": "price_pro_year"}
			lookupFails, loseCheckout := false, false
			lookups := 0
			var queries []url.Values
			var checkouts []url.Values
			var idempotency []string
			var portals []url.Values
			subscriptionPrice := "price_basic"
			transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				if err := r.ParseForm(); err != nil {
					return nil, err
				}
				switch {
				case r.URL.Path == "/v1/prices" && r.Method == "GET":
					lookups++
					queries = append(queries, r.URL.Query())
					if lookupFails {
						return stripeJSON(500, map[string]any{"error": map[string]string{"type": "api_error"}}), nil
					}
					key := r.URL.Query().Get("lookup_keys[0]")
					var data []any
					if id := keys[key]; id != "" {
						data = []any{map[string]any{"id": id, "object": "price", "active": true, "lookup_key": key, "recurring": recurring(id)}}
					}
					return stripeJSON(200, map[string]any{"object": "list", "url": "/v1/prices", "has_more": false, "data": data}), nil
				case strings.HasPrefix(r.URL.Path, "/v1/prices/"):
					id := strings.TrimPrefix(r.URL.Path, "/v1/prices/")
					return stripeJSON(200, map[string]any{"id": id, "object": "price", "active": true, "recurring": recurring(id)}), nil
				case r.URL.Path == "/v1/customers" && r.Method == "POST":
					return stripeJSON(200, map[string]any{"id": "cus_lookup_" + r.PostForm.Get("metadata[userId]"), "object": "customer", "metadata": map[string]string{"userId": r.PostForm.Get("metadata[userId]"), "customerType": "user"}}), nil
				case r.URL.Path == "/v1/checkout/sessions" && r.Method == "POST":
					checkouts, idempotency = append(checkouts, r.PostForm), append(idempotency, r.Header.Get("Idempotency-Key"))
					if loseCheckout {
						return stripeJSON(500, map[string]any{"error": map[string]string{"type": "api_error"}}), nil
					}
					id := fmt.Sprintf("cs_lookup_%d", len(checkouts))
					return stripeJSON(200, map[string]any{"id": id, "object": "checkout.session", "url": "https://checkout.stripe.test/" + id, "status": "open"}), nil
				case strings.HasPrefix(r.URL.Path, "/v1/checkout/sessions/") && r.Method == "GET":
					id := strings.TrimPrefix(r.URL.Path, "/v1/checkout/sessions/")
					return stripeJSON(200, map[string]any{"id": id, "object": "checkout.session", "url": "https://checkout.stripe.test/" + id, "status": "open"}), nil
				case r.URL.Path == "/v1/subscriptions/sub_lookup" && r.Method == "GET":
					item := map[string]any{"id": "si_lookup", "quantity": 1, "current_period_start": 1000, "current_period_end": 2000,
						"price": map[string]any{"id": subscriptionPrice, "object": "price", "active": true, "lookup_key": map[string]string{"price_pro_9": "pro_monthly"}[subscriptionPrice], "recurring": recurring(subscriptionPrice)}}
					return stripeJSON(200, map[string]any{"object": "subscription", "id": "sub_lookup", "customer": "cus_lookup_owner", "status": "active", "metadata": map[string]string{},
						"items": map[string]any{"object": "list", "has_more": false, "data": []any{item}}}), nil
				case r.URL.Path == "/v1/billing_portal/sessions" && r.Method == "POST":
					portals = append(portals, r.PostForm)
					return stripeJSON(200, map[string]any{"id": "bps_lookup", "object": "billing_portal.session", "customer": r.PostForm.Get("customer"), "url": "https://billing.stripe.test/lookup"}), nil
				}
				return nil, fmt.Errorf("unexpected Stripe call %s %s", r.Method, r.URL.Path)
			})
			remote := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})))
			const origin = "https://billing.example"
			off := false
			a, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off,
				Plugins: []auth.Plugin{billing.New(billing.Options{WebhookSecret: secret, Subscriptions: &billing.SubscriptionOptions{Client: remote, Plans: []billing.Plan{
					{Name: "pro", LookupKey: "pro_monthly", AnnualLookupKey: "pro_annual"},
					{Name: "plus", PriceID: "price_plus", LookupKey: "plus_monthly"},
					{Name: "basic", PriceID: "price_basic"},
				}}})}})
			if err != nil {
				t.Fatal(err)
			}
			users := 0
			buyer := func() (*http.Cookie, string) {
				t.Helper()
				users++
				hit, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: "lookup", Email: fmt.Sprintf("lookup%d@example.test", users), Password: "local fixture password"}, auth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				return a.SessionCookie(hit.Token, true), hit.User.ID
			}
			call := func(cookie *http.Cookie, method, path string, body map[string]any) (int, map[string]any, []byte) {
				t.Helper()
				var src bytes.Buffer
				if body != nil {
					json.NewEncoder(&src).Encode(body)
				}
				r := httptest.NewRequest(method, origin+"/api/auth"+path, &src)
				r.Header.Set("Origin", origin)
				if body != nil {
					r.Header.Set("Content-Type", "application/json")
				}
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var out map[string]any
				json.Unmarshal(w.Body.Bytes(), &out)
				return w.Code, out, w.Body.Bytes()
			}
			upgrade := func(cookie *http.Cookie, plan string, annual bool) (int, map[string]any) {
				t.Helper()
				status, out, _ := call(cookie, "POST", "/subscription/upgrade", map[string]any{"plan": plan, "annual": annual, "successUrl": "/done", "cancelUrl": "/cancel", "disableRedirect": true})
				return status, out
			}
			state := func() (int, string, string) {
				mu.Lock()
				defer mu.Unlock()
				return lookups, checkouts[len(checkouts)-1].Get("line_items[0][price]"), idempotency[len(idempotency)-1]
			}
			rows := func(owner string) int {
				t.Helper()
				var n int
				if err := store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "subscription" WHERE "referenceId"=?`), owner).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}

			// The monthly key's price is sold; a retry after a lost response
			// sends the same request with no second lookup.
			first, _ := buyer()
			loseCheckout = true
			if status, _ := upgrade(first, "pro", false); status != 502 {
				t.Fatal("a lost Checkout was not kept", status)
			}
			mu.Lock()
			loseCheckout = false
			if q := queries[0]; q.Get("lookup_keys[0]") != "pro_monthly" || q.Get("active") != "true" || q.Get("limit") != "1" {
				t.Fatal("the lookup was not the exact query", q)
			}
			mu.Unlock()
			seen, sent, key := state()
			if status, out := upgrade(first, "pro", false); status != 200 {
				t.Fatal("retry", status, out)
			}
			if again, resent, rekey := state(); again != seen || sent != "price_pro_1" || resent != sent || rekey != key {
				t.Fatal("a retry looked up or changed the price", seen, again, sent, resent, key, rekey)
			}
			// The key moves to a new price: the pending purchase reopens during
			// a lookup outage, and a new buyer gets the new price.
			mu.Lock()
			keys["pro_monthly"], lookupFails = "price_pro_2", true
			mu.Unlock()
			if status, out := upgrade(first, "pro", false); status != 200 || out["url"] != "https://checkout.stripe.test/cs_lookup_2" {
				t.Fatal("a pending purchase did not reopen after a key transfer", status, out)
			}
			mu.Lock()
			lookupFails = false
			mu.Unlock()
			second, _ := buyer()
			if status, _ := upgrade(second, "pro", false); status != 200 {
				t.Fatal("upgrade after transfer", status)
			}
			if _, sent, _ := state(); sent != "price_pro_2" {
				t.Fatal("a new purchase did not sell the transferred key's price", sent)
			}
			// The annual key, and a configured ID when the key finds nothing.
			third, _ := buyer()
			if status, _ := upgrade(third, "pro", true); status != 200 {
				t.Fatal("annual upgrade", status)
			}
			if _, sent, _ := state(); sent != "price_pro_year" {
				t.Fatal("the annual key's price was not sold", sent)
			}
			fourth, _ := buyer()
			if status, _ := upgrade(fourth, "plus", false); status != 200 {
				t.Fatal("plus upgrade", status)
			}
			if _, sent, _ := state(); sent != "price_plus" {
				t.Fatal("an empty lookup did not fall back to the price ID", sent)
			}
			// A failed lookup answers 502, a key-only plan without a price 400,
			// and a key resolving to another plan's price 409, with no row.
			fifth, fifthID := buyer()
			mu.Lock()
			lookupFails = true
			mu.Unlock()
			if status, out := upgrade(fifth, "plus", false); status != 502 || out["code"] != "STRIPE_PRICE_UNAVAILABLE" || rows(fifthID) != 0 {
				t.Fatal("a failed lookup was not refused", status, out)
			}
			mu.Lock()
			lookupFails = false
			delete(keys, "pro_monthly")
			mu.Unlock()
			if status, out := upgrade(fifth, "pro", false); status != 400 || out["message"] != "Price ID not found for the selected plan" || rows(fifthID) != 0 {
				t.Fatal("a key-only plan without a price was not refused", status, out)
			}
			mu.Lock()
			keys["pro_monthly"] = "price_basic"
			mu.Unlock()
			if status, out := upgrade(fifth, "pro", false); status != 409 || out["code"] != "UNSUPPORTED_SUBSCRIPTION_ITEM" || rows(fifthID) != 0 {
				t.Fatal("a key resolving to another plan's price was accepted", status, out)
			}
			mu.Lock()
			keys["pro_monthly"] = "price_pro_2"
			mu.Unlock()
			// A subscription on an unconfigured price holding the key maps to
			// the plan, and a key-only plan lists no price ID.
			owner, ownerID := buyer()
			if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`), "cus_lookup_owner", ownerID); err != nil {
				t.Fatal(err)
			}
			deliver := func(id string) {
				t.Helper()
				mu.Lock()
				object := map[string]any{"object": "subscription", "id": "sub_lookup", "customer": "cus_lookup_owner"}
				mu.Unlock()
				raw, _ := json.Marshal(map[string]any{"id": id, "object": "event", "api_version": sdk.APIVersion, "created": 1, "type": "customer.subscription.updated", "data": map[string]any{"object": object}})
				r := httptest.NewRequest("POST", origin+"/api/auth/stripe/webhook", bytes.NewReader(raw))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Stripe-Signature", webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: raw, Secret: secret}).Header)
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatal("webhook", w.Code, w.Body.String())
				}
			}
			mu.Lock()
			subscriptionPrice = "price_pro_9"
			mu.Unlock()
			deliver("evt_lookup_key")
			status, _, raw := call(owner, "GET", "/subscription/list", nil)
			var list []map[string]any
			if status != 200 || json.Unmarshal(raw, &list) != nil || len(list) != 1 || list[0]["plan"] != "pro" || list[0]["billingInterval"] != "month" {
				t.Fatal("a price holding the key did not map to the plan", status, string(raw))
			}
			if _, has := list[0]["priceId"]; has {
				t.Fatal("a key-only plan listed a price ID", list[0])
			}
			// A change from basic to pro targets the key's current price.
			mu.Lock()
			subscriptionPrice = "price_basic"
			mu.Unlock()
			deliver("evt_lookup_basic")
			if status, out, _ := call(owner, "POST", "/subscription/upgrade", map[string]any{"plan": "pro", "subscriptionId": "sub_lookup", "returnUrl": "/billing", "disableRedirect": true}); status != 200 {
				t.Fatal("plan change", status, out)
			}
			mu.Lock()
			target := portals[len(portals)-1].Get("flow_data[subscription_update_confirm][items][0][price]")
			mu.Unlock()
			if target != "price_pro_2" {
				t.Fatal("the plan change did not target the key's price", target)
			}
		})
	}
}
