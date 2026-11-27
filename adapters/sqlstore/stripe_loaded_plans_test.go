package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

// LoadPlans runs outside any store transaction for each subscription
// request and plan webhook, not for other events; a changed price is sold
// at once while a retired one keeps its subscribers; and a failing,
// panicking or invalid loader answers 500 FAILED_TO_FETCH_PLANS.
func TestLoadedStripePlans(t *testing.T) {
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
			const secret = "whsec_loaded_local"
			recurring := map[string]any{"interval": "month", "interval_count": 1, "usage_type": "licensed"}
			var mu sync.Mutex
			price := "price_pro_v1"
			var checkouts []url.Values
			subscription := func() map[string]any {
				return map[string]any{"object": "subscription", "id": "sub_loaded", "customer": "cus_loaded", "status": "active", "metadata": map[string]string{},
					"items": map[string]any{"object": "list", "has_more": false, "data": []any{map[string]any{"id": "si_loaded", "quantity": 1,
						"price": map[string]any{"id": price, "object": "price", "active": true, "recurring": recurring}, "current_period_start": 1000, "current_period_end": 2000}}}}
			}
			transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				if err := r.ParseForm(); err != nil {
					return nil, err
				}
				switch {
				case r.URL.Path == "/v1/subscriptions/sub_loaded" && r.Method == "GET":
					return stripeJSON(200, subscription()), nil
				case strings.HasPrefix(r.URL.Path, "/v1/prices/"):
					return stripeJSON(200, map[string]any{"id": strings.TrimPrefix(r.URL.Path, "/v1/prices/"), "object": "price", "active": true, "recurring": recurring}), nil
				case r.URL.Path == "/v1/customers" && r.Method == "POST":
					return stripeJSON(200, map[string]any{"id": "cus_loaded_buyer", "object": "customer", "metadata": map[string]string{"userId": r.PostForm.Get("metadata[userId]"), "customerType": "user"}}), nil
				case r.URL.Path == "/v1/checkout/sessions" && r.Method == "POST":
					checkouts = append(checkouts, r.PostForm)
					return stripeJSON(200, map[string]any{"id": "cs_loaded", "object": "checkout.session", "url": "https://checkout.stripe.test/loaded", "status": "open"}), nil
				}
				return nil, fmt.Errorf("unexpected Stripe call %s %s", r.Method, r.URL.Path)
			})
			remote := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})))
			var loadMu sync.Mutex
			calls := 0
			var owner string
			plans := []billing.Plan{{Name: "pro", PriceID: "price_pro_v1"}}
			var loadErr error
			panics := false
			load := func(ctx context.Context) ([]billing.Plan, error) {
				// No owner lock is held while plans load.
				if owner != "" {
					probe, cancel := context.WithTimeout(ctx, 2*time.Second)
					defer cancel()
					if _, err := store.db.ExecContext(probe, store.bind(`UPDATE "user" SET "name"="name" WHERE "id"=?`), owner); err != nil {
						return nil, err
					}
				}
				loadMu.Lock()
				defer loadMu.Unlock()
				calls++
				if panics {
					panic("loader panic")
				}
				return plans, loadErr
			}
			set := func(p []billing.Plan, err error, panic bool) {
				loadMu.Lock()
				defer loadMu.Unlock()
				plans, loadErr, panics, calls = p, err, panic, 0
			}
			count := func() int {
				loadMu.Lock()
				defer loadMu.Unlock()
				return calls
			}
			const origin = "https://billing.example"
			off := false
			a, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off,
				Plugins: []auth.Plugin{billing.New(billing.Options{WebhookSecret: secret, Subscriptions: &billing.SubscriptionOptions{Client: remote, LoadPlans: load}})}})
			if err != nil {
				t.Fatal(err)
			}
			hit, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: "loaded", Email: "loaded@example.test", Password: "local fixture password"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			owner = hit.User.ID
			if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`), "cus_loaded", owner); err != nil {
				t.Fatal(err)
			}
			events := 0
			deliver := func(kind string, object map[string]any) int {
				t.Helper()
				events++
				raw, _ := json.Marshal(map[string]any{"id": fmt.Sprintf("evt_loaded_%d", events), "object": "event", "api_version": sdk.APIVersion, "created": events, "type": kind, "data": map[string]any{"object": object}})
				r := httptest.NewRequest("POST", origin+"/api/auth/stripe/webhook", bytes.NewReader(raw))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Stripe-Signature", webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: raw, Secret: secret}).Header)
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				return w.Code
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
			cookie := a.SessionCookie(hit.Token, true)
			read := func() billing.Subscription {
				t.Helper()
				row, err := scanStripeSubscription(store.db.QueryRowContext(ctx, store.bind(`SELECT `+subscriptionFields+` FROM "subscription" WHERE "stripeSubscriptionId"=?`), "sub_loaded"))
				if err != nil {
					t.Fatal(err)
				}
				return row
			}
			listed := func() []map[string]any {
				t.Helper()
				status, _, raw := call(cookie, "GET", "/subscription/list", nil)
				var rows []map[string]any
				if status != 200 || json.Unmarshal(raw, &rows) != nil {
					t.Fatal("list", status, string(raw))
				}
				return rows
			}

			// A plan webhook loads the plans once; another event does not.
			if code := deliver("customer.subscription.created", subscription()); code != 200 || count() != 1 || read().Plan != "pro" || read().Status != "active" {
				t.Fatal("a plan webhook did not load the plans once", code, count())
			}
			set(plans, nil, false)
			if code := deliver("invoice.paid", map[string]any{"object": "invoice", "id": "in_loaded"}); code != 200 || count() != 0 {
				t.Fatal("another event loaded the plans", code, count())
			}
			// The plans move to a new price, keeping the old one retired: the
			// subscriber stays on its plan and the new price lists at once.
			set([]billing.Plan{{Name: "pro", PriceID: "price_pro_v2", RetiredPriceIDs: []string{"price_pro_v1"}}}, nil, false)
			if code := deliver("customer.subscription.updated", subscription()); code != 200 || read().Status != "active" || read().Plan != "pro" {
				t.Fatal("a retired price lost its plan", code, read().Status)
			}
			if rows := listed(); len(rows) != 1 || rows[0]["priceId"] != "price_pro_v2" || count() != 2 {
				t.Fatal("the list did not use the loaded plans", rows, count())
			}
			// Without the retired entry, the old price is unmapped.
			set([]billing.Plan{{Name: "pro", PriceID: "price_pro_v2"}}, nil, false)
			if code := deliver("customer.subscription.updated", subscription()); code != 200 || read().Status != "unmapped" {
				t.Fatal("an unlisted old price kept its plan", code, read().Status)
			}
			// A purchase sells the loaded price.
			other, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: "buyer", Email: "loaded-buyer@example.test", Password: "local fixture password"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			buyer := a.SessionCookie(other.Token, true)
			if status, out, _ := call(buyer, "POST", "/subscription/upgrade", map[string]any{"plan": "pro", "successUrl": "/done", "cancelUrl": "/cancel", "disableRedirect": true}); status != 200 {
				t.Fatal("upgrade", status, out)
			}
			mu.Lock()
			sent := checkouts[len(checkouts)-1].Get("line_items[0][price]")
			mu.Unlock()
			if sent != "price_pro_v2" {
				t.Fatal("a purchase did not sell the loaded price", sent)
			}
			// A failing, panicking or invalid loader answers 500 FAILED_TO_FETCH_PLANS.
			for name, tc := range map[string]struct {
				plans []billing.Plan
				err   error
				panic bool
			}{
				"error":      {nil, errors.New("plans unavailable"), false},
				"panic":      {nil, nil, true},
				"duplicate":  {[]billing.Plan{{Name: "Pro", PriceID: "price_a"}, {Name: "pro", PriceID: "price_b"}}, nil, false},
				"seats":      {[]billing.Plan{{Name: "team", PriceID: "price_team", SeatPriceID: "price_team"}}, nil, false},
				"free trial": {[]billing.Plan{{Name: "pro", PriceID: "price_pro_v2", FreeTrial: &billing.FreeTrial{Days: 0}}}, nil, false},
			} {
				set(tc.plans, tc.err, tc.panic)
				if status, out, _ := call(buyer, "POST", "/subscription/upgrade", map[string]any{"plan": "pro", "successUrl": "/done", "cancelUrl": "/cancel"}); status != 500 || out["code"] != "FAILED_TO_FETCH_PLANS" {
					t.Error("a broken loader did not refuse the upgrade", name, status, out)
				}
				if status, out, _ := call(cookie, "GET", "/subscription/list", nil); status != 500 || out["code"] != "FAILED_TO_FETCH_PLANS" {
					t.Error("a broken loader did not refuse the list", name, status, out)
				}
				if code := deliver("customer.subscription.updated", subscription()); code != 500 {
					t.Error("a broken loader acknowledged a plan webhook", name, code)
				}
			}
		})
	}
}
