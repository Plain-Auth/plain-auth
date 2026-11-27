package sqlstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Plain-Org/plain-auth"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
)

// A padded plan name is stored in lowercase; an annual purchase of a plan
// without an annual price answers 400 before Stripe; a price that is not
// monthly or yearly with an interval count of one is refused before any
// row; and a yearly subscription of a plan without an annual price lists
// the monthly price ID.
func TestPlanPriceRules(t *testing.T) {
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
			var mu sync.Mutex
			recurring := map[string]map[string]any{
				"price_pro":     {"interval": "month", "interval_count": 1, "usage_type": "licensed"},
				"price_weekly":  {"interval": "week", "interval_count": 1, "usage_type": "licensed"},
				"price_quarter": {"interval": "month", "interval_count": 3, "usage_type": "licensed"},
			}
			calls := 0
			transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				if err := r.ParseForm(); err != nil {
					return nil, err
				}
				calls++
				switch {
				case strings.HasPrefix(r.URL.Path, "/v1/prices/"):
					id := strings.TrimPrefix(r.URL.Path, "/v1/prices/")
					return stripeJSON(200, map[string]any{"id": id, "object": "price", "active": true, "recurring": recurring[id]}), nil
				case r.URL.Path == "/v1/customers" && r.Method == "POST":
					return stripeJSON(200, map[string]any{"id": "cus_rules", "object": "customer", "metadata": map[string]string{"userId": r.PostForm.Get("metadata[userId]"), "customerType": "user"}}), nil
				case r.URL.Path == "/v1/checkout/sessions" && r.Method == "POST":
					return stripeJSON(200, map[string]any{"id": "cs_rules", "object": "checkout.session", "url": "https://checkout.stripe.test/rules", "status": "open"}), nil
				}
				return nil, fmt.Errorf("unexpected Stripe call %s %s", r.Method, r.URL.Path)
			})
			remote := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})))
			const origin = "https://billing.example"
			off := false
			a, err := plainauth.New(plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off,
				Plugins: []plainauth.Plugin{billing.New(billing.Options{WebhookSecret: "whsec_rules", Subscriptions: &billing.SubscriptionOptions{Client: remote, Plans: []billing.Plan{
					{Name: " Pro ", PriceID: "price_pro"}, {Name: "weekly", PriceID: "price_weekly"}, {Name: "quarter", PriceID: "price_quarter"},
				}}})}})
			if err != nil {
				t.Fatal(err)
			}
			users := 0
			buyer := func() (*http.Cookie, string) {
				t.Helper()
				users++
				hit, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: "rules", Email: fmt.Sprintf("rules%d@example.test", users), Password: "local fixture password"}, plainauth.RequestMeta{})
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
			rows := func(owner string) int {
				t.Helper()
				var n int
				if err := store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "subscription" WHERE "referenceId"=?`), owner).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			stripeCalls := func() int {
				mu.Lock()
				defer mu.Unlock()
				return calls
			}

			// A padded name matches the request in any case and is stored in lowercase.
			cookie, owner := buyer()
			if status, out, _ := call(cookie, "POST", "/subscription/upgrade", map[string]any{"plan": "PRO", "successUrl": "/done", "cancelUrl": "/cancel", "disableRedirect": true}); status != 200 {
				t.Fatal("upgrade", status, out)
			}
			var plan string
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "plan" FROM "subscription" WHERE "referenceId"=?`), owner).Scan(&plan); err != nil || plan != "pro" {
				t.Fatal("the plan name was not stored in lowercase", plan, err)
			}
			// An annual purchase without an annual price answers 400 with no code.
			fresh, freshID := buyer()
			before := stripeCalls()
			if status, out, _ := call(fresh, "POST", "/subscription/upgrade", map[string]any{"plan": "pro", "annual": true, "successUrl": "/done", "cancelUrl": "/cancel"}); status != 400 || out["message"] != "Price ID not found for the selected plan" || out["code"] != nil || stripeCalls() != before || rows(freshID) != 0 {
				t.Fatal("an annual purchase without an annual price was not refused before Stripe", status, out)
			}
			// Weekly and quarterly prices are refused before any row.
			for _, name := range []string{"weekly", "quarter"} {
				if status, out, _ := call(fresh, "POST", "/subscription/upgrade", map[string]any{"plan": name, "successUrl": "/done", "cancelUrl": "/cancel"}); status != 409 || out["code"] != "UNSUPPORTED_SUBSCRIPTION_ITEM" || out["message"] != "Checkout requires an active recurring price with the selected interval" || rows(freshID) != 0 {
					t.Fatal("a price at another interval was accepted", name, status, out)
				}
			}
			// A yearly subscription of a plan without an annual price lists the monthly price.
			listed, listedID := buyer()
			if _, err := store.db.ExecContext(ctx, store.bind(`INSERT INTO "subscription" ("id","plan","referenceId","status","billingInterval","seats") VALUES (?,?,?,?,?,?)`), "sub-rules-year", "pro", listedID, "active", "year", 1); err != nil {
				t.Fatal(err)
			}
			status, _, raw := call(listed, "GET", "/subscription/list", nil)
			var list []map[string]any
			if status != 200 || json.Unmarshal(raw, &list) != nil || len(list) != 1 || list[0]["priceId"] != "price_pro" || list[0]["billingInterval"] != "year" {
				t.Fatal("a yearly subscription without an annual price did not list the monthly price", status, string(raw))
			}
		})
	}
}
