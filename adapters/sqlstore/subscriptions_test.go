package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/FineStack/finestack-auth"
	billing "github.com/FineStack/finestack-auth/plugins/stripe"
	"github.com/FineStack/finestack-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

type localBillingTransport func(*http.Request) (*http.Response, error)

func (f localBillingTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func stripeJSON(status int, body any) *http.Response {
	raw, _ := json.Marshal(body)
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw))}
}

func TestSubscriptionCheckout(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"stripe-subscriptions"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			second, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			var mu sync.Mutex
			var owner string
			var customerRequests, sessionRequests, retrievals int
			var customerKey, checkoutKey string
			var meta map[string]string
			expectedCustomer := "cus_local"
			lostResponse := true
			var activePrice string
			round := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				if err := r.ParseForm(); err != nil {
					return nil, err
				}
				key := r.Header.Get("Idempotency-Key")
				switch r.URL.Path {
				case "/v1/customers":
					if key == "" || r.Form.Get("metadata[userId]") != owner || r.Form.Get("metadata[customerType]") != "user" {
						return nil, fmt.Errorf("incorrect customer association")
					}
					if customerKey != "" && customerKey != key {
						return nil, fmt.Errorf("different customer retry key")
					}
					customerKey = key
					customerRequests++
					return stripeJSON(200, map[string]any{"id": "cus_local", "object": "customer", "metadata": map[string]string{"userId": owner, "customerType": "user"}}), nil
				case "/v1/checkout/sessions":
					if r.Form.Get("customer") != expectedCustomer || r.Form.Get("mode") != "subscription" || r.Form.Get("client_reference_id") != owner || r.Form.Get("success_url") != "https://billing.example/success" || r.Form.Get("cancel_url") != "https://billing.example/cancel" || r.Form.Get("line_items[0][quantity]") != "1" || key == "" {
						return nil, fmt.Errorf("incorrect checkout form")
					}
					for _, k := range []string{"userId", "referenceId", "subscriptionId", "checkoutAttemptId"} {
						if r.Form.Get("metadata["+k+"]") == "" || r.Form.Get("metadata["+k+"]") != r.Form.Get("subscription_data[metadata]["+k+"]") {
							return nil, fmt.Errorf("inconsistent reference metadata")
						}
					}
					meta = map[string]string{}
					for _, k := range []string{"userId", "referenceId", "subscriptionId", "checkoutAttemptId"} {
						meta[k] = r.Form.Get("metadata[" + k + "]")
					}
					if checkoutKey != "" && checkoutKey != key {
						return nil, fmt.Errorf("different checkout retry key")
					}
					checkoutKey = key
					sessionRequests++
					activePrice = r.Form.Get("line_items[0][price]")
					if lostResponse {
						lostResponse = false
						return nil, fmt.Errorf("local timeout after Stripe creates checkout")
					}
					return stripeJSON(200, map[string]any{"id": "cs_local", "object": "checkout.session", "url": "https://checkout.stripe.test/local"}), nil
				case "/v1/subscriptions/sub_local":
					retrievals++
					return stripeJSON(200, map[string]any{"id": "sub_local", "object": "subscription", "customer": "cus_local", "metadata": meta, "status": "trialing", "trial_start": 1234, "trial_end": 2345, "items": map[string]any{"data": []any{map[string]any{"quantity": 1, "price": map[string]string{"id": activePrice}, "current_period_start": 1234, "current_period_end": 3456}}}}), nil
				default:
					return nil, fmt.Errorf("unexpected Stripe call %s", r.URL.Path)
				}
			})
			backends := sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: round}, MaxNetworkRetries: sdk.Int64(0)})
			const secret = "whsec_local_recurring_test"
			const origin = "https://billing.example"
			plugin := billing.New(billing.Options{WebhookSecret: secret, Subscriptions: &billing.SubscriptionOptions{Client: sdk.NewClient("sk_test_local", sdk.WithBackends(backends)), Plans: []billing.Plan{{Name: "Pro", PriceID: "price_month", AnnualPriceID: "price_year"}}}})
			off := false
			opts := auth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("x", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []auth.Plugin{plugin}}
			first, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			opts.Store = second
			other, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			signup := func(name string) (auth.AuthResult, *http.Cookie) {
				hit, err := first.SignUpEmail(ctx, auth.SignUpInput{Name: name, Email: name + "@example.test", Password: "local fixture password"}, auth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				return hit, first.SessionCookie(hit.Token, true)
			}
			user, cookie := signup("owner")
			owner = user.User.ID
			otherUser, foreign := signup("other")
			request := func(a *auth.Auth, path string, body map[string]any, c *http.Cookie) (int, []byte) {
				var src bytes.Buffer
				method := "GET"
				if body != nil {
					method = "POST"
					json.NewEncoder(&src).Encode(body)
				}
				r := httptest.NewRequest(method, origin+"/api/auth/subscription/"+path, &src)
				r.Header.Set("Origin", origin)
				if body != nil {
					r.Header.Set("Content-Type", "application/json")
				}
				if c != nil {
					r.AddCookie(c)
				}
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				return w.Code, w.Body.Bytes()
			}
			body := map[string]any{"plan": "PRO", "annual": true, "successUrl": "/success", "cancelUrl": "/cancel", "disableRedirect": true}
			check := func(want int, a *auth.Auth, path string, body map[string]any, c *http.Cookie) []byte {
				t.Helper()
				status, data := request(a, path, body, c)
				if status != want {
					t.Fatalf("%s returned %d expected %d: %s", path, status, want, data)
				}
				return data
			}
			check(401, first, "upgrade", body, nil)
			check(403, first, "upgrade", map[string]any{"plan": "pro", "referenceId": owner}, foreign)
			check(403, first, "list?referenceId="+owner, nil, foreign)
			check(403, first, "upgrade", map[string]any{"plan": "pro", "successUrl": "https://untrusted.example/done"}, cookie)
			check(403, first, "upgrade", map[string]any{"plan": "pro", "cancelUrl": "https://untrusted.example/cancel"}, cookie)
			check(400, first, "upgrade", map[string]any{"plan": "pro", "priceId": "price_untrusted"}, cookie)
			check(400, first, "upgrade", map[string]any{"plan": "absent"}, cookie)
			if customerRequests+sessionRequests != 0 {
				t.Fatal("invalid requests reached Stripe")
			}
			check(502, first, "upgrade", body, cookie)
			if got := string(check(200, first, "list", nil, cookie)); strings.TrimSpace(got) != "[]" {
				t.Fatal("incomplete checkout granted a subscription")
			}
			statuses := make(chan int, 2)
			for _, a := range []*auth.Auth{first, other} {
				go func(a *auth.Auth) { code, _ := request(a, "upgrade", body, cookie); statuses <- code }(a)
			}
			if a, b := <-statuses, <-statuses; a != 200 || b != 200 {
				t.Fatalf("retry statuses %d and %d", a, b)
			}
			recorded := sessionRequests
			got := check(200, other, "upgrade", body, cookie)
			if !bytes.Contains(got, []byte(`"redirect":false`)) || !bytes.Contains(got, []byte("cs_local")) || customerRequests != 1 || sessionRequests != recorded || activePrice != "price_year" {
				t.Fatal("checkout retry or configured price was incorrect")
			}
			check(409, first, "upgrade", map[string]any{"plan": "pro"}, cookie)
			count := func(expected int, q string, args ...any) {
				t.Helper()
				var n int
				if err := store.db.QueryRowContext(ctx, store.bind(q), args...).Scan(&n); err != nil || n != expected {
					t.Fatalf("%s returned %d expected %d: %v", q, n, expected, err)
				}
			}
			count(1, `SELECT COUNT(*) FROM "subscription" WHERE "referenceId"=? AND "status"='incomplete' AND "stripeCustomerId"='cus_local'`, owner)
			send := func(event, customer string, signed bool) int {
				payload, _ := json.Marshal(map[string]any{"id": "evt_local", "object": "event", "api_version": sdk.APIVersion, "type": event, "data": map[string]any{"object": map[string]any{"id": "cs_local", "object": "checkout.session", "mode": "subscription", "metadata": meta, "client_reference_id": owner, "customer": customer, "subscription": "sub_local"}}})
				r := httptest.NewRequest("POST", origin+"/api/auth/stripe/webhook", bytes.NewReader(payload))
				r.Header.Set("Content-Type", "application/json")
				if signed {
					signature := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: payload, Secret: secret})
					r.Header.Set("Stripe-Signature", signature.Header)
				}
				w := httptest.NewRecorder()
				other.ServeHTTP(w, r)
				return w.Code
			}
			if code := send("checkout.session.completed", "cus_local", false); code != 400 {
				t.Fatal("unsigned checkout was accepted")
			}
			if code := send("checkout.session.completed", "cus_other", true); code != 500 {
				t.Fatal("foreign customer was accepted")
			}
			if retrievals != 0 {
				t.Fatal("foreign receipt triggered a subscription fetch")
			}
			if code := send("checkout.session.completed", "cus_local", true); code != 200 {
				t.Fatal("matching signed completion failed", code)
			}
			if code := send("checkout.session.completed", "cus_local", true); code != 200 || retrievals != 1 {
				t.Fatal("receipt retry repeated side effects")
			}
			var rows []billing.Subscription
			if err := json.Unmarshal(check(200, first, "list", nil, cookie), &rows); err != nil || len(rows) != 1 || rows[0].PriceID != "price_year" || rows[0].Status != "trialing" || rows[0].PeriodEnd == nil || rows[0].PeriodEnd.Unix() != 3456 {
				t.Fatalf("unexpected active subscriptions: %+v %v", rows, err)
			}
			if got := string(check(200, other, "list", nil, foreign)); strings.TrimSpace(got) != "[]" {
				t.Fatal("another account's subscription was listed")
			}
			check(409, first, "upgrade", body, cookie)
			// Reconciliation releases exactly the expired attempt. A delayed expiry
			// from an older checkout cannot close the replacement reservation.
			otherWant := billing.CheckoutAttempt{Plan: "pro", Interval: "month", Price: "price_month", SuccessURL: origin + "/s", CancelURL: origin + "/c"}
			start := time.Now().UTC()
			stale, err := store.ReserveStripeCheckout(ctx, otherUser.User.ID, otherUser.Token, otherWant, start)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = store.ReserveStripeCheckout(ctx, otherUser.User.ID, otherUser.Token, otherWant, start.Add(23*time.Hour+time.Second)); err != billing.ErrCheckoutReconcile {
				t.Fatal("ambiguous expired checkout was recreated", err)
			}
			if err = store.BindStripeCheckoutCustomer(ctx, stale, otherUser.Token, "cus_local", start); err != billing.ErrCheckoutReconcile {
				t.Fatal("duplicate customer was bound", err)
			}
			count(0, `SELECT COUNT(*) FROM "user" WHERE "id"=? AND "stripeCustomerId" IS NOT NULL`, otherUser.User.ID)
			if err = store.BindStripeCheckoutCustomer(ctx, stale, otherUser.Token, "cus_other", start); err != nil {
				t.Fatal(err)
			}
			stale.Customer = "cus_other"
			if err = store.SaveStripeCheckoutResult(ctx, stale, otherUser.Token, "cs_other", "https://checkout.stripe.test/other", start); err != nil {
				t.Fatal(err)
			}
			meta = map[string]string{"checkoutAttemptId": stale.ID, "referenceId": stale.Owner, "userId": stale.Owner, "subscriptionId": stale.LocalSubscription}
			expiredObject := map[string]any{"id": "cs_other", "object": "checkout.session", "mode": "subscription", "customer": stale.Customer, "client_reference_id": stale.Owner, "metadata": meta}
			raw, _ := json.Marshal(map[string]any{"id": "evt_expired", "object": "event", "api_version": sdk.APIVersion, "type": "checkout.session.expired", "data": map[string]any{"object": expiredObject}})
			sign := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: raw, Secret: secret})
			notifyExpiry := func() {
				t.Helper()
				r := httptest.NewRequest("POST", origin+"/api/auth/stripe/webhook", bytes.NewReader(raw))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Stripe-Signature", sign.Header)
				w := httptest.NewRecorder()
				first.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatalf("expiry not applied: %d %s", w.Code, w.Body)
				}
			}
			notifyExpiry()
			count(1, `SELECT COUNT(*) FROM "subscription" WHERE "id"=? AND "status"='incomplete_expired'`, stale.LocalSubscription)
			replacement, err := second.ReserveStripeCheckout(ctx, otherUser.User.ID, otherUser.Token, otherWant, start)
			if err != nil || replacement.ID == stale.ID {
				t.Fatal("abandoned checkout could not be replaced", err)
			}
			notifyExpiry()
			if _, err = store.FindStripeCheckout(ctx, otherUser.User.ID, replacement.ID); err != nil {
				t.Fatal("late expiry removed the replacement", err)
			}
			monthly, monthlyCookie := signup("monthly")
			owner = monthly.User.ID
			expectedCustomer = "cus_monthly"
			checkoutKey = ""
			if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`), expectedCustomer, owner); err != nil {
				t.Fatal(err)
			}
			delete(body, "annual")
			check(200, first, "upgrade", body, monthlyCookie)
			if activePrice != "price_month" || customerRequests != 1 {
				t.Fatal("monthly checkout failed to reuse the linked customer")
			}
			if _, err := store.ListStripeSubscriptions(context.Background(), owner, "", time.Now()); err == nil {
				t.Fatal("unauthenticated store read allowed")
			}
		})
	}
}
