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
	"time"

	"github.com/Plain-Org/plain-auth"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
)

// A verified user's purchase reuses the Stripe customer found for the email
// when no other user owns it, through search or, when search is
// unavailable, a list by email; otherwise, and for an unverified user, a
// customer is created with the user's email, name and metadata.
func TestCheckoutCustomerLookup(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			ddl, err := schema.Generate(dialect, []string{"stripe-organization"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			var mu sync.Mutex
			var searches, lists []url.Values
			var creates []url.Values
			var checkouts []string
			var keys []string
			var checkoutCustomer string
			var made int
			var createFails, concurrent bool
			var arrivals int
			var deletes []string
			barrier := make(chan struct{})
			searchStatus, listStatus := 200, 200
			var found, listed []map[string]any
			transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				if err := r.ParseForm(); err != nil {
					return nil, err
				}
				switch {
				case r.URL.Path == "/v1/prices/price_basic":
					return stripeJSON(200, map[string]any{"id": "price_basic", "active": true, "recurring": map[string]any{"interval": "month", "interval_count": 1, "usage_type": "licensed"}}), nil
				case r.URL.Path == "/v1/customers/search":
					searches = append(searches, r.Form)
					if searchStatus != 200 {
						return stripeJSON(searchStatus, map[string]any{"error": map[string]string{"code": "search_not_available", "type": "invalid_request_error"}}), nil
					}
					return stripeJSON(200, map[string]any{"object": "search_result", "has_more": false, "data": found}), nil
				case r.URL.Path == "/v1/customers" && r.Method == http.MethodGet:
					lists = append(lists, r.Form)
					if listStatus != 200 {
						return stripeJSON(listStatus, map[string]any{"error": map[string]string{"type": "api_error", "message": "down"}}), nil
					}
					return stripeJSON(200, map[string]any{"object": "list", "has_more": false, "data": listed}), nil
				case strings.HasPrefix(r.URL.Path, "/v1/customers/") && r.Method == http.MethodDelete:
					deletes = append(deletes, strings.TrimPrefix(r.URL.Path, "/v1/customers/"))
					return stripeJSON(200, map[string]any{"id": strings.TrimPrefix(r.URL.Path, "/v1/customers/"), "object": "customer", "deleted": true}), nil
				case r.URL.Path == "/v1/customers" && r.Method == http.MethodPost:
					if concurrent {
						// Both creations are in flight before either answers.
						arrivals++
						if arrivals == 2 {
							close(barrier)
						}
						mu.Unlock()
						<-barrier
						mu.Lock()
					}
					if createFails {
						createFails = false
						return stripeJSON(500, map[string]any{"error": map[string]string{"type": "api_error", "message": "down"}}), nil
					}
					creates = append(creates, r.PostForm)
					keys = append(keys, r.Header.Get("Idempotency-Key"))
					made++
					id := fmt.Sprintf("cus_new%d", made)
					return stripeJSON(200, map[string]any{"id": id, "object": "customer", "metadata": map[string]string{"userId": r.PostForm.Get("metadata[userId]"), "customerType": r.PostForm.Get("metadata[customerType]")}}), nil
				case r.URL.Path == "/v1/checkout/sessions":
					checkoutCustomer = r.PostForm.Get("customer")
					checkouts = append(checkouts, checkoutCustomer)
					return stripeJSON(200, map[string]any{"id": "cs_" + checkoutCustomer, "object": "checkout.session", "url": "https://checkout.stripe.test/" + checkoutCustomer}), nil
				}
				return nil, fmt.Errorf("unexpected Stripe call %s %s", r.Method, r.URL.Path)
			})
			backend := sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})
			provider := sdk.NewClient("sk_test_local", sdk.WithBackends(backend))
			const origin = "https://billing.example"
			off := false
			a, err := plainauth.New(plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off,
				Plugins: []plainauth.Plugin{billing.New(billing.Options{WebhookSecret: "whsec_lookup", Subscriptions: &billing.SubscriptionOptions{Client: provider, Plans: []billing.Plan{{Name: "basic", PriceID: "price_basic"}}}})}})
			if err != nil {
				t.Fatal(err)
			}
			customerOf := func(id string) string {
				t.Helper()
				var customer *string
				if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "stripeCustomerId" FROM "user" WHERE "id"=?`), id).Scan(&customer); err != nil {
					t.Fatal(err)
				}
				if customer == nil {
					return ""
				}
				return *customer
			}
			upgrade := func(cookie *http.Cookie) (int, map[string]any) {
				t.Helper()
				var src bytes.Buffer
				json.NewEncoder(&src).Encode(map[string]any{"plan": "basic", "successUrl": "/done", "cancelUrl": "/cancel", "disableRedirect": true})
				r := httptest.NewRequest(http.MethodPost, origin+"/api/auth/subscription/upgrade", &src)
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "application/json")
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var out map[string]any
				json.Unmarshal(w.Body.Bytes(), &out)
				return w.Code, out
			}
			var last *http.Cookie
			// buy signs a user up, verified or not, and starts a checkout.
			buy := func(name string, verified bool) (string, int, map[string]any) {
				t.Helper()
				hit, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: name + " Buyer", Email: name + "@example.test", Password: "local fixture password"}, plainauth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				if verified {
					if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "emailVerified"=? WHERE "id"=?`), true, hit.User.ID); err != nil {
						t.Fatal(err)
					}
				}
				last = a.SessionCookie(hit.Token, true)
				status, out := upgrade(last)
				return hit.User.ID, status, out
			}
			reset := func() {
				mu.Lock()
				defer mu.Unlock()
				searches, lists, creates, keys, checkoutCustomer = nil, nil, nil, nil, ""
				searchStatus, listStatus, found, listed = 200, 200, nil, nil
			}

			// An unowned match is reused, without a creation.
			found = []map[string]any{{"id": "cus_match", "object": "customer", "metadata": map[string]string{}}}
			id, status, out := buy("reuse", true)
			if status != 200 || len(creates) != 0 || customerOf(id) != "cus_match" || checkoutCustomer != "cus_match" {
				t.Fatal("an unowned match was not reused", status, out, len(creates), customerOf(id))
			}
			if len(searches) != 1 || searches[0].Get("query") != `email:"reuse@example.test" AND -metadata["customerType"]:"organization"` || searches[0].Get("limit") != "1" {
				t.Fatal("the customer search was wrong", searches)
			}
			// A match another user owns is not reused: a customer is created with
			// the user's email, name and metadata.
			reset()
			found = []map[string]any{{"id": "cus_theirs", "object": "customer", "metadata": map[string]string{"userId": "someone-else"}}}
			id, status, out = buy("owned", true)
			if status != 200 || len(creates) != 1 || customerOf(id) != "cus_new1" || checkoutCustomer != "cus_new1" {
				t.Fatal("an owned match was reused", status, out, len(creates))
			}
			created := 1
			if c := creates[0]; c.Get("email") != "owned@example.test" || c.Get("name") != "owned Buyer" || c.Get("metadata[userId]") != id || c.Get("metadata[customerType]") != "user" || strings.HasPrefix(keys[0], "auth-customer-") {
				t.Fatal("the created customer was wrong", c, keys)
			}
			// A match another local account holds is not shared.
			reset()
			found = []map[string]any{{"id": "cus_held", "object": "customer", "metadata": map[string]string{}}}
			holder, _, _ := buy("holder-setup", false)
			reset()
			found = []map[string]any{{"id": "cus_held", "object": "customer", "metadata": map[string]string{}}}
			if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`), "cus_held", holder); err != nil {
				t.Fatal(err)
			}
			id, status, out = buy("shared", true)
			created += 2
			if status != 200 || len(creates) != 1 || customerOf(id) != fmt.Sprintf("cus_new%d", created) || customerOf(holder) != "cus_held" {
				t.Fatal("a customer another account holds was shared", status, out, len(creates), customerOf(id))
			}
			// An unverified email is not looked up.
			reset()
			searchStatus, listStatus = 400, 500
			id, status, out = buy("unverified", false)
			created++
			if status != 200 || len(searches) != 0 || len(lists) != 0 || len(creates) != 1 || customerOf(id) != fmt.Sprintf("cus_new%d", created) {
				t.Fatal("an unverified email was looked up", status, out, len(searches), len(lists))
			}
			// Search unavailable: the list by email skips an organization's
			// customer and reuses the next.
			reset()
			searchStatus = 400
			listed = []map[string]any{{"id": "cus_org", "object": "customer", "metadata": map[string]string{"customerType": "organization"}}, {"id": "cus_listed", "object": "customer", "metadata": map[string]string{}}}
			id, status, out = buy("listed", true)
			if status != 200 || len(lists) != 1 || lists[0].Get("email") != "listed@example.test" || lists[0].Get("limit") != "100" || len(creates) != 0 || customerOf(id) != "cus_listed" {
				t.Fatal("the list fallback did not reuse the person's customer", status, out, lists, len(creates), customerOf(id))
			}
			// A failed creation can be retried once Stripe recovers.
			reset()
			createFails = true
			id, status, out = buy("retried", false)
			if status != 400 || out["code"] != "UNABLE_TO_CREATE_CUSTOMER" || len(creates) != 0 {
				t.Fatal("a failed creation was not refused", status, out)
			}
			if status, out = upgrade(last); status != 200 || len(creates) != 1 || customerOf(id) == "" {
				t.Fatal("a failed creation could not be retried", status, out, len(creates))
			}
			// Two identical purchases at once settle on the first customer
			// bound, and the other created customer is deleted.
			reset()
			mu.Lock()
			deletes, checkouts = nil, nil
			mu.Unlock()
			hit, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: "twice Buyer", Email: "twice@example.test", Password: "local fixture password"}, plainauth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			twice := a.SessionCookie(hit.Token, true)
			concurrent = true
			statuses := make(chan int, 2)
			for range 2 {
				go func() { status, _ := upgrade(twice); statuses <- status }()
			}
			first, second := <-statuses, <-statuses
			concurrent = false
			mu.Lock()
			bound := customerOf(hit.User.ID)
			if first != 200 || second != 200 || len(creates) != 2 || len(deletes) != 1 || deletes[0] == bound || bound == "" || len(checkouts) != 2 || checkouts[0] != bound || checkouts[1] != bound {
				mu.Unlock()
				t.Fatal("concurrent identical purchases did not settle on one customer", first, second, len(creates), deletes, bound, checkouts)
			}
			mu.Unlock()
			// A match an organization holds is not shared either.
			reset()
			if _, err := store.db.ExecContext(ctx, store.bind(`INSERT INTO "organization" ("id","name","slug","createdAt","stripeCustomerId") VALUES(?,?,?,?,?)`), "org_held", "Held", "held", store.date(time.Now()), "cus_orgheld"); err != nil {
				t.Fatal(err)
			}
			found = []map[string]any{{"id": "cus_orgheld", "object": "customer", "metadata": map[string]string{}}}
			id, status, out = buy("orgheld", true)
			if status != 200 || len(creates) != 1 || customerOf(id) == "cus_orgheld" || customerOf(id) == "" {
				t.Fatal("a customer an organization holds was shared", status, out, len(creates), customerOf(id))
			}
			// Both lookups failing for a verified user answer
			// UNABLE_TO_CREATE_CUSTOMER without a creation or a Checkout.
			reset()
			searchStatus, listStatus = 400, 500
			id, status, out = buy("failing", true)
			if status != 400 || out["code"] != "UNABLE_TO_CREATE_CUSTOMER" || len(creates) != 0 || checkoutCustomer != "" || customerOf(id) != "" {
				t.Fatal("a failed lookup was not refused", status, out, len(creates))
			}
		})
	}
}
