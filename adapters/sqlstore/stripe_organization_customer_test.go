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

	"github.com/Plain-Org/plain-auth"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
)

// An organization's first purchase creates its customer with the host's
// CustomerCreateParams beneath the organization's name and metadata, then
// reports it once through OnCustomerCreate; a customer found in Stripe or a
// personal purchase calls neither, and a failing callback answers
// UNABLE_TO_CREATE_CUSTOMER.
func TestOrganizationCustomerCallbacks(t *testing.T) {
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
			var creates []url.Values
			var found []map[string]any
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
					return stripeJSON(200, map[string]any{"object": "search_result", "has_more": false, "data": found}), nil
				case r.URL.Path == "/v1/customers" && r.Method == "POST":
					creates = append(creates, r.PostForm)
					meta := map[string]string{"userId": r.PostForm.Get("metadata[userId]"), "organizationId": r.PostForm.Get("metadata[organizationId]"), "customerType": r.PostForm.Get("metadata[customerType]")}
					return stripeJSON(200, map[string]any{"id": fmt.Sprintf("cus_orgcb_%d", len(creates)), "object": "customer", "metadata": meta}), nil
				case r.URL.Path == "/v1/checkout/sessions" && r.Method == "POST":
					return stripeJSON(200, map[string]any{"id": "cs_" + r.PostForm.Get("customer"), "object": "checkout.session", "url": "https://checkout.stripe.test/" + r.PostForm.Get("customer"), "status": "open"}), nil
				case strings.HasPrefix(r.URL.Path, "/v1/checkout/sessions/") && r.Method == "GET":
					id := strings.TrimPrefix(r.URL.Path, "/v1/checkout/sessions/")
					return stripeJSON(200, map[string]any{"id": id, "object": "checkout.session", "url": "https://checkout.stripe.test/" + id, "status": "open"}), nil
				}
				return nil, fmt.Errorf("unexpected Stripe call %s %s", r.Method, r.URL.Path)
			})
			remote := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})))
			var params []billing.NewOrganizationCustomer
			var reported []billing.OrganizationCustomerCreated
			var paramsErr, reportErr error
			orgPlugin, err := org.New(org.Options{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			const origin = "https://billing.example"
			off := false
			a, err := plainauth.New(plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off,
				Plugins: []plainauth.Plugin{orgPlugin, billing.New(billing.Options{WebhookSecret: "whsec_orgcb",
					Organization: &billing.OrganizationOptions{
						AuthorizeReference: func(m billing.ReferenceAuthorization) bool { return m.Role == "owner" },
						CustomerCreateParams: func(_ context.Context, in billing.NewOrganizationCustomer) (*sdk.CustomerCreateParams, error) {
							mu.Lock()
							defer mu.Unlock()
							params = append(params, in)
							p := &sdk.CustomerCreateParams{Email: sdk.String("billing@" + in.Name + ".test"), Name: sdk.String("Spoofed"), Description: sdk.String("Team " + in.Name),
								Metadata: map[string]string{"plan": "team", "organizationId": "spoof", "customerType": "user"}}
							return p, paramsErr
						},
						OnCustomerCreate: func(_ context.Context, c billing.OrganizationCustomerCreated) error {
							mu.Lock()
							defer mu.Unlock()
							reported = append(reported, c)
							return reportErr
						}},
					Subscriptions: &billing.SubscriptionOptions{Client: remote, Plans: []billing.Plan{{Name: "basic", PriceID: "price_basic"}}}})}})
			if err != nil {
				t.Fatal(err)
			}
			hit, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: "owner", Email: "owner@example.test", Password: "local fixture password"}, plainauth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			cookie := a.SessionCookie(hit.Token, true)
			call := func(path string, body map[string]any) (int, map[string]any) {
				t.Helper()
				var src bytes.Buffer
				json.NewEncoder(&src).Encode(body)
				r := httptest.NewRequest("POST", origin+"/api/auth"+path, &src)
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "application/json")
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var out map[string]any
				json.Unmarshal(w.Body.Bytes(), &out)
				return w.Code, out
			}
			group := func(name string) string {
				t.Helper()
				status, out := call("/organization/create", map[string]any{"name": name, "slug": name})
				id, _ := out["id"].(string)
				if status != 200 || id == "" {
					t.Fatal("organization create", status, out)
				}
				return id
			}
			upgrade := func(id string) (int, map[string]any) {
				t.Helper()
				body := map[string]any{"plan": "basic", "successUrl": "/done", "cancelUrl": "/cancel", "disableRedirect": true}
				if id != "" {
					body["customerType"], body["referenceId"] = "organization", id
				}
				return call("/subscription/upgrade", body)
			}
			customerOf := func(id string) string {
				t.Helper()
				var customer *string
				if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "stripeCustomerId" FROM "organization" WHERE "id"=?`), id).Scan(&customer); err != nil {
					t.Fatal(err)
				}
				if customer == nil {
					return ""
				}
				return *customer
			}
			counts := func() (int, int, int) {
				mu.Lock()
				defer mu.Unlock()
				return len(creates), len(params), len(reported)
			}

			// The first purchase merges the host's parameters beneath the
			// organization's name and metadata, and reports the customer once.
			acme := group("acme")
			if status, out := upgrade(acme); status != 200 {
				t.Fatal("organization upgrade", status, out)
			}
			made, asked, told := counts()
			if made != 1 || asked != 1 || told != 1 || customerOf(acme) != "cus_orgcb_1" {
				t.Fatal("the first purchase did not create and report the customer once", made, asked, told, customerOf(acme))
			}
			if f := creates[0]; f.Get("name") != "acme" || f.Get("email") != "billing@acme.test" || f.Get("description") != "Team acme" || f.Get("metadata[plan]") != "team" || f.Get("metadata[organizationId]") != acme || f.Get("metadata[customerType]") != "organization" {
				t.Fatal("the host's parameters were not merged beneath the organization's", f)
			}
			if in := params[0]; in.OrganizationID != acme || in.Name != "acme" || in.User.ID != hit.User.ID || in.Request == nil || !strings.HasSuffix(in.Request.URL.Path, "/subscription/upgrade") {
				t.Fatal("the parameters callback input was wrong", in)
			}
			if c := reported[0]; c.Customer.ID != "cus_orgcb_1" || c.OrganizationID != acme || c.User.ID != hit.User.ID {
				t.Fatal("the creation callback input was wrong", c)
			}
			// A retry of the pending purchase calls neither callback.
			if status, _ := upgrade(acme); status != 200 {
				t.Fatal("retry", status)
			}
			if made, asked, told := counts(); made != 1 || asked != 1 || told != 1 {
				t.Fatal("a retry called a callback or created a customer", made, asked, told)
			}

			// A customer found in Stripe and a personal purchase call neither.
			found = []map[string]any{{"id": "cus_found_org", "object": "customer", "metadata": map[string]string{"organizationId": "", "customerType": "organization"}}}
			beta := group("beta")
			found[0]["metadata"] = map[string]string{"organizationId": beta, "customerType": "organization"}
			if status, out := upgrade(beta); status != 200 || customerOf(beta) != "cus_found_org" {
				t.Fatal("a found organization customer was not used", status, out, customerOf(beta))
			}
			found = nil
			if status, out := upgrade(""); status != 200 {
				t.Fatal("personal upgrade", status, out)
			}
			if made, asked, told := counts(); made != 2 || asked != 1 || told != 1 {
				t.Fatal("a found customer or a personal purchase called an organization callback", made, asked, told)
			}

			// A failing parameters callback creates nothing; a failing
			// creation callback keeps the customer, and the retry continues
			// with it without reporting it again.
			paramsErr = errors.New("host detail")
			gamma := group("gamma")
			if status, out := upgrade(gamma); status != 400 || out["code"] != "UNABLE_TO_CREATE_CUSTOMER" || customerOf(gamma) != "" {
				t.Fatal("a failing parameters callback did not refuse the purchase", status, out)
			}
			if made, _, _ := counts(); made != 2 {
				t.Fatal("a failing parameters callback created a customer", made)
			}
			paramsErr, reportErr = nil, errors.New("host detail")
			if status, out := upgrade(gamma); status != 400 || out["code"] != "UNABLE_TO_CREATE_CUSTOMER" || customerOf(gamma) != "cus_orgcb_3" {
				t.Fatal("a failing creation callback did not refuse the purchase with the customer stored", status, out, customerOf(gamma))
			}
			reportErr = nil
			if status, out := upgrade(gamma); status != 200 {
				t.Fatal("a retry after a failing creation callback failed", status, out)
			}
			if made, _, told := counts(); made != 3 || told != 2 {
				t.Fatal("a retry created another customer or reported it again", made, told)
			}
		})
	}
}
