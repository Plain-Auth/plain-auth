package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

// The billing routes answer another runtime's error codes, statuses and
// messages, and a failure to find or create a Stripe customer, personal or
// organization, answers UNABLE_TO_CREATE_CUSTOMER before any Checkout and
// leaves the purchase retryable.
func TestStripeErrorCodes(t *testing.T) {
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
			var creates, checkouts int
			transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				switch {
				case r.URL.Path == "/v1/prices/price_basic":
					return stripeJSON(200, map[string]any{"id": "price_basic", "active": true, "recurring": map[string]any{"interval": "month", "interval_count": 1, "usage_type": "licensed"}}), nil
				case r.URL.Path == "/v1/customers" && r.Method == http.MethodPost:
					creates++
					return stripeJSON(500, map[string]any{"error": map[string]string{"type": "api_error", "message": "provider down"}}), nil
				case r.URL.Path == "/v1/customers/search":
					return stripeJSON(400, map[string]any{"error": map[string]string{"code": "search_not_available", "type": "invalid_request_error"}}), nil
				case r.URL.Path == "/v1/customers", r.URL.Path == "/v1/billing_portal/sessions":
					return stripeJSON(500, map[string]any{"error": map[string]string{"type": "api_error", "message": "provider down"}}), nil
				case r.URL.Path == "/v1/checkout/sessions":
					checkouts++
				}
				return nil, fmt.Errorf("unexpected Stripe call %s %s", r.Method, r.URL.Path)
			})
			backend := sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})
			provider := sdk.NewClient("sk_test_local", sdk.WithBackends(backend))
			const secret = "whsec_local_errors"
			const origin = "https://billing.example"
			plans := []billing.Plan{{Name: "basic", PriceID: "price_basic"}}
			owners := &billing.OrganizationOptions{AuthorizeReference: func(p billing.ReferenceAuthorization) bool { return p.Role == "owner" }}
			off := false
			instance := func(opts billing.Options) *plainauth.Auth {
				t.Helper()
				orgPlugin, err := org.New(org.Options{Store: store})
				if err != nil {
					t.Fatal(err)
				}
				a, err := plainauth.New(plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off,
					Plugins: []plainauth.Plugin{orgPlugin, billing.New(opts)}})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			full := instance(billing.Options{WebhookSecret: secret, OnEvent: func(context.Context, sdk.Event) error { return errors.New("observer down") },
				Portal: &billing.PortalOptions{Client: provider, Customers: store}, Subscriptions: &billing.SubscriptionOptions{Client: provider, Plans: plans}, Organization: owners})
			personal := instance(billing.Options{WebhookSecret: secret, Subscriptions: &billing.SubscriptionOptions{Client: provider, Plans: plans}})
			unset := instance(billing.Options{WebhookSecret: secret, Subscriptions: &billing.SubscriptionOptions{Client: provider, Plans: plans}, Organization: &billing.OrganizationOptions{}})
			unsigned := instance(billing.Options{Portal: &billing.PortalOptions{Client: provider, Customers: store}})
			verified := instance(billing.Options{WebhookSecret: secret, Subscriptions: &billing.SubscriptionOptions{Client: provider, Plans: plans, RequireEmailVerification: true}})
			signup := func(name string) (string, *http.Cookie) {
				t.Helper()
				hit, err := full.SignUpEmail(ctx, plainauth.SignUpInput{Name: name, Email: name + "@example.test", Password: "local fixture password"}, plainauth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				return hit.User.ID, full.SessionCookie(hit.Token, true)
			}
			_, ownerCookie := signup("owner")
			other, otherCookie := signup("other")
			customer, customerCookie := signup("customer")
			call := func(a *plainauth.Auth, path string, body any, cookie *http.Cookie, header http.Header) (int, map[string]any) {
				t.Helper()
				var src bytes.Buffer
				switch v := body.(type) {
				case string:
					src.WriteString(v)
				case nil:
				default:
					json.NewEncoder(&src).Encode(v)
				}
				r := httptest.NewRequest(http.MethodPost, origin+"/api/auth"+path, &src)
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "application/json")
				for k, v := range header {
					r.Header[k] = v
				}
				if cookie != nil {
					r.AddCookie(cookie)
				}
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var out map[string]any
				json.Unmarshal(w.Body.Bytes(), &out)
				return w.Code, out
			}
			expect := func(label string, status int, code, message string, got int, out map[string]any) {
				t.Helper()
				gotCode, _ := out["code"].(string)
				if got != status || gotCode != code || out["message"] != message {
					t.Errorf("%s answered %d %q %v, want %d %q %q", label, got, gotCode, out["message"], status, code, message)
				}
			}
			var created org.Organization
			{
				status, out := call(full, "/organization/create", map[string]string{"name": "Errors organization", "slug": "errors-org"}, ownerCookie, nil)
				raw, _ := json.Marshal(out)
				if status != 200 || json.Unmarshal(raw, &created) != nil || created.ID == "" {
					t.Fatal("organization create failed", status, out)
				}
			}
			checkout := func(extra map[string]any) map[string]any {
				body := map[string]any{"plan": "basic", "successUrl": "/done", "cancelUrl": "/cancel", "disableRedirect": true}
				for k, v := range extra {
					body[k] = v
				}
				return body
			}
			status, out := call(full, "/subscription/upgrade", checkout(nil), nil, nil)
			expect("signed out", 401, "UNAUTHORIZED", "Unauthorized", status, out)
			status, out = call(full, "/subscription/upgrade", checkout(map[string]any{"plan": "absent"}), ownerCookie, nil)
			expect("unknown plan", 400, "SUBSCRIPTION_PLAN_NOT_FOUND", "Subscription plan not found", status, out)
			status, out = call(full, "/subscription/upgrade", checkout(map[string]any{"annual": true}), ownerCookie, nil)
			expect("missing annual price", 400, "", "Price ID not found for the selected plan", status, out)
			status, out = call(full, "/subscription/upgrade", checkout(map[string]any{"referenceId": other}), ownerCookie, nil)
			expect("foreign reference", 400, "REFERENCE_ID_NOT_ALLOWED", "Reference id is not allowed", status, out)
			status, out = call(full, "/subscription/upgrade", checkout(map[string]any{"customerType": "organization", "referenceId": "org_missing"}), ownerCookie, nil)
			expect("unknown organization", 403, "UNAUTHORIZED", "Unauthorized access", status, out)
			status, out = call(full, "/subscription/upgrade", checkout(map[string]any{"customerType": "organization"}), otherCookie, nil)
			expect("no organization", 400, "ORGANIZATION_REFERENCE_ID_REQUIRED", "Reference ID is required. Provide referenceId or set activeOrganizationId in session", status, out)
			status, out = call(personal, "/subscription/upgrade", checkout(map[string]any{"customerType": "organization", "referenceId": created.ID}), ownerCookie, nil)
			expect("organization billing off", 400, "ORGANIZATION_SUBSCRIPTION_NOT_ENABLED", "Organization subscription is not enabled", status, out)
			status, out = call(unset, "/subscription/upgrade", checkout(map[string]any{"customerType": "organization", "referenceId": created.ID}), ownerCookie, nil)
			expect("no policy", 400, "AUTHORIZE_REFERENCE_REQUIRED", "Organization subscriptions require authorizeReference callback to be configured", status, out)
			status, out = call(verified, "/subscription/upgrade", checkout(nil), ownerCookie, nil)
			expect("unverified", 400, "EMAIL_VERIFICATION_REQUIRED", "Email verification is required before you can subscribe to a plan", status, out)
			// A customer Stripe fails to create, personal or organization,
			// stops before Checkout and can be retried.
			for range 2 {
				status, out = call(full, "/subscription/upgrade", checkout(nil), ownerCookie, nil)
				expect("personal customer", 400, "UNABLE_TO_CREATE_CUSTOMER", "Unable to create customer", status, out)
			}
			status, out = call(full, "/subscription/upgrade", checkout(map[string]any{"customerType": "organization", "referenceId": created.ID}), ownerCookie, nil)
			expect("organization customer", 400, "UNABLE_TO_CREATE_CUSTOMER", "Unable to create customer", status, out)
			mu.Lock()
			if creates != 2 || checkouts != 0 {
				t.Errorf("customer failures made %d creations and %d checkouts", creates, checkouts)
			}
			mu.Unlock()
			status, out = call(full, "/subscription/billing-portal", map[string]any{}, otherCookie, nil)
			expect("no customer", 404, "CUSTOMER_NOT_FOUND", "Stripe customer not found for this user", status, out)
			if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`), "cus_errors", customer); err != nil {
				t.Fatal(err)
			}
			status, out = call(full, "/subscription/billing-portal", map[string]any{}, customerCookie, nil)
			expect("portal failure", 500, "UNABLE_TO_CREATE_BILLING_PORTAL", "Unable to create billing portal session", status, out)
			status, out = call(full, "/subscription/cancel", map[string]any{"subscriptionId": "sub_missing", "returnUrl": "/billing"}, customerCookie, nil)
			expect("unknown subscription", 400, "SUBSCRIPTION_NOT_FOUND", "Subscription not found", status, out)
			if _, err := store.db.ExecContext(ctx, store.bind(`INSERT INTO "subscription" ("id","plan","referenceId","stripeCustomerId","stripeSubscriptionId","status") VALUES('sub_past','basic',?,?,?,'past_due')`), customer, "cus_errors", "sub_remote_past"); err != nil {
				t.Fatal(err)
			}
			status, out = call(full, "/subscription/restore", map[string]any{"subscriptionId": "sub_remote_past"}, customerCookie, nil)
			expect("inactive subscription", 400, "SUBSCRIPTION_NOT_ACTIVE", "Subscription is not active", status, out)
			// Webhook deliveries.
			status, out = call(full, "/stripe/webhook", nil, nil, nil)
			expect("empty delivery", 400, "INVALID_REQUEST_BODY", "Invalid request body", status, out)
			status, out = call(full, "/stripe/webhook", "{}", nil, nil)
			expect("unsigned delivery", 400, "STRIPE_SIGNATURE_NOT_FOUND", "Stripe signature not found", status, out)
			status, out = call(full, "/stripe/webhook", "{}", nil, http.Header{"Stripe-Signature": {"t=1,v1=00"}})
			expect("bad signature", 400, "FAILED_TO_CONSTRUCT_STRIPE_EVENT", "Failed to construct Stripe event", status, out)
			event, _ := json.Marshal(map[string]any{"id": "evt_errors", "object": "event", "type": "invoice.paid", "api_version": sdk.APIVersion, "livemode": false, "created": time.Now().Unix(), "data": map[string]any{"object": map[string]any{"id": "in_errors", "object": "invoice"}}})
			signed := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: event, Secret: secret})
			status, out = call(full, "/stripe/webhook", string(event), nil, http.Header{"Stripe-Signature": {signed.Header}})
			expect("observer failure", 400, "STRIPE_WEBHOOK_ERROR", "Stripe webhook error", status, out)
			status, out = call(unsigned, "/stripe/webhook", string(event), nil, http.Header{"Stripe-Signature": {signed.Header}})
			expect("no secret", 500, "STRIPE_WEBHOOK_SECRET_NOT_FOUND", "Stripe webhook secret not found", status, out)
		})
	}
}
