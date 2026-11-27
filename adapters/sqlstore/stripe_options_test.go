package sqlstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/organization"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

// Subscription options mount the upgrade, list, cancel, restore and success
// routes and portal options the billing portal, each without the other; a
// store without the Stripe schema refuses subscriptions at startup.
func TestStripeSubscriptionOptions(t *testing.T) {
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
			var calls atomic.Int32
			transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				return stripeJSON(500, map[string]any{"error": map[string]string{"type": "api_error"}}), nil
			})
			provider := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})))
			const origin = "https://billing.example"
			const secret = "whsec_options"
			off := false
			start := func(s *Store, opts billing.Options) (*plainauth.Auth, error) {
				return plainauth.New(plainauth.Options{Store: s, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{billing.New(opts)}})
			}
			subscriptions := &billing.SubscriptionOptions{Client: provider, Plans: []billing.Plan{{Name: "pro", PriceID: "price_pro"}}}
			call := func(a *plainauth.Auth, method, path, body string) *httptest.ResponseRecorder {
				var src *bytes.Reader
				if body != "" {
					src = bytes.NewReader([]byte(body))
				} else {
					src = bytes.NewReader(nil)
				}
				r := httptest.NewRequest(method, origin+"/api/auth"+path, src)
				r.Header.Set("Origin", origin)
				if body != "" {
					r.Header.Set("Content-Type", "application/json")
				}
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				return w
			}
			routes := []struct{ method, path, body string }{
				{"POST", "/subscription/upgrade", `{"plan":"pro"}`}, {"GET", "/subscription/list", ""},
				{"POST", "/subscription/cancel", `{"returnUrl":"/billing"}`}, {"POST", "/subscription/restore", `{}`},
				{"GET", "/subscription/success?callbackURL=%2F", ""},
			}
			// Portal options alone mount only the billing portal.
			portal, err := start(store, billing.Options{WebhookSecret: secret, Portal: &billing.PortalOptions{Client: provider, Customers: store}})
			if err != nil {
				t.Fatal(err)
			}
			for _, route := range routes {
				if w := call(portal, route.method, route.path, route.body); w.Code != 404 {
					t.Error("portal options mounted a subscription route", route.path, w.Code)
				}
			}
			if w := call(portal, "POST", "/subscription/billing-portal", `{}`); w.Code != 401 {
				t.Error("portal options did not mount the billing portal", w.Code)
			}
			event, _ := json.Marshal(map[string]any{"id": "evt_options", "object": "event", "type": "customer.subscription.updated", "api_version": sdk.APIVersion, "created": 1,
				"data": map[string]any{"object": map[string]any{"id": "sub_options", "object": "subscription", "customer": "cus_options", "status": "active"}}})
			r := httptest.NewRequest("POST", origin+"/api/auth/stripe/webhook", bytes.NewReader(event))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Stripe-Signature", webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: event, Secret: secret}).Header)
			w := httptest.NewRecorder()
			portal.ServeHTTP(w, r)
			if w.Code != 200 || calls.Load() != 0 {
				t.Error("a subscription event reached Stripe without subscription options", w.Code, calls.Load())
			}
			// Subscription options alone mount the subscription routes and no
			// billing portal.
			subs, err := start(store, billing.Options{WebhookSecret: secret, Subscriptions: subscriptions})
			if err != nil {
				t.Fatal(err)
			}
			for i, route := range routes {
				w := call(subs, route.method, route.path, route.body)
				switch {
				case i < 4 && w.Code != 401:
					t.Error("a subscription route answered a signed-out request", route.path, w.Code)
				case i == 4 && (w.Code != 302 || w.Header().Get("Location") != origin+"/"):
					t.Error("the signed-out success return did not redirect", w.Code, w.Header().Get("Location"))
				}
			}
			if w := call(subs, "POST", "/subscription/billing-portal", `{}`); w.Code != 404 {
				t.Error("subscription options mounted the billing portal", w.Code)
			}
			// A store without the Stripe schema refuses subscriptions at startup.
			bare, err := Open(ctx, dialect, organizationTestDSN(t, dialect))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { bare.Close() })
			if _, err := start(bare, billing.Options{WebhookSecret: secret, Subscriptions: subscriptions}); err == nil {
				t.Error("subscriptions started on a store without the Stripe schema")
			}
		})
	}
}

// By default an unverified owner reaches Checkout; with
// RequireEmailVerification, new checkouts and plan changes are refused
// before Stripe until the email is verified.
func TestCheckoutEmailVerification(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			var calls atomic.Int32
			counting := func(f *returnFixture, r *http.Request) (*http.Response, error) {
				calls.Add(1)
				return f.provider(r)
			}
			plan := billing.Plan{Name: "pro", PriceID: "price_pro"}
			open := configuredReturnFixture(t, dialect, plan, false, counting)
			open.start(open.user("open"))
			f := configuredReturnFixture(t, dialect, plan, false, counting, func(o *billing.Options) { o.Subscriptions.RequireEmailVerification = true })
			owner := f.user("owner")
			cookie := f.a.SessionCookie(owner.Token, true)
			refused := func(body map[string]string) {
				t.Helper()
				raw, _ := json.Marshal(body)
				before := calls.Load()
				w := f.hit(f.a, "/subscription/upgrade", bytes.NewReader(raw), cookie)
				var out map[string]any
				json.Unmarshal(w.Body.Bytes(), &out)
				if w.Code != 400 || out["code"] != "EMAIL_VERIFICATION_REQUIRED" || out["message"] != "Email verification is required before you can subscribe to a plan" || calls.Load() != before {
					t.Fatal("an unverified owner was not refused before Stripe", body, w.Code, out, calls.Load()-before)
				}
			}
			refused(map[string]string{"plan": "pro", "successUrl": returnTemplate, "cancelUrl": "/cancel"})
			if _, err := f.store.db.ExecContext(t.Context(), f.store.bind(`INSERT INTO "subscription" ("id","plan","referenceId","stripeCustomerId","stripeSubscriptionId","status") VALUES('local_pending','pro',?,?,'sub_pending','active')`), owner.User.ID, "cus_owner"); err != nil {
				t.Fatal(err)
			}
			refused(map[string]string{"plan": "pro", "subscriptionId": "sub_pending", "returnUrl": "/billing"})
			if _, err := f.store.db.ExecContext(t.Context(), f.store.bind(`UPDATE "user" SET "emailVerified"=? WHERE "id"=?`), true, owner.User.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.db.ExecContext(t.Context(), f.store.bind(`DELETE FROM "subscription" WHERE "id"='local_pending'`)); err != nil {
				t.Fatal(err)
			}
			f.start(owner)
		})
	}
}

// noSeatStore is a subscription store without the automatic seat methods.
type noSeatStore struct {
	plainauth.Store
	billing.SubscriptionStore
}

// Organization billing needs the organization customer column, a membership
// plan needs an organization policy and a seat-capable store, and without a
// policy organization requests are refused before Stripe while personal
// billing still works.
func TestStripeOrganizationOptions(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			var calls atomic.Int32
			transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				if r.URL.Path == "/v1/billing_portal/sessions" {
					return stripeJSON(200, map[string]string{"id": "bps", "url": "https://billing.example.test/portal", "customer": "cus_personal"}), nil
				}
				return stripeJSON(500, map[string]any{"error": map[string]string{"type": "api_error"}}), nil
			})
			provider := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})))
			const origin = "https://billing.example"
			const secret = "whsec_org_options"
			off := false
			start := func(s plainauth.Store, opts billing.Options, password bool) (*plainauth.Auth, error) {
				return plainauth.New(plainauth.Options{Store: s, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: password, RateLimit: &off, Plugins: []plainauth.Plugin{billing.New(opts)}})
			}
			policy := &billing.OrganizationOptions{AuthorizeReference: func(billing.ReferenceAuthorization) bool { return true }}
			pro := []billing.Plan{{Name: "pro", PriceID: "price_pro"}}
			subscriptions := &billing.SubscriptionOptions{Client: provider, Plans: pro}
			// Without the organization customer column, organization billing
			// refuses to start; the schema upgrade keeps existing organizations.
			dsn := organizationTestDSN(t, dialect)
			old, err := schema.Generate(dialect, []string{"organization", "stripe-subscriptions"})
			if err != nil {
				t.Fatal(err)
			}
			before, err := OpenWithSchema(ctx, dialect, dsn, old)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { before.Close() })
			if _, err := before.db.ExecContext(ctx, before.bind(`INSERT INTO "organization" ("id","name","slug","createdAt") VALUES(?,?,?,?)`), "org_old", "Old organization", "old", before.date(time.Now())); err != nil {
				t.Fatal(err)
			}
			for _, subs := range []*billing.SubscriptionOptions{nil, subscriptions} {
				if _, err := start(before, billing.Options{WebhookSecret: secret, Organization: policy, Subscriptions: subs}, false); err == nil {
					t.Fatal("organization billing started without its schema", subs != nil)
				}
			}
			if _, err := start(before, billing.Options{WebhookSecret: secret, Subscriptions: subscriptions}, false); err != nil {
				t.Fatal("personal billing refused the older schema", err)
			}
			current, err := schema.Generate(dialect, []string{"stripe-organization"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(ctx, dialect, dsn, current)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			if _, err := start(store, billing.Options{WebhookSecret: secret, Organization: policy, Subscriptions: subscriptions}, false); err != nil {
				t.Fatal("organization billing refused the upgraded schema", err)
			}
			var customer *string
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "stripeCustomerId" FROM "organization" WHERE "id"=?`), "org_old").Scan(&customer); err != nil || customer != nil {
				t.Fatal("schema upgrade lost an existing organization", err, customer)
			}
			// A membership plan needs an organization policy and a seat store.
			team := &billing.SubscriptionOptions{Client: provider, Plans: []billing.Plan{{Name: "team", PriceID: "price_team", SeatPriceID: "price_seat"}}}
			for _, org := range []*billing.OrganizationOptions{nil, {}} {
				if _, err := start(store, billing.Options{WebhookSecret: secret, Organization: org, Subscriptions: team}, false); err == nil || !strings.Contains(err.Error(), "membership-based billing requires organization authorization") {
					t.Fatal("a membership plan started without an organization policy", err)
				}
			}
			if _, err := start(noSeatStore{store, store}, billing.Options{WebhookSecret: secret, Organization: policy, Subscriptions: team}, false); err == nil || !strings.Contains(err.Error(), "store does not support automatic seats") {
				t.Fatal("a membership plan started on a store without seats", err)
			}
			if _, err := start(store, billing.Options{WebhookSecret: secret, Organization: policy, Subscriptions: team}, false); err != nil {
				t.Fatal("a membership plan refused a seat store", err)
			}
			// Without a policy, organization requests are refused before Stripe
			// or a reservation; personal billing still works.
			a, err := start(store, billing.Options{WebhookSecret: secret, Organization: &billing.OrganizationOptions{}, Subscriptions: subscriptions, Portal: &billing.PortalOptions{Client: provider, Customers: store}}, true)
			if err != nil {
				t.Fatal(err)
			}
			hit, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: "owner", Email: "owner@example.test", Password: "local fixture password"}, plainauth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			cookie := a.SessionCookie(hit.Token, true)
			call := func(method, path string, body any) (int, map[string]any) {
				var src bytes.Buffer
				if body != nil {
					json.NewEncoder(&src).Encode(body)
				}
				r := httptest.NewRequest(method, origin+"/api/auth"+path, &src)
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "application/json")
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var out map[string]any
				json.Unmarshal(w.Body.Bytes(), &out)
				return w.Code, out
			}
			org := map[string]any{"customerType": "organization", "referenceId": "org_fixture"}
			with := func(extra map[string]any) map[string]any {
				body := map[string]any{}
				for k, v := range org {
					body[k] = v
				}
				for k, v := range extra {
					body[k] = v
				}
				return body
			}
			for _, req := range []struct {
				method, path string
				body         any
			}{
				{"POST", "/subscription/upgrade", with(map[string]any{"plan": "pro"})},
				{"GET", "/subscription/list?customerType=organization&referenceId=org_fixture", nil},
				{"GET", "/subscription/list?customerType=organization", nil},
				{"POST", "/subscription/cancel", with(map[string]any{"returnUrl": "/billing"})},
				{"POST", "/subscription/restore", with(nil)},
				{"POST", "/subscription/billing-portal", with(nil)},
			} {
				status, out := call(req.method, req.path, req.body)
				if status != 400 || out["code"] != "AUTHORIZE_REFERENCE_REQUIRED" || out["message"] != "Organization subscriptions require authorizeReference callback to be configured" {
					t.Error("an organization request without a policy was not refused", req.path, status, out)
				}
			}
			if status, _ := call("GET", "/subscription/success?"+url.Values{"callbackURL": {"/"}, "checkoutSessionId": {"cs_fixture"}, "organizationId": {"org_fixture"}}.Encode(), nil); status != 401 {
				t.Error("an organization return without a policy was not refused", status)
			}
			var rows int
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "subscription"`)).Scan(&rows); err != nil || calls.Load() != 0 || rows != 0 {
				t.Fatal("organization request without a policy reached Stripe or a reservation", calls.Load(), rows, err)
			}
			if status, out := call("GET", "/subscription/list", nil); status != 200 {
				t.Fatal("personal listing failed without an organization policy", status, out)
			}
			if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`), "cus_personal", hit.User.ID); err != nil {
				t.Fatal(err)
			}
			if status, out := call("POST", "/subscription/billing-portal", map[string]any{}); status != 200 || calls.Load() != 1 {
				t.Fatal("the personal portal failed without an organization policy", status, out, calls.Load())
			}
		})
	}
}

// A personal checkout of a membership plan keeps the caller's base price
// and quantity while an organization is active.
func TestPersonalCheckoutForSeatPlan(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		for _, seat := range []string{"price_pro", "price_member"} {
			t.Run(dialect+"/"+seat, func(t *testing.T) {
				var mu sync.Mutex
				var form url.Values
				recording := func(f *returnFixture, r *http.Request) (*http.Response, error) {
					if r.Method == "POST" && r.URL.Path == "/v1/checkout/sessions" {
						if err := r.ParseForm(); err != nil {
							return nil, err
						}
						mu.Lock()
						form = r.PostForm
						mu.Unlock()
					}
					return f.provider(r)
				}
				f := configuredReturnFixture(t, dialect, billing.Plan{Name: "pro", PriceID: "price_pro", SeatPriceID: seat}, true, recording)
				buyer := f.user("buyer")
				cookie := f.a.SessionCookie(buyer.Token, true)
				if w := f.hit(f.a, "/organization/create", strings.NewReader(`{"name":"Seat organization","slug":"seat-org"}`), cookie); w.Code != 200 {
					t.Fatal("organization create", w.Code, w.Body)
				}
				raw, _ := json.Marshal(map[string]any{"plan": "pro", "seats": 4, "successUrl": returnTemplate, "cancelUrl": "/cancel"})
				if w := f.hit(f.a, "/subscription/upgrade", bytes.NewReader(raw), cookie); w.Code != 200 {
					t.Fatal("upgrade", w.Code, w.Body)
				}
				mu.Lock()
				defer mu.Unlock()
				var seats int
				if err := f.store.db.QueryRowContext(t.Context(), f.store.bind(`SELECT "seats" FROM "subscription" WHERE "referenceId"=?`), buyer.User.ID).Scan(&seats); err != nil {
					t.Fatal(err)
				}
				if form.Get("line_items[0][price]") != "price_pro" || form.Get("line_items[0][quantity]") != "4" || form.Get("line_items[1][price]") != "" ||
					form.Get("client_reference_id") != buyer.User.ID || form.Get("metadata[organizationId]") != "" || form.Get("metadata[customerType]") == "organization" || seats != 4 {
					t.Fatal("personal checkout of a seat plan used organization seat billing", form, seats)
				}
			})
		}
	}
}

// The list endpoint returns each plan's configured limits, numbers,
// booleans, arrays and nested objects included, for personal and
// organization subscriptions, and omits them for a plan without limits.
func TestStripePlanLimits(t *testing.T) {
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
			provider := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: localBillingTransport(func(r *http.Request) (*http.Response, error) {
				return nil, errors.New("unexpected Stripe call " + r.URL.Path)
			})}, MaxNetworkRetries: sdk.Int64(0)})))
			limits := map[string]any{"projects": 5, "features": []any{"api", "sso"}, "rate": map[string]any{"requests": 1000}, "permissions": map[string]any{"admin": true, "write": false}, "bandwidth": []any{100, "GB"}}
			orgPlugin, err := organization.New(organization.Options{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			const origin = "https://billing.example"
			off := false
			a, err := plainauth.New(plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{orgPlugin,
				billing.New(billing.Options{WebhookSecret: "whsec_limits", Organization: &billing.OrganizationOptions{AuthorizeReference: func(m billing.ReferenceAuthorization) bool { return m.Role == "owner" }},
					Subscriptions: &billing.SubscriptionOptions{Client: provider, Plans: []billing.Plan{{Name: "pro", PriceID: "price_pro", Limits: limits, Group: "core"}, {Name: "basic", PriceID: "price_basic"}}}})}})
			if err != nil {
				t.Fatal(err)
			}
			// Later changes to the host's map never reach the installed plan.
			limits["projects"] = 99
			signup := func(name string) (string, *http.Cookie) {
				hit, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: name, Email: name + "@example.test", Password: "local fixture password"}, plainauth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				return hit.User.ID, a.SessionCookie(hit.Token, true)
			}
			owner, ownerCookie := signup("owner")
			other, otherCookie := signup("other")
			get := func(path string, cookie *http.Cookie) string {
				t.Helper()
				r := httptest.NewRequest("GET", origin+"/api/auth"+path, nil)
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatal(path, w.Code, w.Body)
				}
				return w.Body.String()
			}
			r := httptest.NewRequest("POST", origin+"/api/auth/organization/create", strings.NewReader(`{"name":"Limits","slug":"limits"}`))
			r.Header.Set("Origin", origin)
			r.Header.Set("Content-Type", "application/json")
			r.AddCookie(ownerCookie)
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			var group struct{ ID string }
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &group) != nil || group.ID == "" {
				t.Fatal("organization create", w.Code, w.Body)
			}
			seed := func(id, plan, reference, customer string) {
				t.Helper()
				if _, err := store.db.ExecContext(ctx, store.bind(`INSERT INTO "subscription" ("id","plan","referenceId","stripeCustomerId","stripeSubscriptionId","status","seats") VALUES(?,?,?,?,?,'active',1)`), id, plan, reference, customer, "sub_"+id); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`), "cus_owner", owner); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`), "cus_other", other); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "organization" SET "stripeCustomerId"=? WHERE "id"=?`), "cus_group", group.ID); err != nil {
				t.Fatal(err)
			}
			seed("local_owner", "pro", owner, "cus_owner")
			seed("local_group", "pro", group.ID, "cus_group")
			seed("local_other", "basic", other, "cus_other")
			const want = `"limits":{"bandwidth":[100,"GB"],"features":["api","sso"],"permissions":{"admin":true,"write":false},"projects":5,"rate":{"requests":1000}}`
			for _, body := range []string{get("/subscription/list", ownerCookie), get("/subscription/list?customerType=organization&referenceId="+group.ID, ownerCookie)} {
				if !strings.Contains(body, want) {
					t.Fatal("a plan's limits were not listed", body)
				}
			}
			if body := get("/subscription/list", otherCookie); strings.Contains(body, `"limits"`) {
				t.Fatal("a plan without limits listed some", body)
			}
			var rows []billing.Subscription
			if err := json.Unmarshal([]byte(get("/subscription/list", ownerCookie)), &rows); err != nil || len(rows) != 1 || rows[0].Limits["projects"] != float64(5) || rows[0].Limits["permissions"].(map[string]any)["admin"] != true {
				t.Fatal("listed limits did not decode", rows, err)
			}
		})
	}
}
