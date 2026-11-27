package polar

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/schema"
	"github.com/google/uuid"
	polargo "github.com/polarsource/polar-go"
)

// listProvider serves customer sessions and the customer portal lists.
type listProvider struct {
	mu       sync.Mutex
	queries  map[string]url.Values
	foreign  bool
	sessions int
	// during runs on each portal list request, before it answers.
	during func()
}

// orgCheckout is the checkout the ledger reserved for an organization.
const orgCheckout = "77777777-0000-4000-8000-000000000001"

func (p *listProvider) Do(req *http.Request) (*http.Response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if req.Header.Get("Polar-Version") != apiVersion {
		return nil, errors.New("missing Polar-Version")
	}
	now := time.Now().UTC()
	reply := func(status int, v any) (*http.Response, error) {
		raw, _ := json.Marshal(v)
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw)), Request: req}, nil
	}
	customer := func(owner string) string { return uuid.NewSHA1(uuid.NameSpaceOID, []byte(owner)).String() }
	if req.Method == "POST" && req.URL.Path == "/v1/customer-sessions/" {
		var payload map[string]any
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			return nil, err
		}
		owner, _ := payload["external_customer_id"].(string)
		if len(payload) != 1 || req.Header.Get("Authorization") != "Bearer fixture" {
			return nil, errors.New("a list session forwarded more than the external ID")
		}
		p.sessions++
		person := map[string]any{"id": customer(owner), "external_id": owner, "email": "lister@example.test", "email_verified": true, "type": "individual",
			"organization_id": merchant, "created_at": now, "deleted_at": nil, "name": "lister", "metadata": map[string]any{}, "avatar_url": "https://avatars.example.test/1"}
		return reply(201, map[string]any{"id": "4ffb29e3-05df-4096-984a-ffdd76e534ea", "customer_id": customer(owner), "customer": person, "created_at": now,
			"expires_at": now.Add(time.Hour), "return_url": nil, "token": "polar_cst_list_" + owner, "customer_portal_url": "https://polar.test/portal?customer_session_token=polar_cst_list_" + owner})
	}
	token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer polar_cst_list_")
	if token == req.Header.Get("Authorization") {
		return nil, errors.New("a portal list did not use the customer session")
	}
	owner := customer(token)
	if p.foreign {
		owner = customer("someone-else")
	}
	p.queries[req.URL.Path] = req.URL.Query()
	if p.during != nil {
		p.during()
	}
	page := map[string]any{"total_count": 3, "max_page": 2}
	switch req.URL.Path {
	case "/v1/customer-portal/benefit-grants/":
		grant := func(id string, granted, revoked bool) map[string]any {
			return map[string]any{"id": id, "created_at": now, "granted_at": now, "revoked_at": nil, "customer_id": owner, "benefit_id": "41b2b61b-bec8-4a70-ba07-d4dbe85fd399",
				"subscription_id": nil, "order_id": "7a9b29e3-05df-4096-984a-ffdd76e534ea", "is_granted": granted, "is_revoked": revoked,
				"customer": map[string]any{"id": owner, "created_at": now, "email_verified": true, "oauth_accounts": map[string]any{}}, "properties": map[string]any{"license_key": "secret-license"},
				"benefit": map[string]any{"id": "41b2b61b-bec8-4a70-ba07-d4dbe85fd399", "type": "custom", "description": "Priority support", "selectable": true, "deletable": true,
					"organization_id": merchant, "created_at": now, "metadata": map[string]any{"note": "merchant-only"}, "properties": map[string]any{},
					"organization": map[string]any{"id": merchant, "created_at": now, "name": "Merchant", "slug": "merchant", "proration_behavior": "invoice", "allow_customer_updates": true}}}
		}
		return reply(200, map[string]any{"items": []any{grant("11111111-0000-4000-8000-000000000001", true, false), grant("11111111-0000-4000-8000-000000000002", false, true)}, "pagination": page})
	case "/v1/customer-portal/orders/":
		order := func(id string, checkout any, subscription any) map[string]any {
			return map[string]any{"id": id, "created_at": now, "status": "paid", "paid": true,
				"subtotal_amount": 1000, "discount_amount": 0, "net_amount": 1000, "tax_amount": 200, "total_amount": 1200, "refunded_amount": 0, "currency": "usd",
				"billing_reason": "purchase", "billing_name": "Private Name", "billing_address": map[string]any{"country": "US", "line1": "1 Private St"}, "customer_id": owner,
				"product_id": otherProduct, "subscription_id": nil, "description": "Pro", "checkout_id": checkout, "subscription": subscription}
		}
		// A renewal names its subscription's checkout, not its own.
		renewed := map[string]any{"id": "33333333-0000-4000-8000-000000000001", "created_at": now, "modified_at": nil, "amount": 1000, "currency": "usd", "recurring_interval": "month",
			"recurring_interval_count": 1, "status": "active", "current_period_start": now, "current_period_end": now.Add(720 * time.Hour), "trial_start": nil, "trial_end": nil,
			"cancel_at_period_end": false, "canceled_at": nil, "started_at": now, "ends_at": nil, "ended_at": nil, "customer_id": owner, "product_id": otherProduct,
			"discount_id": nil, "checkout_id": orgCheckout, "customer_cancellation_reason": nil, "customer_cancellation_comment": nil}
		return reply(200, map[string]any{"items": []any{order("22222222-0000-4000-8000-000000000001", nil, renewed), order("22222222-0000-4000-8000-000000000002", "88888888-0000-4000-8000-000000000001", nil)}, "pagination": page})
	case "/v1/customer-portal/meters/":
		return reply(200, map[string]any{"items": []any{map[string]any{"id": "44444444-0000-4000-8000-000000000001", "created_at": now, "customer_id": owner,
			"meter_id": "60352a5a-2768-4016-97b8-315f585a9a6f", "consumed_units": 2.5, "credited_units": 4, "balance": 1.5,
			"meter": map[string]any{"id": "60352a5a-2768-4016-97b8-315f585a9a6f", "name": "API requests", "created_at": now, "metadata": map[string]any{"note": "merchant-only"}}}}, "pagination": page})
	case "/v1/customer-portal/subscriptions/":
		return reply(200, map[string]any{"items": []any{map[string]any{"id": "33333333-0000-4000-8000-000000000001", "created_at": now, "status": "active", "amount": 1000,
			"currency": "usd", "recurring_interval": "month", "current_period_start": now, "current_period_end": now.Add(720 * time.Hour), "cancel_at_period_end": false,
			"customer_id": owner, "product_id": otherProduct, "customer_cancellation_comment": "private comment", "checkout_id": orgCheckout}}, "pagination": page})
	}
	return nil, errors.New("unexpected provider endpoint " + req.URL.Path)
}

// The signed-in customer's granted benefits, orders and subscriptions list
// through the customer portal with only page, limit and the documented
// filter, as a subset that keeps secrets and personal details at Polar,
// and a page for another customer is refused.
func TestCustomerPortalLists(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			db, dsn := database(t, dialect)
			ddl, err := schema.Generate(dialect, nil)
			if err != nil {
				t.Fatal(err)
			}
			store, err := sqlstore.OpenWithSchema(ctx, dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			ledger, err := OpenLedger(ctx, db, dialect)
			if err != nil {
				t.Fatal(err)
			}
			remote := &listProvider{queries: map[string]url.Values{}}
			plugin, err := New(Options{Client: polargo.New(polargo.WithSecurity("fixture"), polargo.WithClient(remote)), Ledger: ledger, OrganizationID: merchant,
				Portal: &PortalOptions{URL: portalURL}, Usage: &UsageOptions{}})
			if err != nil {
				t.Fatal(err)
			}
			a, err := auth.New(auth.Options{BaseURL: host, Secret: strings.Repeat("l", 40), Store: store, EmailAndPassword: true, Plugins: []auth.Plugin{plugin}})
			if err != nil {
				t.Fatal(err)
			}
			v, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: "lister", Email: "lister@example.test", Password: "local fixture password"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			q := `UPDATE "user" SET "emailVerified"=TRUE WHERE "id"=?`
			if dialect == "mysql" {
				q = strings.ReplaceAll(q, `"`, "`")
			}
			if _, err := db.Exec(ledger.bind(q), v.User.ID); err != nil {
				t.Fatal(err)
			}
			// The ledger reserved orgCheckout for an organization.
			if _, err := db.Exec(ledger.bind(`INSERT INTO plainauth_polar_checkout (slot,attempt,owner_id,contact_hash,product,products,reference_id,merchant,success_url,return_url,checkout_id,hosted_url,status,expires_ms,changed_us) VALUES (?,?,?,?,?,?,?,?,?,?,?,'','succeeded',0,0)`),
				strings.Repeat("c", 64), uuid.NewString(), v.User.ID, strings.Repeat("d", 64), otherProduct, otherProduct, "org_acme", merchant, "https://app.test/s", "", orgCheckout); err != nil {
				t.Fatal(err)
			}
			cookie := a.SessionCookie(v.Token, true)
			get := func(path string) (int, map[string]any, string) {
				t.Helper()
				w := readPersonal(a, "GET", path, "", cookie, nil)
				var out map[string]any
				json.Unmarshal(w.Body.Bytes(), &out)
				return w.Code, out, w.Body.String()
			}
			// Benefits list only granted grants, without their secrets.
			status, out, raw := get("/customer/benefits/list?page=2&limit=5")
			items, _ := out["items"].([]any)
			if status != 200 || len(items) != 1 || items[0].(map[string]any)["description"] != "Priority support" || items[0].(map[string]any)["benefit_type"] != "custom" ||
				out["pagination"].(map[string]any)["max_page"] != 2.0 || strings.Contains(raw, "secret-license") || strings.Contains(raw, "merchant-only") {
				t.Fatal("the benefits were not listed as granted subsets", status, raw)
			}
			if got := remote.queries["/v1/customer-portal/benefit-grants/"]; got.Get("page") != "2" || got.Get("limit") != "5" {
				t.Fatal("the paging was not forwarded", got)
			}
			// Orders filter by billing type and page, leave billing details out,
			// and name the organization a renewal bills through its subscription.
			status, out, raw = get("/customer/orders/list?productBillingType=one_time&page=2&limit=7")
			orders, _ := out["items"].([]any)
			if status != 200 || len(orders) != 2 || strings.Contains(raw, "Private") || orders[0].(map[string]any)["total_amount"] != 1200.0 || out["pagination"].(map[string]any)["total_count"] != 3.0 {
				t.Fatal("the orders were not listed as subsets", status, raw)
			}
			if orders[0].(map[string]any)["reference_id"] != "org_acme" || orders[1].(map[string]any)["reference_id"] != "" {
				t.Fatal("an organization's order read as the member's own", raw)
			}
			if got := remote.queries["/v1/customer-portal/orders/"]; got.Get("product_billing_type") != "one_time" || got.Get("page") != "2" || got.Get("limit") != "7" {
				t.Fatal("the billing type and paging were not forwarded", got)
			}
			// Subscriptions filter by active and page, leave comments out, and
			// name the organization a member bought one for.
			status, out, raw = get("/customer/subscriptions/list?active=true&page=3&limit=4")
			subs, _ := out["items"].([]any)
			if status != 200 || len(subs) != 1 || strings.Contains(raw, "private comment") || subs[0].(map[string]any)["product_id"] != otherProduct || out["pagination"].(map[string]any)["max_page"] != 2.0 {
				t.Fatal("the subscriptions were not listed as subsets", status, raw)
			}
			if subs[0].(map[string]any)["reference_id"] != "org_acme" {
				t.Fatal("an organization's subscription read as the member's own", raw)
			}
			if got := remote.queries["/v1/customer-portal/subscriptions/"]; got.Get("active") != "true" || got.Get("page") != "3" || got.Get("limit") != "4" {
				t.Fatal("the active filter and paging were not forwarded", got)
			}
			// Meters list the customer's consumption, credits and balance.
			status, out, raw = get("/usage/meters/list?limit=10")
			meters, _ := out["items"].([]any)
			if status != 200 || len(meters) != 1 || meters[0].(map[string]any)["balance"] != 1.5 || meters[0].(map[string]any)["consumed_units"] != 2.5 || meters[0].(map[string]any)["credited_units"] != 4.0 ||
				meters[0].(map[string]any)["meter"].(map[string]any)["name"] != "API requests" || strings.Contains(raw, "merchant-only") {
				t.Fatal("the meters were not listed as subsets", status, raw)
			}
			if got := remote.queries["/v1/customer-portal/meters/"]; got.Get("limit") != "10" {
				t.Fatal("the meter paging was not forwarded", got)
			}
			// Other query keys, repeated or out-of-range values are refused before Polar.
			before := remote.sessions
			for _, bad := range []string{"/customer/benefits/list?active=true", "/customer/orders/list?productBillingType=lifetime", "/customer/subscriptions/list?active=yes",
				"/customer/orders/list?limit=101", "/customer/orders/list?page=0", "/usage/meters/list?meterId=other", "/customer/orders/list?page=1&page=2", "/customer/subscriptions/list?customerId=other"} {
				if status, out, _ := get(bad); status != 400 || out["code"] != "POLAR_INVALID_QUERY" {
					t.Error("an invalid list query was accepted", bad, status, out)
				}
			}
			if remote.sessions != before {
				t.Fatal("an invalid query reached Polar")
			}
			// A session revoked while Polar answers withholds the page.
			for _, path := range []string{"/customer/benefits/list", "/customer/orders/list", "/customer/subscriptions/list", "/usage/meters/list"} {
				w, err := a.SignInEmail(ctx, auth.SignInInput{Email: "lister@example.test", Password: "local fixture password"}, auth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				remote.mu.Lock()
				remote.during = func() {
					q := `DELETE FROM "session" WHERE "token"=?`
					if dialect == "mysql" {
						q = strings.ReplaceAll(q, `"`, "`")
					}
					if _, err := db.Exec(ledger.bind(q), w.Token); err != nil {
						t.Error(err)
					}
				}
				remote.mu.Unlock()
				r := readPersonal(a, "GET", path, "", a.SessionCookie(w.Token, true), nil)
				remote.mu.Lock()
				remote.during = nil
				remote.mu.Unlock()
				if r.Code != 401 || strings.Contains(r.Body.String(), "-0000-4000-8000-") {
					t.Error("a revoked session received a list", path, r.Code, r.Body.String())
				}
			}
			// A page for another customer is refused.
			remote.mu.Lock()
			remote.foreign = true
			remote.mu.Unlock()
			if status, out, _ := get("/customer/orders/list"); status != 502 || out["code"] != "POLAR_CUSTOMER_MISMATCH" {
				t.Fatal("another customer's orders were listed", status, out)
			}
			// Signed out, the lists answer 401.
			if w := readPersonal(a, "GET", "/customer/subscriptions/list", "", nil, nil); w.Code != 401 {
				t.Fatal("a signed-out list was answered", w.Code)
			}
		})
	}
}
