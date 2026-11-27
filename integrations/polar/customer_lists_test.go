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
}

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
		return reply(200, map[string]any{"items": []any{map[string]any{"id": "22222222-0000-4000-8000-000000000001", "created_at": now, "status": "paid", "paid": true,
			"subtotal_amount": 1000, "discount_amount": 0, "net_amount": 1000, "tax_amount": 200, "total_amount": 1200, "refunded_amount": 0, "currency": "usd",
			"billing_reason": "purchase", "billing_name": "Private Name", "billing_address": map[string]any{"country": "US", "line1": "1 Private St"}, "customer_id": owner,
			"product_id": otherProduct, "subscription_id": nil, "description": "Pro"}}, "pagination": page})
	case "/v1/customer-portal/subscriptions/":
		return reply(200, map[string]any{"items": []any{map[string]any{"id": "33333333-0000-4000-8000-000000000001", "created_at": now, "status": "active", "amount": 1000,
			"currency": "usd", "recurring_interval": "month", "current_period_start": now, "current_period_end": now.Add(720 * time.Hour), "cancel_at_period_end": false,
			"customer_id": owner, "product_id": otherProduct, "customer_cancellation_comment": "private comment"}}, "pagination": page})
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
				Portal: &PortalOptions{URL: portalURL}})
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
			// Orders filter by billing type and leave billing details out.
			status, out, raw = get("/customer/orders/list?productBillingType=one_time")
			if status != 200 || len(out["items"].([]any)) != 1 || strings.Contains(raw, "Private") || out["items"].([]any)[0].(map[string]any)["total_amount"] != 1200.0 {
				t.Fatal("the orders were not listed as subsets", status, raw)
			}
			if got := remote.queries["/v1/customer-portal/orders/"]; got.Get("product_billing_type") != "one_time" {
				t.Fatal("the billing type was not forwarded", got)
			}
			// Subscriptions filter by active and leave comments out.
			status, out, raw = get("/customer/subscriptions/list?active=true")
			if status != 200 || len(out["items"].([]any)) != 1 || strings.Contains(raw, "private comment") || out["items"].([]any)[0].(map[string]any)["product_id"] != otherProduct {
				t.Fatal("the subscriptions were not listed as subsets", status, raw)
			}
			if got := remote.queries["/v1/customer-portal/subscriptions/"]; got.Get("active") != "true" {
				t.Fatal("the active filter was not forwarded", got)
			}
			// Other query keys, repeated or out-of-range values are refused before Polar.
			before := remote.sessions
			for _, bad := range []string{"/customer/benefits/list?active=true", "/customer/orders/list?productBillingType=lifetime", "/customer/subscriptions/list?active=yes",
				"/customer/orders/list?limit=101", "/customer/orders/list?page=0", "/customer/orders/list?page=1&page=2", "/customer/subscriptions/list?customerId=other"} {
				if status, out, _ := get(bad); status != 400 || out["code"] != "POLAR_INVALID_QUERY" {
					t.Error("an invalid list query was accepted", bad, status, out)
				}
			}
			if remote.sessions != before {
				t.Fatal("an invalid query reached Polar")
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
