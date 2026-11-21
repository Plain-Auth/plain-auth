package sqlstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/client"
	stripeclient "github.com/Stonewrit/stonewrit-auth/client/stripe"
	org "github.com/Stonewrit/stonewrit-auth/plugins/organization"
	billing "github.com/Stonewrit/stonewrit-auth/plugins/stripe"
	"github.com/Stonewrit/stonewrit-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

func TestOrganizationBillingIsolation(t *testing.T) {
	const protectedOrganization = "RestrictedBillingOrg"
	for _, kind := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(kind, func(t *testing.T) {
			ctx := t.Context()
			ddl, err := schema.Generate(kind, []string{"stripe-organization"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(ctx, kind, organizationTestDSN(t, kind), ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := store.db.ExecContext(ctx, store.bind(q), args...); err != nil {
					t.Fatal(err)
				}
			}
			host := httptest.NewUnstartedServer(nil)
			origin := "https://" + host.Listener.Addr().String()
			var group, actor, createKey, successURL string
			var receipt map[string]string
			var beforeCheckout, beforePortal func()
			var calls, checkoutCalls int
			currentPrice := "price_basic"
			currentStatus := "active"
			now := time.Now().Unix()
			subscription := func() map[string]any {
				return map[string]any{"id": "sub_group", "object": "subscription", "customer": "cus_group", "status": currentStatus, "metadata": receipt, "items": map[string]any{"data": []any{map[string]any{"id": "si_group", "quantity": 1, "current_period_start": now, "current_period_end": now + 86400, "price": map[string]any{"id": currentPrice, "recurring": map[string]string{"interval": "month"}}}}}}
			}
			checkout := func() map[string]any {
				return map[string]any{"id": "cs_group", "object": "checkout.session", "url": "https://checkout.example.test/group", "mode": "subscription", "customer": "cus_group", "client_reference_id": group, "metadata": receipt, "subscription": "sub_group", "status": "complete", "payment_status": "paid"}
			}
			transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if err := r.ParseForm(); err != nil {
					return nil, err
				}
				switch r.URL.Path {
				case "/v1/customers/search":
					if !strings.Contains(r.Form.Get("query"), group) {
						return nil, errors.New("wrong organization search reference")
					}
					return stripeJSON(400, map[string]any{"error": map[string]string{"code": "search_not_available", "type": "invalid_request_error"}}), nil
				case "/v1/customers":
					if r.Method != "GET" {
						return nil, errors.New("created a duplicate organization customer")
					}
					return stripeJSON(200, map[string]any{"object": "list", "has_more": false, "data": []any{
						map[string]any{"id": "cus_personal", "metadata": map[string]string{"userId": actor, "customerType": "user"}},
						map[string]any{"id": "cus_group", "metadata": map[string]string{"organizationId": group, "customerType": "organization"}}}}), nil
				case "/v1/checkout/sessions":
					createdKey := r.Header.Get("Idempotency-Key")
					if r.PostForm.Get("customer") != "cus_group" || r.PostForm.Get("client_reference_id") != group || r.PostForm.Get("line_items[0][price]") != "price_basic" || r.PostForm.Get("line_items[0][quantity]") != "1" || createdKey == "" || (createKey != "" && createdKey != createKey) {
						return nil, errors.New("changed organization checkout identity")
					}
					createKey = createdKey
					receipt = map[string]string{}
					for _, key := range []string{"userId", "referenceId", "organizationId", "customerType", "subscriptionId", "checkoutAttemptId"} {
						receipt[key] = r.PostForm.Get("metadata[" + key + "]")
						if receipt[key] == "" || receipt[key] != r.PostForm.Get("subscription_data[metadata]["+key+"]") {
							return nil, errors.New("invalid organization checkout metadata")
						}
					}
					if receipt["userId"] != actor || receipt["referenceId"] != group || receipt["organizationId"] != group || receipt["customerType"] != "organization" {
						return nil, errors.New("wrong purchaser or organization")
					}
					successURL = strings.ReplaceAll(r.PostForm.Get("success_url"), "{CHECKOUT_SESSION_ID}", "cs_group")
					if beforeCheckout != nil {
						fn := beforeCheckout
						beforeCheckout = nil
						fn()
					}
					checkoutCalls++
					return stripeJSON(200, checkout()), nil
				case "/v1/subscriptions/sub_group":
					return stripeJSON(200, subscription()), nil
				case "/v1/checkout/sessions/cs_group":
					return stripeJSON(200, checkout()), nil
				case "/v1/billing_portal/sessions":
					customer := r.PostForm.Get("customer")
					if beforePortal != nil {
						fn := beforePortal
						beforePortal = nil
						fn()
					}
					return stripeJSON(200, map[string]string{"id": "bps", "url": "https://billing.example.test/" + customer, "customer": customer}), nil
				default:
					return nil, fmt.Errorf("unexpected request %s", r.URL.Path)
				}
			})
			backend := sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})
			provider := sdk.NewClient("sk_test_local", sdk.WithBackends(backend))
			orgPlugin, err := org.New(org.Options{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			stripePlugin := billing.New(billing.Options{WebhookSecret: "whsec_local_org", Portal: &billing.PortalOptions{Client: provider, Customers: store}, Subscriptions: &billing.SubscriptionOptions{Client: provider, Plans: []billing.Plan{{Name: "basic", PriceID: "price_basic"}, {Name: "pro", PriceID: "price_pro"}}},
				Organization: &billing.OrganizationOptions{AuthorizeReference: func(policy billing.ReferenceAuthorization) bool {
					if policy.OrganizationID == protectedOrganization {
						return false
					}
					return policy.Role == "owner" || policy.Role == "admin" || (policy.Role == "finance" && policy.Action == "list-subscription")
				}}})
			off := false
			auth, err := stonewrit.New(stonewrit.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off, Plugins: []stonewrit.Plugin{orgPlugin, stripePlugin}})
			if err != nil {
				t.Fatal(err)
			}
			host.Config.Handler = auth
			host.StartTLS()
			defer host.Close()
			register := func(name string) (stripeclient.Client, string, string) {
				t.Helper()
				native, err := client.New(origin, host.Client())
				if err != nil {
					t.Fatal(err)
				}
				u, err := native.SignUpEmail(ctx, client.SignUpRequest{Name: name, Email: name + "@example.test", Password: "local-password"})
				if err != nil {
					t.Fatal(err)
				}
				if u.Token == nil {
					t.Fatal("missing fixture login session")
				}
				return stripeclient.Client{Auth: native}, u.User.ID, *u.Token
			}
			buyer, uid, buyerToken := register("buyer")
			actor = uid
			deputy, did, deputyToken := register("deputy")
			outsider, _, outToken := register("outside")
			var created org.Organization
			if err := buyer.Auth.Do(ctx, "POST", "/organization/create", map[string]string{"name": "Fixture organization", "slug": "billing-org"}, &created); err != nil {
				t.Fatal(err)
			}
			group = created.ID
			exec(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`, "cus_personal", actor)
			exec(`INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES(?,?,?,?,?)`, "deputy_member", group, did, "finance", store.date(time.Now()))
			code := func(err error, status int, label string) {
				t.Helper()
				var api *stonewrit.APIError
				if !errors.As(err, &api) || api.Status != status || api.Code != label {
					t.Fatalf("expected %d/%s: %v", status, label, err)
				}
			}
			want := stripeclient.Checkout{Plan: "basic", CustomerType: "organization", SuccessURL: "/receipt", CancelURL: "/billing", DisableRedirect: true}
			exec(`INSERT INTO "organization" ("id","name","slug","createdAt","stripeCustomerId") VALUES(?,?,?,?,?)`, protectedOrganization, "Restricted billing", "restricted", store.date(time.Now()), "cus_restricted")
			exec(`INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES(?,?,?,?,?)`, "restricted_owner", protectedOrganization, actor, "owner", store.date(time.Now()))
			for _, reference := range []string{protectedOrganization, strings.ToLower(protectedOrganization)} {
				page, err := buyer.BillingPortal(ctx, stripeclient.Portal{CustomerType: "organization", ReferenceID: reference})
				code(err, 401, "UNAUTHORIZED")
				if page.URL != "" {
					t.Fatal("protected organization returned a billing portal URL")
				}
				checkout := want
				checkout.ReferenceID = reference
				page, err = buyer.Upgrade(ctx, checkout)
				code(err, 401, "UNAUTHORIZED")
				if page.URL != "" || calls != 0 {
					t.Fatal("protected organization reached Stripe")
				}
			}
			var pending int
			if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM subscription").Scan(&pending); err != nil || pending != 0 {
				t.Fatal("denied organization spelling persisted a checkout", pending, err)
			}
			withID := want
			withID.ReferenceID = group
			_, err = outsider.Upgrade(ctx, withID)
			code(err, 401, "UNAUTHORIZED")
			_, err = deputy.Upgrade(ctx, withID)
			code(err, 401, "UNAUTHORIZED")
			if _, err = deputy.ListOrganization(ctx, group); err != nil {
				t.Fatal(err)
			}
			if calls != 0 {
				t.Fatal("unauthorized organizational purchase reached Stripe")
			}
			beforeCheckout = func() { exec(`UPDATE "member" SET "role"='member' WHERE "userId"=?`, actor) }
			page, err := buyer.Upgrade(ctx, want)
			code(err, 401, "UNAUTHORIZED")
			if page.URL != "" {
				t.Fatal("downgraded purchaser saw a hosted checkout")
			}
			exec(`UPDATE "member" SET "role"='admin' WHERE "userId"=?`, did)
			page, err = deputy.Upgrade(ctx, withID)
			if err != nil || page.URL != "https://checkout.example.test/group" || checkoutCalls != 2 {
				t.Fatal("authorized recovery of the original checkout", page, err, checkoutCalls)
			}
			page, err = deputy.Upgrade(ctx, withID)
			if err != nil || page.ID != "cs_group" || checkoutCalls != 2 {
				t.Fatal("cached organization checkout was recreated", err)
			}
			portal := stripeclient.Portal{CustomerType: "organization", ReferenceID: group, ReturnURL: "/billing"}
			beforePortal = func() { exec(`UPDATE "member" SET "role"='finance' WHERE "userId"=?`, did) }
			page, err = deputy.BillingPortal(ctx, portal)
			code(err, 401, "UNAUTHORIZED")
			if page.URL != "" {
				t.Fatal("changed billing role received a portal link")
			}
			exec(`UPDATE "member" SET "role"='admin' WHERE "userId"=?`, did)
			if err := deputy.Auth.Do(ctx, "POST", "/organization/set-active", map[string]string{"organizationId": group}, nil); err != nil {
				t.Fatal(err)
			}
			beforePortal = func() { exec(`UPDATE "session" SET "activeOrganizationId"=NULL WHERE "userId"=?`, did) }
			page, err = deputy.BillingPortal(ctx, stripeclient.Portal{CustomerType: "organization"})
			code(err, 401, "UNAUTHORIZED")
			if page.URL != "" {
				t.Fatal("a changed implicit organization received a portal link")
			}
			if page, err = buyer.BillingPortal(ctx, stripeclient.Portal{}); err != nil || page.URL != "https://billing.example.test/cus_personal" {
				t.Fatal("personal billing customer changed", page, err)
			}
			returnStatus := func(token string) int {
				r := httptest.NewRequest("GET", successURL, nil)
				r.AddCookie(auth.SessionCookie(token, true))
				w := httptest.NewRecorder()
				auth.ServeHTTP(w, r)
				return w.Code
			}
			if got := returnStatus(outToken); got != 401 {
				t.Fatal("foreign checkout return", got)
			}
			if got := returnStatus(buyerToken); got != 401 {
				t.Fatal("downgraded checkout return", got)
			}
			signed := func(id, typ string, object any) int {
				data, _ := json.Marshal(map[string]any{"id": id, "object": "event", "type": typ, "api_version": sdk.APIVersion, "livemode": false, "created": now, "data": map[string]any{"object": object}})
				sig := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: data, Secret: "whsec_local_org"})
				r := httptest.NewRequest("POST", origin+"/api/auth/stripe/webhook", bytes.NewReader(data))
				r.Header.Set("Stripe-Signature", sig.Header)
				w := httptest.NewRecorder()
				auth.ServeHTTP(w, r)
				return w.Code
			}
			if got := signed("evt_created", "customer.subscription.created", subscription()); got != 200 {
				t.Fatal("early organization lifecycle event", got)
			}
			if got := signed("evt_checkout", "checkout.session.completed", checkout()); got != 200 {
				t.Fatal("settling bound organization checkout", got)
			}
			if got := returnStatus(deputyToken); got != 302 {
				t.Fatal("authorized organization receipt", got)
			}
			rows, err := deputy.ListOrganization(ctx, group)
			if err != nil || len(rows) != 1 || rows[0].ReferenceID != group || rows[0].PriceID != "price_basic" {
				t.Fatal("organization list after early event", rows, err)
			}
			if rows, err := buyer.List(ctx); err != nil || len(rows) != 0 {
				t.Fatal("organization charge appeared on a personal account", rows, err)
			}
			exec(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`, "cus_group", actor)
			currentPrice = "price_pro"
			if got := signed("evt_renew", "customer.subscription.updated", subscription()); got != 500 {
				t.Fatal("ambiguous customer was reconciled", got)
			}
			_, err = deputy.ListOrganization(ctx, group)
			code(err, 409, "CHECKOUT_RECONCILIATION_REQUIRED")
			exec(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`, "cus_personal", actor)
			deleteEvent := subscription()
			deleteEvent["metadata"] = map[string]string{"customerType": "user", "referenceId": actor}
			if got := signed("evt_wrong", "customer.subscription.updated", deleteEvent); got != 200 {
				t.Fatal("current provider state should take priority", got)
			}
			if got := signed("evt_renew", "customer.subscription.updated", subscription()); got != 200 {
				t.Fatal("recovery after removing duplicate customer", got)
			}
			if rows, err := deputy.ListOrganization(ctx, group); err != nil || len(rows) != 1 || rows[0].PriceID != "price_pro" {
				t.Fatal("organization renewal was not reconciled", rows, err)
			}
			exec(`INSERT INTO "organization" ("id","name","slug","createdAt") VALUES(?,?,?,?)`, actor, "Distinct organization", "org-with-user-id", store.date(time.Now()))
			_, err = buyer.List(ctx)
			code(err, 409, "CHECKOUT_RECONCILIATION_REQUIRED")
			_, err = buyer.BillingPortal(ctx, stripeclient.Portal{})
			code(err, 409, "CHECKOUT_RECONCILIATION_REQUIRED")
			exec(`DELETE FROM "organization" WHERE "id"=?`, actor)
			currentStatus = "canceled"
			if got := signed("evt_remove", "customer.subscription.deleted", subscription()); got != 200 {
				t.Fatal("organization cancellation", got)
			}
			if rows, err := deputy.ListOrganization(ctx, group); err != nil || len(rows) != 0 {
				t.Fatal("canceled organization subscription remained active", rows, err)
			}
		})
	}
}
