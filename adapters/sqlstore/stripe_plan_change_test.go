package sqlstore

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/client"
	stripeclient "github.com/Stonewrit/stonewrit-auth/client/stripe"
	billing "github.com/Stonewrit/stonewrit-auth/plugins/stripe"
	"github.com/Stonewrit/stonewrit-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
)

type changeProvider struct {
	mu             sync.Mutex
	mode           string
	calls, portals int
	form           url.Values
	onPortal       func()
}

func (p *changeProvider) RoundTrip(r *http.Request) (*http.Response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	recurring := func(interval string) map[string]any {
		return map[string]any{"interval": interval, "interval_count": 1, "usage_type": "licensed"}
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/v1/subscriptions/sub_owner":
		item := map[string]any{"id": "si_owner", "quantity": 1, "current_period_end": time.Now().Add(24 * time.Hour).Unix(),
			"price": map[string]any{"id": "price_pro", "recurring": recurring("month")}}
		items := map[string]any{"data": []any{item}}
		sub := map[string]any{"object": "subscription", "id": "sub_owner", "customer": "cus_owner", "status": "active", "items": items}
		switch p.mode {
		case "pending":
			sub["pending_update"] = map[string]any{"expires_at": time.Now().Add(time.Hour).Unix()}
		case "cancel":
			sub["cancel_at_period_end"] = true
		case "schedule":
			sub["schedule"] = "sub_sched_external"
		case "paused":
			sub["pause_collection"] = map[string]any{"behavior": "void"}
		case "foreign":
			sub["customer"] = "cus_peer"
		case "multiple":
			items["data"] = []any{item, item}
		case "paginated":
			items["has_more"] = true
		case "seats":
			item["quantity"] = 5
		case "unmapped":
			item["price"] = map[string]any{"id": "price_unknown", "recurring": recurring("month")}
		case "trial":
			sub["status"] = "trialing"
		}
		return stripeJSON(200, sub), nil
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/prices/price_"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/prices/")
		interval := "month"
		if id == "price_team_year" {
			interval = "year"
		}
		detail := recurring(interval)
		switch p.mode {
		case "metered":
			detail["usage_type"] = "metered"
		case "interval":
			detail["interval"] = "week"
		}
		return stripeJSON(200, map[string]any{"id": id, "active": p.mode != "archived", "recurring": detail}), nil
	case r.Method == "POST" && r.URL.Path == "/v1/billing_portal/sessions":
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		p.form = r.PostForm
		p.portals++
		if p.onPortal != nil {
			run := p.onPortal
			p.onPortal = nil
			run()
		}
		customer := "cus_owner"
		if p.mode == "wrongPortal" {
			customer = "cus_peer"
		}
		if p.mode == "decline" {
			return stripeJSON(400, map[string]any{"error": map[string]string{"type": "invalid_request_error", "code": "billing_portal_feature_not_enabled", "message": "Portal is unavailable"}}), nil
		}
		return stripeJSON(200, map[string]string{"id": "bps_change", "url": "https://billing.example.test/review", "customer": customer}), nil
	default:
		return nil, fmt.Errorf("unexpected Stripe plan-change operation %s %s", r.Method, r.URL.Path)
	}
}

func TestHostedSubscriptionPlanChanges(t *testing.T) {
	for _, kind := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(kind, func(t *testing.T) {
			ctx := t.Context()
			ddl, err := schema.Generate(kind, []string{"stripe-subscriptions"})
			if err != nil {
				t.Fatal(err)
			}
			db, err := OpenWithSchema(ctx, kind, organizationTestDSN(t, kind), ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			host := httptest.NewUnstartedServer(nil)
			origin := "https://" + host.Listener.Addr().String()
			provider := &changeProvider{}
			backends := sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: provider}, MaxNetworkRetries: sdk.Int64(0)})
			remote := sdk.NewClient("sk_test_local", sdk.WithBackends(backends))
			stripePlugin := billing.New(billing.Options{WebhookSecret: "whsec_local",
				Subscriptions: &billing.SubscriptionOptions{Client: remote, Plans: []billing.Plan{{Name: "pro", PriceID: "price_pro"}, {Name: "team", PriceID: "price_team", AnnualPriceID: "price_team_year"}}}})
			auth, err := stonewrit.New(stonewrit.Options{BaseURL: origin, Secret: strings.Repeat("s", 32), EmailAndPassword: true, Store: db, Plugins: []stonewrit.Plugin{stripePlugin}})
			if err != nil {
				t.Fatal(err)
			}
			host.Config.Handler = auth
			host.StartTLS()
			defer host.Close()
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := db.db.ExecContext(ctx, db.bind(sql), args...); err != nil {
					t.Fatal(err)
				}
			}
			owner := func(name string) (stripeclient.Client, string) {
				b, err := client.New(origin, host.Client())
				if err != nil {
					t.Fatal(err)
				}
				u, err := b.SignUpEmail(ctx, client.SignUpRequest{Name: name, Email: name + "@example.org", Password: "local-password"})
				if err != nil {
					t.Fatal(err)
				}
				exec(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`, "cus_"+name, u.User.ID)
				exec(`INSERT INTO "subscription" ("id","plan","referenceId","stripeCustomerId","stripeSubscriptionId","status","seats","billingInterval") VALUES(?,?,?,?,?,'active',1,'month')`, "local_"+name, "pro", u.User.ID, "cus_"+name, "sub_"+name)
				return stripeclient.Client{Auth: b}, u.User.ID
			}
			buyer, uid := owner("owner")
			peer, _ := owner("peer")
			request := stripeclient.Checkout{Plan: "team", SubscriptionID: "sub_owner", ReturnURL: "/billing/done", DisableRedirect: true}
			mustCode := func(err error, status int, code string) {
				t.Helper()
				var api *stonewrit.APIError
				if !errors.As(err, &api) || api.Status != status || api.Code != code {
					t.Fatalf("want %d %s, got %v", status, code, err)
				}
			}
			_, err = peer.Upgrade(ctx, request)
			mustCode(err, 400, "SUBSCRIPTION_NOT_FOUND")
			foreignReturn := request
			foreignReturn.ReturnURL = "https://untrusted.example/return"
			_, err = buyer.Upgrade(ctx, foreignReturn)
			mustCode(err, 403, "INVALID_CALLBACK_URL")
			exec(`INSERT INTO "subscription" ("id","plan","referenceId","stripeCustomerId","stripeSubscriptionId","status") VALUES(?,?,?,?,?,'active')`, "second", "pro", uid, "cus_owner", "sub_second")
			_, err = buyer.Upgrade(ctx, stripeclient.Checkout{Plan: "team"})
			mustCode(err, 409, "SUBSCRIPTION_ALREADY_EXISTS")
			exec(`DELETE FROM "subscription" WHERE "id"='second'`)
			if provider.calls != 0 {
				t.Fatal("provider contacted before owner, selection and callback authorization")
			}
			for _, annual := range []bool{false, true, true} {
				in := request
				in.Annual = annual
				target := "price_team"
				if annual {
					target = "price_team_year"
				} else {
					in.SubscriptionID = ""
				}
				page, err := buyer.Upgrade(ctx, in)
				if err != nil || page.URL != "https://billing.example.test/review" || page.Redirect || page.ID != "" {
					t.Fatal("targeted hosted plan confirmation", page, err)
				}
				expected := url.Values{
					"customer": {"cus_owner"}, "return_url": {origin + "/billing/done"}, "flow_data[type]": {"subscription_update_confirm"},
					"flow_data[after_completion][type]": {"redirect"}, "flow_data[after_completion][redirect][return_url]": {origin + "/billing/done"},
					"flow_data[subscription_update_confirm][subscription]": {"sub_owner"}, "flow_data[subscription_update_confirm][items][0][id]": {"si_owner"},
					"flow_data[subscription_update_confirm][items][0][quantity]": {"1"}, "flow_data[subscription_update_confirm][items][0][price]": {target}}
				if !reflect.DeepEqual(expected, provider.form) {
					t.Fatalf("wrong hosted plan confirmation: %v", provider.form)
				}
				rows, err := buyer.List(ctx)
				if err != nil || len(rows) != 1 || rows[0].Plan != "pro" {
					t.Fatal("an unconfirmed plan became active", rows, err)
				}
			}
			provider.mode = "seats" // The existing price currently bills five seats.
			samePrice := stripeclient.Checkout{Plan: "pro", Seats: 5, SubscriptionID: "sub_owner"}
			_, err = buyer.Upgrade(ctx, samePrice)
			mustCode(err, 400, "ALREADY_SUBSCRIBED_PLAN")
			defaultQuantity := samePrice
			defaultQuantity.Seats = 0 // Omitted from the native client request.
			defaultPage, err := buyer.Upgrade(ctx, defaultQuantity)
			if err != nil || defaultPage.URL == "" || provider.form.Get("flow_data[subscription_update_confirm][items][0][quantity]") != "1" {
				t.Fatal("omitted quantity did not present one seat for hosted confirmation", defaultPage, err)
			}
			if rows, err := buyer.List(ctx); err != nil || len(rows) != 1 || rows[0].Seats == nil || *rows[0].Seats != 5 {
				t.Fatal("five seats changed before the customer confirmed", rows, err)
			}
			samePrice.Seats = 7
			page, err := buyer.Upgrade(ctx, samePrice)
			if err != nil || page.URL == "" || provider.form.Get("flow_data[subscription_update_confirm][items][0][quantity]") != "7" {
				t.Fatal("quantity-only hosted confirmation", page, err)
			}
			if rows, err := buyer.List(ctx); err != nil || len(rows) != 1 || rows[0].Seats == nil || *rows[0].Seats != 5 {
				t.Fatal("hosted change applied seats before confirmation", rows, err)
			}
			provider.onPortal = func() { exec(`UPDATE "subscription" SET "seats"=3 WHERE "id"='local_owner'`) }
			page, err = buyer.Upgrade(ctx, samePrice)
			mustCode(err, 409, "CHECKOUT_RECONCILIATION_REQUIRED")
			if page.URL != "" {
				t.Fatal("a concurrent seat change exposed a stale confirmation")
			}
			samePrice.ScheduleAtPeriodEnd = true
			_, err = buyer.Upgrade(ctx, samePrice)
			mustCode(err, 409, "UNSUPPORTED_SCHEDULE_QUANTITY")
			for _, tc := range []struct {
				mode   string
				status int
				code   string
			}{
				{"pending", 409, "SUBSCRIPTION_PENDING_CHANGE"}, {"cancel", 409, "SUBSCRIPTION_PENDING_CHANGE"}, {"schedule", 409, "SUBSCRIPTION_PENDING_CHANGE"},
				{"paused", 409, "SUBSCRIPTION_PENDING_CHANGE"}, {"foreign", 409, "CHECKOUT_RECONCILIATION_REQUIRED"}, {"multiple", 409, "UNSUPPORTED_SUBSCRIPTION_ITEM"},
				{"paginated", 409, "UNSUPPORTED_SUBSCRIPTION_ITEM"}, {"unmapped", 409, "UNSUPPORTED_SUBSCRIPTION_ITEM"},
				{"metered", 409, "UNSUPPORTED_SUBSCRIPTION_ITEM"}, {"interval", 409, "UNSUPPORTED_SUBSCRIPTION_ITEM"}, {"archived", 409, "UNSUPPORTED_SUBSCRIPTION_ITEM"},
				{"wrongPortal", 502, "UNABLE_TO_CREATE_BILLING_PORTAL"}, {"decline", 400, "billing_portal_feature_not_enabled"},
			} {
				t.Run(tc.mode, func(t *testing.T) {
					exec(`UPDATE "subscription" SET "status"='active',"plan"='pro',"billingInterval"='month',"cancelAtPeriodEnd"=?,"stripeScheduleId"=NULL WHERE "id"='local_owner'`, false)
					provider.mu.Lock()
					provider.mode = tc.mode
					portals := provider.portals
					provider.mu.Unlock()
					page, err := buyer.Upgrade(ctx, request)
					mustCode(err, tc.status, tc.code)
					if page.URL != "" {
						t.Fatal("rejected change disclosed a confirmation link")
					}
					if tc.mode != "wrongPortal" && tc.mode != "decline" && provider.portals != portals {
						t.Fatal("ineligible subscription reached portal")
					}
				})
			}
			provider.mu.Lock()
			provider.mode = "trial"
			provider.mu.Unlock()
			page, err = buyer.Upgrade(ctx, stripeclient.Checkout{Plan: "pro", SubscriptionID: "sub_owner"})
			if err != nil || !page.Redirect || provider.form.Get("return_url") != origin+"/" {
				t.Fatal("trialing plan confirmation or default return", page, err)
			}
			provider.mu.Lock()
			provider.mode = ""
			provider.onPortal = func() {
				if _, err := db.db.ExecContext(ctx, db.bind(`DELETE FROM "session" WHERE "userId"=?`), uid); err != nil {
					t.Error(err)
				}
			}
			provider.mu.Unlock()
			page, err = buyer.Upgrade(ctx, request)
			mustCode(err, 401, "UNAUTHORIZED")
			if page.URL != "" {
				t.Fatal("a revoked session received a hosted confirmation")
			}
		})
	}
}
