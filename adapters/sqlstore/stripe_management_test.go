package sqlstore

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	stripeclient "github.com/Plain-Org/plain-auth/client/stripe"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
)

// stripeFailure is a Stripe API error the fake returns instead of a result;
// code may be empty, as Stripe sends for many refusals.
type stripeFailure struct {
	status        int
	code, message string
}

func stripeError(f stripeFailure) *http.Response {
	body := map[string]string{"type": "invalid_request_error", "message": f.message}
	if f.code != "" {
		body["code"] = f.code
	}
	return stripeJSON(f.status, map[string]any{"error": body})
}

type managementProvider struct {
	mu                                           sync.Mutex
	origin, customer, schedule, scheduleCustomer string
	// status and scheduleStatus report active when empty.
	status, scheduleStatus string
	// periodEnd is fixed on first use.
	periodEnd, cancelAt, canceledAt int64
	atEnd, missing                  bool
	portalError, updateError        *stripeFailure
	scheduleError, releaseError     *stripeFailure
	// onPortal runs under mu and only assigns fields.
	onPortal func()
	// others are more subscriptions of the same customer, item and period,
	// by ID and status, with no pending cancellation.
	others                            map[string]string
	portalForm, updateForm            url.Values
	updates, releases, calls, portals int
}

// form is a copy of the last portal form.
func (p *managementProvider) form() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return maps.Clone(p.portalForm)
}

// lastUpdate is a copy of the last subscription update form.
func (p *managementProvider) lastUpdate() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return maps.Clone(p.updateForm)
}

func (p *managementProvider) subscription(id, status string) map[string]any {
	if p.periodEnd == 0 {
		p.periodEnd = time.Now().Add(24 * time.Hour).Unix()
	}
	if status == "" {
		status = "active"
	}
	// Only sub_fixture carries the fixture's pending cancellation.
	cancelAt, atEnd, canceledAt := p.cancelAt, p.atEnd, p.canceledAt
	if id != "sub_fixture" {
		cancelAt, atEnd, canceledAt = 0, false, 0
	}
	data := map[string]any{"id": id, "object": "subscription", "customer": p.customer, "status": status, "cancel_at": cancelAt, "cancel_at_period_end": atEnd, "canceled_at": canceledAt,
		"items": map[string]any{"data": []any{map[string]any{"id": "si_fixture", "quantity": 1, "price": map[string]any{"id": "price_pro", "recurring": map[string]any{"interval": "month", "interval_count": 1, "usage_type": "licensed"}}, "current_period_start": 100, "current_period_end": p.periodEnd}}}}
	if status == "canceled" {
		data["ended_at"] = p.periodEnd - 3600
	}
	if p.schedule != "" && id == "sub_fixture" {
		data["schedule"] = p.schedule
	}
	return data
}

func (p *managementProvider) RoundTrip(r *http.Request) (*http.Response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	path := r.URL.Path
	switch {
	case path == "/v1/subscriptions/sub_fixture":
		if p.missing {
			return stripeError(stripeFailure{404, "resource_missing", "No such subscription: 'sub_fixture'"}), nil
		}
		if r.Method == "POST" {
			if p.updateError != nil {
				return stripeError(*p.updateError), nil
			}
			switch {
			case p.cancelAt != 0 && r.PostForm.Has("cancel_at") && r.PostForm.Get("cancel_at") == "" && !r.PostForm.Has("cancel_at_period_end"):
				// Unsetting cancel_at also clears a period-end cancellation.
				p.cancelAt, p.atEnd = 0, false
			case p.atEnd && r.PostForm.Get("cancel_at_period_end") == "false" && !r.PostForm.Has("cancel_at"):
				p.atEnd = false
			default:
				return nil, errors.New("wrong Stripe restore parameters")
			}
			p.canceledAt = 0
			p.updateForm = maps.Clone(r.PostForm)
			p.updates++
		}
		return stripeJSON(200, p.subscription("sub_fixture", p.status)), nil
	case strings.HasPrefix(path, "/v1/subscriptions/") && p.others[strings.TrimPrefix(path, "/v1/subscriptions/")] != "" && r.Method == "GET":
		id := strings.TrimPrefix(path, "/v1/subscriptions/")
		return stripeJSON(200, p.subscription(id, p.others[id])), nil
	case path == "/v1/billing_portal/sessions" && r.Method == "POST":
		if r.PostForm.Get("return_url") != p.origin+"/billing" {
			return nil, errors.New("wrong portal return")
		}
		p.portalForm = maps.Clone(r.PostForm)
		p.portals++
		if p.onPortal != nil {
			p.onPortal()
		}
		if p.portalError != nil {
			return stripeError(*p.portalError), nil
		}
		return stripeJSON(200, map[string]string{"id": "bps_fixture", "url": "https://billing.stripe.test/fixture", "customer": r.PostForm.Get("customer")}), nil
	case path == "/v1/subscription_schedules/sched_fixture" && r.Method == "GET":
		if p.scheduleError != nil {
			return stripeError(*p.scheduleError), nil
		}
		status := p.scheduleStatus
		if status == "" {
			status = "active"
		}
		return stripeJSON(200, map[string]string{"id": p.schedule, "customer": p.scheduleCustomer, "status": status, "subscription": "sub_fixture"}), nil
	case path == "/v1/subscription_schedules/sched_fixture/release" && r.Method == "POST":
		if p.releaseError != nil {
			return stripeError(*p.releaseError), nil
		}
		p.releases++
		p.schedule = ""
		return stripeJSON(200, map[string]string{"id": "sched_fixture", "status": "released", "released_subscription": "sub_fixture"}), nil
	default:
		return nil, fmt.Errorf("unexpected request %s %s", r.Method, path)
	}
}

func TestOwnerSubscriptionManagement(t *testing.T) {
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
			p := &managementProvider{origin: origin, customer: "cus_owner", scheduleCustomer: "cus_owner"}
			backends := sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: p}, MaxNetworkRetries: sdk.Int64(0)})
			remote := sdk.NewClient("sk_test_local", sdk.WithBackends(backends))
			plugin := billing.New(billing.Options{WebhookSecret: "whsec_local",
				Portal:        &billing.PortalOptions{Client: remote, Customers: db},
				Subscriptions: &billing.SubscriptionOptions{Client: remote, RequireEmailVerification: true, Plans: []billing.Plan{{Name: "Pro", PriceID: "price_pro"}}}})
			instance, err := plainauth.New(plainauth.Options{BaseURL: origin, Secret: strings.Repeat("s", 32), EmailAndPassword: true, Store: db, Plugins: []plainauth.Plugin{plugin}})
			if err != nil {
				t.Fatal(err)
			}
			host.Config.Handler = instance
			host.StartTLS()
			t.Cleanup(host.Close)
			browser := func() stripeclient.Client {
				c, err := client.New(origin, host.Client())
				if err != nil {
					t.Fatal(err)
				}
				return stripeclient.Client{Auth: c}
			}
			mustCode := func(err error, status int, code string) {
				t.Helper()
				var api *plainauth.APIError
				if !errors.As(err, &api) || api.Status != status || api.Code != code {
					t.Fatalf("expected %d %s, got %v", status, code, err)
				}
			}
			a, b := browser(), browser()
			_, err = a.Cancel(ctx, stripeclient.Cancellation{ReturnURL: "/billing"})
			mustCode(err, 401, "UNAUTHORIZED")
			create := func(b stripeclient.Client, email string) string {
				u, err := b.Auth.SignUpEmail(ctx, client.SignUpRequest{Email: email, Name: "Account", Password: "local-password"})
				if err != nil {
					t.Fatal(err)
				}
				return u.User.ID
			}
			uid := create(a, "owner@example.org")
			create(b, "peer@example.org")
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := db.db.ExecContext(ctx, db.bind(q), args...); err != nil {
					t.Fatal(err)
				}
			}
			exec(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`, "cus_owner", uid)
			exec(`INSERT INTO "subscription" ("id","plan","referenceId","stripeCustomerId","stripeSubscriptionId","status","seats") VALUES(?,?,?,?,?,'active',1)`, "local_fixture", "pro", uid, "cus_owner", "sub_fixture")
			upgrade := stripeclient.Checkout{Plan: "pro", SuccessURL: "/ok", CancelURL: "/billing"}
			_, err = a.Upgrade(ctx, upgrade)
			mustCode(err, 400, "EMAIL_VERIFICATION_REQUIRED")
			exec(`UPDATE "user" SET "emailVerified"=? WHERE "id"=?`, true, uid)
			_, err = a.Upgrade(ctx, upgrade)
			mustCode(err, 400, "ALREADY_SUBSCRIBED_PLAN")
			beforeForeign := p.calls
			cancellation := stripeclient.Cancellation{SubscriptionID: "sub_fixture", ReturnURL: "/billing", DisableRedirect: true}
			_, err = b.Cancel(ctx, cancellation)
			mustCode(err, 400, "SUBSCRIPTION_NOT_FOUND")
			_, err = b.Restore(ctx, "sub_fixture")
			mustCode(err, 400, "SUBSCRIPTION_NOT_FOUND")
			_, err = a.Cancel(ctx, stripeclient.Cancellation{ReturnURL: "https://foreign.example/"})
			if err == nil {
				t.Fatal("accepted foreign portal return")
			}
			if p.calls != beforeForeign {
				t.Fatal("foreign request reached billing provider")
			}
			page, err := a.Cancel(ctx, cancellation)
			if form := p.form(); err != nil || page.Redirect || page.URL != "https://billing.stripe.test/fixture" || form.Get("customer") != "cus_owner" ||
				form.Get("flow_data[type]") != "subscription_cancel" || form.Get("flow_data[subscription_cancel][subscription]") != "sub_fixture" {
				t.Fatal("targeted cancellation portal", page, err)
			}
			page, err = a.BillingPortal(ctx, stripeclient.Portal{ReturnURL: "/billing"})
			if form := p.form(); err != nil || !page.Redirect || form.Get("customer") != "cus_owner" || form.Has("flow_data[type]") {
				t.Fatal("account portal", page, err)
			}
			_, err = a.Restore(ctx, "sub_fixture")
			mustCode(err, 400, "SUBSCRIPTION_NOT_PENDING_CHANGE")
			p.mu.Lock()
			p.atEnd = true
			p.mu.Unlock()
			result, err := a.Restore(ctx, "")
			if err != nil || result.CancelAtPeriodEnd || result.ID != "sub_fixture" {
				t.Fatal("period-end restoration", err)
			}
			p.mu.Lock()
			p.cancelAt = 1870000000
			p.mu.Unlock()
			result, err = a.Restore(ctx, "sub_fixture")
			if err != nil || result.CancelAt != 0 {
				t.Fatal("explicit cancellation date restoration", err)
			}
			p.mu.Lock()
			p.schedule = "sched_fixture"
			p.scheduleCustomer = "cus_foreign"
			p.mu.Unlock()
			_, err = a.Restore(ctx, "sub_fixture")
			mustCode(err, 409, "CHECKOUT_RECONCILIATION_REQUIRED")
			p.mu.Lock()
			p.scheduleCustomer = p.customer
			p.mu.Unlock()
			result, err = a.Restore(ctx, "")
			if err != nil || result.Schedule != nil {
				t.Fatal("scheduled change restoration", err)
			}
			rows, err := a.List(ctx)
			if err != nil || len(rows) != 1 || rows[0].ScheduleID != nil || rows[0].CancelAt != nil || (rows[0].CancelAtPeriodEnd != nil && *rows[0].CancelAtPeriodEnd) {
				t.Fatal("restoration did not persist current Stripe state", rows, err)
			}
			if p.releases != 1 || p.updates != 2 {
				t.Fatal("unexpected provider mutations", p.releases, p.updates)
			}
		})
	}
}
