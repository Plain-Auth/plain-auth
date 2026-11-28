package sqlstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	stripeclient "github.com/Plain-Org/plain-auth/client/stripe"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

func TestOrganizationSubscriptionManagement(t *testing.T) {
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
			p := &scheduleProvider{start: time.Now().Add(-time.Hour).Unix(), end: time.Now().Add(30 * 24 * time.Hour).Unix()}
			backends := sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: p}, MaxNetworkRetries: sdk.Int64(0)})
			remote := sdk.NewClient("sk_test_local", sdk.WithBackends(backends))
			orgPlugin, err := org.New(org.Options{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			actions := &referenceActions{}
			stripePlugin := billing.New(billing.Options{WebhookSecret: "whsec_org_management", Organization: &billing.OrganizationOptions{AuthorizeReference: actions.wrap(func(m billing.ReferenceAuthorization) bool {
				return m.Role == "owner" || m.Role == "change-only" && m.Action == "upgrade-subscription" ||
					m.Role == "restore-only" && m.Action == "restore-subscription" || m.Role == "reader" && m.Action == "list-subscription"
			})}, Portal: &billing.PortalOptions{Client: remote, Customers: store}, Subscriptions: &billing.SubscriptionOptions{Client: remote, Plans: []billing.Plan{{Name: "basic", PriceID: "price_month"}, {Name: "team", PriceID: "price_team", AnnualPriceID: "price_year"}}}})
			off := false
			auth, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{orgPlugin, stripePlugin}})
			if err != nil {
				t.Fatal(err)
			}
			host.Config.Handler = auth
			host.StartTLS()
			defer host.Close()
			register := func(name string) (stripeclient.Client, string) {
				native, err := client.New(origin, host.Client())
				if err != nil {
					t.Fatal(err)
				}
				u, err := native.SignUpEmail(ctx, client.SignUpRequest{Email: name + "@example.test", Name: name, Password: "local-pass-123"})
				if err != nil {
					t.Fatal(err)
				}
				return stripeclient.Client{Auth: native}, u.User.ID
			}
			buyer, bid := register("buyer")
			delegate, did := register("delegate")
			var group org.Organization
			if err := buyer.Auth.Do(ctx, "POST", "/organization/create", map[string]string{"name": "Group", "slug": "billing"}, &group); err != nil {
				t.Fatal(err)
			}
			exec(`INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES(?,?,?,'reader',?)`, "delegate", group.ID, did, store.date(time.Now()))
			exec(`UPDATE "organization" SET "stripeCustomerId"=? WHERE "id"=?`, "cus_owner", group.ID)
			exec(`INSERT INTO "subscription" ("id","plan","referenceId","stripeCustomerId","stripeSubscriptionId","status","seats") VALUES(?,?,?,?,?,'active',1)`, "local_group", "basic", group.ID, "cus_owner", "sub_owner")
			exec(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`, "cus_personal", bid)
			exec(`INSERT INTO "subscription" ("id","plan","referenceId","stripeCustomerId","stripeSubscriptionId","status","seats") VALUES(?,?,?,?,?,'active',1)`, "local_person", "basic", bid, "cus_personal", "sub_personal")
			role := func(id, value string) {
				exec(`UPDATE "member" SET "role"=? WHERE "organizationId"=? AND "userId"=?`, value, group.ID, id)
			}
			mustCode := func(err error, code int, name string) {
				t.Helper()
				var api *plainauth.APIError
				if !errors.As(err, &api) || api.Status != code || api.Code != name {
					t.Fatalf("want %d %s, got %v", code, name, err)
				}
			}
			cancel := stripeclient.Cancellation{CustomerType: "organization", ReferenceID: group.ID, SubscriptionID: "sub_owner", ReturnURL: "/billing", DisableRedirect: true}
			change := stripeclient.Checkout{Plan: "team", Annual: true, CustomerType: "organization", ReferenceID: group.ID, SubscriptionID: "sub_owner", ReturnURL: "/billing", DisableRedirect: true}
			deferred := change
			deferred.ScheduleAtPeriodEnd = true
			_, err = delegate.Cancel(ctx, cancel)
			mustCode(err, 403, "UNAUTHORIZED")
			_, err = delegate.RestoreOrganization(ctx, group.ID, "sub_owner")
			mustCode(err, 403, "UNAUTHORIZED")
			_, err = delegate.Upgrade(ctx, change)
			mustCode(err, 403, "UNAUTHORIZED")
			_, err = delegate.Upgrade(ctx, deferred)
			mustCode(err, 403, "UNAUTHORIZED")
			outside := cancel
			outside.SubscriptionID = "sub_personal"
			_, err = buyer.Cancel(ctx, outside)
			mustCode(err, 400, "SUBSCRIPTION_NOT_FOUND")
			if p.calls != 0 {
				t.Fatal("unapproved management action reached the provider")
			}
			p.onPortal = func() { role(bid, "reader") }
			page, err := buyer.Cancel(ctx, cancel)
			mustCode(err, 403, "UNAUTHORIZED")
			if page.URL != "" {
				t.Fatal("revoked manager received a cancellation page")
			}
			role(bid, "owner")
			actions.expect(t, "cancel-subscription", func() { page, err = buyer.Cancel(ctx, cancel) })
			if err != nil || page.URL != "https://billing.example.test/subscription_cancel" || p.portalForm.Get("customer") != "cus_owner" || p.portalForm.Get("flow_data[subscription_cancel][subscription]") != "sub_owner" {
				t.Fatal("organization cancellation target", page, err)
			}
			signed := func(id string) {
				t.Helper()
				data, _ := json.Marshal(map[string]any{"id": id, "type": "customer.subscription.updated", "object": "event", "api_version": sdk.APIVersion, "data": map[string]any{"object": map[string]string{"id": "sub_owner", "object": "subscription", "customer": "cus_owner"}}})
				sig := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: data, Secret: "whsec_org_management"})
				r := httptest.NewRequest("POST", origin+"/api/auth/stripe/webhook", bytes.NewReader(data))
				r.Header.Set("Stripe-Signature", sig.Header)
				w := httptest.NewRecorder()
				auth.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatal("organization webhook", w.Code, w.Body.String())
				}
			}
			p.atEnd = true
			signed("evt_cancel")
			var rows []billing.Subscription
			actions.expect(t, "list-subscription", func() { rows, err = delegate.ListOrganization(ctx, group.ID) })
			if err != nil || len(rows) != 1 || rows[0].CancelAtPeriodEnd == nil || !*rows[0].CancelAtPeriodEnd {
				t.Fatal("confirmed organization cancellation", rows, err)
			}
			role(did, "restore-only")
			var sub *sdk.Subscription
			actions.expect(t, "restore-subscription", func() { sub, err = delegate.RestoreOrganization(ctx, group.ID, "sub_owner") })
			if err != nil || sub.CancelAtPeriodEnd || p.cancelUpdates != 1 {
				t.Fatal("restore role could not clear cancellation", err)
			}
			p.cancelAt = p.end
			signed("evt_cancel_at")
			sub, err = buyer.RestoreOrganization(ctx, "", "")
			if err != nil || sub.CancelAt != 0 || p.cancelUpdates != 2 {
				t.Fatal("active organization dated restoration", err)
			}
			role(did, "change-only")
			_, err = delegate.RestoreOrganization(ctx, group.ID, "sub_owner")
			mustCode(err, 403, "UNAUTHORIZED")
			p.onPriceRead = func() { role(did, "reader") }
			before := p.portals
			page, err = delegate.Upgrade(ctx, change)
			mustCode(err, 403, "UNAUTHORIZED")
			if page.URL != "" || p.portals != before {
				t.Fatal("revoked plan permission opened a confirmation")
			}
			role(did, "change-only")
			actions.expect(t, "upgrade-subscription", func() { page, err = delegate.Upgrade(ctx, change) })
			if err != nil || page.URL != "https://billing.example.test/subscription_update_confirm" || p.portalForm.Get("flow_data[subscription_update_confirm][items][0][price]") != "price_year" || p.portalForm.Get("customer") != "cus_owner" {
				t.Fatal("wrong organization plan confirmation", page, err)
			}
			resize := change
			resize.Plan, resize.Annual, resize.Seats = "basic", false, 6
			page, err = delegate.Upgrade(ctx, resize)
			if err != nil || page.URL == "" || p.portalForm.Get("flow_data[subscription_update_confirm][items][0][quantity]") != "6" || p.portalForm.Get("customer") != "cus_owner" {
				t.Fatal("organization seat confirmation targeted the wrong account or quantity", page, err)
			}
			p.onScheduleRead = func() { role(did, "reader") }
			page, err = delegate.Upgrade(ctx, deferred)
			mustCode(err, 403, "UNAUTHORIZED")
			if page.URL != "" || p.updated != 0 {
				t.Fatal("role downgrade during schedule read changed a future price")
			}
			actions.expect(t, "upgrade-subscription", func() { page, err = buyer.Upgrade(ctx, deferred) })
			if err != nil || page.URL != origin+"/billing" || p.created != 1 || p.updated != 1 || p.target != "price_year" {
				t.Fatal("new authorized manager failed to resume the same schedule", page, err)
			}
			rows, err = buyer.ListOrganization(ctx, group.ID)
			if err != nil || len(rows) != 1 || rows[0].PriceID != "price_month" || rows[0].ScheduleID == nil {
				t.Fatal("current plan changed before billing boundary", rows, err)
			}
			actions.expect(t, "billing-portal", func() {
				page, err = buyer.BillingPortal(ctx, stripeclient.Portal{CustomerType: "organization", ReferenceID: group.ID, ReturnURL: "/billing"})
			})
			if err != nil || page.URL == "" || p.portalForm.Get("customer") != "cus_owner" || p.portalForm.Has("flow_data[type]") {
				t.Fatal("organization billing portal", page, err, p.portalForm)
			}
			role(did, "restore-only")
			p.onScheduleRead = func() { role(did, "reader") }
			_, err = delegate.RestoreOrganization(ctx, group.ID, "sub_owner")
			mustCode(err, 403, "UNAUTHORIZED")
			if p.released != 0 {
				t.Fatal("revoked restore permission released the schedule")
			}
			if _, err = buyer.RestoreOrganization(ctx, "", "sub_owner"); err != nil || p.released != 1 {
				t.Fatal("authorized schedule restoration failed", err)
			}
			for _, loseRelease := range []bool{false, true} {
				role(did, "change-only")
				p.loseCreate = true
				_, err = delegate.Upgrade(ctx, deferred)
				mustCode(err, 502, "STRIPE_SUBSCRIPTION_UNAVAILABLE")
				lostSchedule, lostKey := p.attached, p.createKey
				if lostSchedule == "" || p.target != "" {
					t.Fatal("fixture did not attach the unconfirmed schedule")
				}
				p.loseRelease = loseRelease
				_, err = buyer.RestoreOrganization(ctx, group.ID, "sub_owner")
				if loseRelease {
					mustCode(err, 502, "STRIPE_SUBSCRIPTION_UNAVAILABLE")
				} else if err != nil {
					t.Fatal("a second manager could not release the unconfirmed schedule", err)
				}
				if p.lastReleased != lostSchedule || p.attached != "" {
					t.Fatal("restore did not release the exact schedule")
				}
				next := deferred
				next.Annual = false
				page, err = delegate.Upgrade(ctx, next)
				if err != nil || page.URL == "" || p.attached == "" || p.attached == lostSchedule || p.createKey == lostKey || p.target != "price_team" {
					t.Fatal("a released unconfirmed schedule blocked a new destination", err)
				}
				if _, err = buyer.RestoreOrganization(ctx, group.ID, "sub_owner"); err != nil {
					t.Fatal("restoring the replacement schedule", err)
				}
			}
			personal, err := buyer.List(ctx)
			if err != nil || len(personal) != 1 || personal[0].SubscriptionID == nil || *personal[0].SubscriptionID != "sub_personal" || personal[0].ScheduleID != nil {
				t.Fatal("organization operations changed personal billing", personal, err)
			}
		})
	}
}

// referenceActions records the action of every organization policy check.
type referenceActions struct {
	mu   sync.Mutex
	seen []string
}

func (r *referenceActions) wrap(policy func(billing.ReferenceAuthorization) bool) func(billing.ReferenceAuthorization) bool {
	return func(m billing.ReferenceAuthorization) bool {
		r.mu.Lock()
		r.seen = append(r.seen, m.Action)
		r.mu.Unlock()
		return policy(m)
	}
}

// expect clears the record, runs call, and fails unless at least one check
// ran and every check named action.
func (r *referenceActions) expect(t *testing.T, action string, call func()) {
	t.Helper()
	r.mu.Lock()
	r.seen = nil
	r.mu.Unlock()
	call()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.seen) == 0 {
		t.Fatal("no policy check ran for", action)
	}
	for _, seen := range r.seen {
		if seen != action {
			t.Fatal("the policy received", seen, "for", action, r.seen)
		}
	}
}
