package sqlstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	stripeclient "github.com/Plain-Org/plain-auth/client/stripe"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

// managementFixture serves, over TLS on one SQL engine, an owner with
// customer cus_owner holding local_fixture/sub_fixture and a peer with
// customer cus_peer holding local_peer/sub_peer.
type managementFixture struct {
	t               *testing.T
	store           *Store
	p               *managementProvider
	auth            *plainauth.Auth
	origin          string
	owner, peer     stripeclient.Client
	ownerID, peerID string
	events          int
}

func newManagementFixture(t *testing.T, kind string) *managementFixture {
	t.Helper()
	ddl, err := schema.Generate(kind, []string{"stripe-subscriptions"})
	if err != nil {
		t.Fatal(err)
	}
	f := &managementFixture{t: t}
	f.store, err = OpenWithSchema(t.Context(), kind, organizationTestDSN(t, kind), ddl)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	host := httptest.NewUnstartedServer(nil)
	f.origin = "https://" + host.Listener.Addr().String()
	f.p = &managementProvider{origin: f.origin, customer: "cus_owner", scheduleCustomer: "cus_owner", others: map[string]string{}}
	remote := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: f.p}, MaxNetworkRetries: sdk.Int64(0)})))
	plugin := billing.New(billing.Options{WebhookSecret: "whsec_local", Portal: &billing.PortalOptions{Client: remote, Customers: f.store},
		Subscriptions: &billing.SubscriptionOptions{Client: remote, Plans: []billing.Plan{{Name: "pro", PriceID: "price_pro"}}}})
	off := false
	f.auth, err = plainauth.New(plainauth.Options{BaseURL: f.origin, Secret: strings.Repeat("s", 32), EmailAndPassword: true, Store: f.store, RateLimit: &off, Plugins: []plainauth.Plugin{plugin}})
	if err != nil {
		t.Fatal(err)
	}
	host.Config.Handler = f.auth
	host.StartTLS()
	t.Cleanup(host.Close)
	f.owner, f.ownerID = f.signUp(host, "owner@example.org")
	f.peer, f.peerID = f.signUp(host, "peer@example.org")
	f.exec(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`, "cus_owner", f.ownerID)
	f.exec(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`, "cus_peer", f.peerID)
	f.addSubscription(f.ownerID, "local_fixture", "sub_fixture", "cus_owner", "active")
	f.addSubscription(f.peerID, "local_peer", "sub_peer", "cus_peer", "active")
	return f
}

func (f *managementFixture) exec(query string, args ...any) {
	f.t.Helper()
	if _, err := f.store.db.ExecContext(f.t.Context(), f.store.bind(query), args...); err != nil {
		f.t.Fatal(err)
	}
}

func (f *managementFixture) signUp(host *httptest.Server, email string) (stripeclient.Client, string) {
	f.t.Helper()
	c, err := client.New(f.origin, host.Client())
	if err != nil {
		f.t.Fatal(err)
	}
	u, err := c.SignUpEmail(f.t.Context(), client.SignUpRequest{Email: email, Name: "Account", Password: "local-password"})
	if err != nil {
		f.t.Fatal(err)
	}
	return stripeclient.Client{Auth: c}, u.User.ID
}

func (f *managementFixture) addSubscription(owner, local, remote, customer, status string) {
	f.t.Helper()
	f.exec(`INSERT INTO "subscription" ("id","plan","referenceId","stripeCustomerId","stripeSubscriptionId","status","seats") VALUES(?,?,?,?,?,?,1)`, local, "pro", owner, customer, remote, status)
}

func (f *managementFixture) expectError(err error, status int, code, message string) {
	f.t.Helper()
	var api *plainauth.APIError
	if !errors.As(err, &api) || api.Status != status || api.Code != code || message != "" && api.Message != message {
		f.t.Fatalf("expected %d %s %q, got %v", status, code, message, err)
	}
}

// signedUpdate delivers a signed update for sub_fixture, which the store
// reconciles from Stripe.
func (f *managementFixture) signedUpdate(id string) {
	f.t.Helper()
	f.events++
	raw, _ := json.Marshal(map[string]any{"id": id, "object": "event", "api_version": sdk.APIVersion, "created": time.Now().Unix() + int64(f.events), "type": "customer.subscription.updated",
		"data": map[string]any{"object": map[string]any{"id": "sub_fixture", "object": "subscription", "customer": "cus_owner", "status": "active"}}})
	r := httptest.NewRequest("POST", f.origin+"/api/auth/stripe/webhook", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Stripe-Signature", webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: raw, Secret: "whsec_local"}).Header)
	w := httptest.NewRecorder()
	f.auth.ServeHTTP(w, r)
	if w.Code != 200 {
		f.t.Fatal("signed update", w.Code, w.Body)
	}
}

// listed is the owner's single listed subscription.
func (f *managementFixture) listed() billing.Subscription {
	f.t.Helper()
	rows, err := f.owner.List(f.t.Context())
	if err != nil || len(rows) != 1 {
		f.t.Fatal("expected one listed subscription", rows, err)
	}
	return rows[0]
}

type storedSubscription struct {
	status, plan string
	ended        bool
}

func (f *managementFixture) stored(local string) storedSubscription {
	f.t.Helper()
	var row storedSubscription
	if err := f.store.db.QueryRowContext(f.t.Context(), f.store.bind(`SELECT "status","plan","endedAt" IS NOT NULL FROM "subscription" WHERE "id"=?`), local).Scan(&row.status, &row.plan, &row.ended); err != nil {
		f.t.Fatal(err)
	}
	return row
}

func (f *managementFixture) calls() (calls, portals, updates, releases int) {
	f.p.mu.Lock()
	defer f.p.mu.Unlock()
	return f.p.calls, f.p.portals, f.p.updates, f.p.releases
}

func (f *managementFixture) set(change func(p *managementProvider)) {
	f.p.mu.Lock()
	defer f.p.mu.Unlock()
	change(f.p)
}

// A cancellation targets the first active subscription when the ID is
// omitted and the named one otherwise, and another account's, an unknown
// or an ended subscription is refused before Stripe opens a portal.
func TestOwnerCancellationSelection(t *testing.T) {
	for _, kind := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(kind, func(t *testing.T) {
			ctx := t.Context()
			f := newManagementFixture(t, kind)
			f.addSubscription(f.ownerID, "local_ended", "sub_ended", "cus_owner", "canceled")
			f.set(func(p *managementProvider) { p.others["sub_ended"] = "canceled" })
			page, err := f.owner.Cancel(ctx, stripeclient.Cancellation{ReturnURL: "/billing"})
			if form := f.p.form(); err != nil || !page.Redirect || form.Get("customer") != "cus_owner" || form.Get("flow_data[type]") != "subscription_cancel" || form.Get("flow_data[subscription_cancel][subscription]") != "sub_fixture" {
				t.Fatal("an omitted subscription did not target the active one", page, err, form)
			}
			calls, portals, _, _ := f.calls()
			for _, tc := range []struct {
				who stripeclient.Client
				id  string
			}{{f.owner, "sub_peer"}, {f.peer, "sub_fixture"}, {f.owner, "sub_unknown"}} {
				_, err := tc.who.Cancel(ctx, stripeclient.Cancellation{SubscriptionID: tc.id, ReturnURL: "/billing"})
				f.expectError(err, 400, "SUBSCRIPTION_NOT_FOUND", "Subscription not found")
			}
			if now, _, _, _ := f.calls(); now != calls {
				t.Fatal("a foreign or unknown subscription reached Stripe", now-calls)
			}
			_, err = f.owner.Cancel(ctx, stripeclient.Cancellation{SubscriptionID: "sub_ended", ReturnURL: "/billing"})
			f.expectError(err, 400, "SUBSCRIPTION_NOT_FOUND", "Subscription not found")
			if _, now, _, _ := f.calls(); now != portals {
				t.Fatal("an ended subscription opened a portal")
			}
			f.addSubscription(f.ownerID, "local_another", "sub_another", "cus_owner", "active")
			f.set(func(p *managementProvider) { p.others["sub_another"] = "active" })
			page, err = f.owner.Cancel(ctx, stripeclient.Cancellation{SubscriptionID: "sub_fixture", ReturnURL: "/billing", DisableRedirect: true})
			if form := f.p.form(); err != nil || page.Redirect || form.Get("flow_data[subscription_cancel][subscription]") != "sub_fixture" {
				t.Fatal("a named subscription was not targeted", page, err, form)
			}
			if _, err := f.owner.Cancel(ctx, stripeclient.Cancellation{ReturnURL: "/billing"}); err != nil || f.p.form().Get("flow_data[subscription_cancel][subscription]") != "sub_another" {
				t.Fatal("an omitted subscription did not target the first active one", err, f.p.form())
			}
			if row := f.stored("local_another"); row.status != "active" || row.plan != "pro" {
				t.Fatal("opening a portal changed the subscription", row)
			}
		})
	}
}

// Stripe's own answers decide a cancellation: an already scheduled one is
// synchronized, a coded refusal is relayed, other failures answer 502, a
// missing subscription is left unchanged and an ended one is kept as
// history, without a portal.
func TestOwnerCancellationProviderStates(t *testing.T) {
	for _, kind := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(kind, func(t *testing.T) {
			ctx := t.Context()
			f := newManagementFixture(t, kind)
			cancel := stripeclient.Cancellation{SubscriptionID: "sub_fixture", ReturnURL: "/billing"}
			// A codeless refusal for a cancellation Stripe already scheduled.
			f.set(func(p *managementProvider) {
				p.portalError = &stripeFailure{400, "", "This subscription is already set to be canceled."}
				p.onPortal = func() { p.atEnd, p.cancelAt, p.canceledAt = true, p.periodEnd, 1_800_000_000 }
			})
			_, err := f.owner.Cancel(ctx, cancel)
			f.expectError(err, 502, "STRIPE_SUBSCRIPTION_UNAVAILABLE", "Could not contact the billing provider")
			if row := f.listed(); row.CancelAtPeriodEnd == nil || !*row.CancelAtPeriodEnd || row.CancelAt == nil || row.CancelAt.Unix() != f.p.periodEnd || row.CanceledAt == nil || row.CanceledAt.Unix() != 1_800_000_000 {
				t.Fatal("refused cancellation did not synchronize Stripe's pending cancellation", row)
			}
			f.set(func(p *managementProvider) {
				p.portalError, p.onPortal = nil, nil
				p.atEnd, p.cancelAt, p.canceledAt = false, 0, 0
			})
			f.signedUpdate("evt_cancel_undone")
			// A coded refusal is relayed with a fixed message; any other failure
			// answers 502.
			f.set(func(p *managementProvider) {
				p.portalError = &stripeFailure{400, "parameter_missing", "Missing required param."}
			})
			_, err = f.owner.Cancel(ctx, cancel)
			f.expectError(err, 400, "parameter_missing", "Stripe rejected this subscription change")
			f.set(func(p *managementProvider) { p.portalError = &stripeFailure{500, "", "Something went wrong."} })
			_, err = f.owner.Cancel(ctx, cancel)
			f.expectError(err, 502, "STRIPE_SUBSCRIPTION_UNAVAILABLE", "Could not contact the billing provider")
			f.set(func(p *managementProvider) { p.portalError = nil })
			// A subscription Stripe reports missing is left unchanged.
			_, portals, _, _ := f.calls()
			f.set(func(p *managementProvider) { p.missing = true })
			_, err = f.owner.Cancel(ctx, cancel)
			f.expectError(err, 400, "SUBSCRIPTION_NOT_FOUND", "Subscription not found")
			if _, now, _, _ := f.calls(); now != portals || f.stored("local_fixture").status != "active" || f.listed().ID != "local_fixture" {
				t.Fatal("a subscription Stripe reports missing was changed or opened a portal")
			}
			// One Stripe reports ended is kept as history and leaves the list.
			f.set(func(p *managementProvider) { p.missing, p.status = false, "canceled" })
			_, err = f.owner.Cancel(ctx, cancel)
			f.expectError(err, 400, "SUBSCRIPTION_NOT_FOUND", "Subscription not found")
			rows, err := f.owner.List(ctx)
			if row := f.stored("local_fixture"); row.status != "canceled" || !row.ended || err != nil || len(rows) != 0 {
				t.Fatal("an ended subscription was not kept as history", row, rows, err)
			}
			if _, now, _, _ := f.calls(); now != portals {
				t.Fatal("an ended subscription opened a portal")
			}
		})
	}
}

// A restore targets the first active subscription when the ID is omitted
// and the named one otherwise; an ended, foreign or unknown subscription is
// refused before Stripe.
func TestOwnerRestoreSelection(t *testing.T) {
	for _, kind := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(kind, func(t *testing.T) {
			ctx := t.Context()
			f := newManagementFixture(t, kind)
			f.addSubscription(f.ownerID, "local_ended", "sub_ended", "cus_owner", "canceled")
			f.set(func(p *managementProvider) { p.atEnd = true })
			if result, err := f.owner.Restore(ctx, ""); err != nil || result.ID != "sub_fixture" || result.CancelAtPeriodEnd {
				t.Fatal("an omitted subscription did not restore the active one", result, err)
			}
			calls, _, _, _ := f.calls()
			_, err := f.owner.Restore(ctx, "sub_ended")
			f.expectError(err, 400, "SUBSCRIPTION_NOT_ACTIVE", "Subscription is not active")
			for _, tc := range []struct {
				who stripeclient.Client
				id  string
			}{{f.owner, "sub_peer"}, {f.peer, "sub_fixture"}, {f.owner, "sub_unknown"}} {
				_, err := tc.who.Restore(ctx, tc.id)
				f.expectError(err, 400, "SUBSCRIPTION_NOT_FOUND", "Subscription not found")
			}
			if now, _, _, _ := f.calls(); now != calls {
				t.Fatal("an ended, foreign or unknown subscription reached Stripe", now-calls)
			}
			f.addSubscription(f.ownerID, "local_another", "sub_another", "cus_owner", "active")
			f.set(func(p *managementProvider) { p.others["sub_another"], p.atEnd = "active", true })
			_, err = f.owner.Restore(ctx, "")
			f.expectError(err, 400, "SUBSCRIPTION_NOT_PENDING_CHANGE", "Subscription has no pending cancellation or scheduled plan change")
			if row := f.stored("local_another"); row.status != "active" || row.plan != "pro" {
				t.Fatal("a refused restore changed the first subscription", row)
			}
			_, _, updates, _ := f.calls()
			if _, err := f.owner.Restore(ctx, "sub_fixture"); err != nil {
				t.Fatal("a named subscription was not restored", err)
			}
			if _, _, now, _ := f.calls(); now != updates+1 {
				t.Fatal("the named restore did not reach Stripe once", now-updates)
			}
			f.exec(`DELETE FROM "subscription" WHERE "id"='local_another'`)
			f.exec(`UPDATE "subscription" SET "status"='canceled',"endedAt"=? WHERE "id"='local_fixture'`, f.store.date(time.Now()))
			calls, _, _, _ = f.calls()
			_, err = f.owner.Restore(ctx, "sub_fixture")
			f.expectError(err, 400, "SUBSCRIPTION_NOT_ACTIVE", "Subscription is not active")
			_, err = f.owner.Restore(ctx, "")
			f.expectError(err, 400, "SUBSCRIPTION_NOT_FOUND", "Subscription not found")
			if now, _, _, _ := f.calls(); now != calls {
				t.Fatal("an ended subscription reached Stripe", now-calls)
			}
		})
	}
}

// A restore sends Stripe only the field that clears the cancellation and
// persists Stripe's answer, releases a schedule Stripe reports active,
// clears one it no longer reports, and relays Stripe's refusals.
func TestOwnerRestoreProviderStates(t *testing.T) {
	for _, kind := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(kind, func(t *testing.T) {
			ctx := t.Context()
			f := newManagementFixture(t, kind)
			cleared := func(label string) {
				t.Helper()
				if row := f.listed(); row.CancelAtPeriodEnd != nil && *row.CancelAtPeriodEnd || row.CancelAt != nil || row.CanceledAt != nil {
					t.Fatal(label, "the listed row kept a cancellation", row)
				}
			}
			// (a) A period-end cancellation.
			f.set(func(p *managementProvider) { p.atEnd, p.canceledAt = true, 1_800_000_000 })
			f.signedUpdate("evt_period_end")
			result, err := f.owner.Restore(ctx, "sub_fixture")
			if update := f.p.lastUpdate(); err != nil || result.CancelAtPeriodEnd || result.CanceledAt != 0 || update.Get("cancel_at_period_end") != "false" || update.Has("cancel_at") {
				t.Fatal("a period-end cancellation was not cleared", result, err, update)
			}
			cleared("period end")
			// (b) A dated cancellation.
			f.set(func(p *managementProvider) {
				p.cancelAt, p.canceledAt = time.Now().Add(48*time.Hour).Unix(), 1_800_000_000
			})
			f.signedUpdate("evt_dated")
			if _, err := f.owner.Restore(ctx, "sub_fixture"); err != nil {
				t.Fatal(err)
			}
			if update := f.p.lastUpdate(); !update.Has("cancel_at") || update.Get("cancel_at") != "" || update.Has("cancel_at_period_end") {
				t.Fatal("a dated cancellation was not cleared alone", update)
			}
			cleared("dated")
			// (c) Stripe's own shape: period end with cancel_at at the period end.
			f.set(func(p *managementProvider) { p.atEnd, p.cancelAt, p.canceledAt = true, p.periodEnd, 1_800_000_000 })
			f.signedUpdate("evt_stripe_shape")
			if _, err := f.owner.Restore(ctx, "sub_fixture"); err != nil {
				t.Fatal(err)
			}
			if update := f.p.lastUpdate(); update.Get("cancel_at") != "" || !update.Has("cancel_at") || update.Has("cancel_at_period_end") {
				t.Fatal("Stripe's cancellation shape was not cleared through cancel_at", update)
			}
			cleared("stripe shape")
			// (d) A coded refusal keeps the cancellation.
			f.set(func(p *managementProvider) { p.atEnd = true })
			f.signedUpdate("evt_refused")
			f.set(func(p *managementProvider) {
				p.updateError = &stripeFailure{400, "parameter_invalid_empty", "Invalid empty parameter."}
			})
			_, err = f.owner.Restore(ctx, "sub_fixture")
			f.expectError(err, 400, "parameter_invalid_empty", "Stripe rejected this subscription change")
			if row := f.listed(); row.CancelAtPeriodEnd == nil || !*row.CancelAtPeriodEnd {
				t.Fatal("a refused restore cleared the cancellation", row)
			}
			f.set(func(p *managementProvider) { p.updateError = nil })
			if _, err := f.owner.Restore(ctx, "sub_fixture"); err != nil {
				t.Fatal(err)
			}
			// (e)-(h) Schedule refusals keep the schedule.
			f.set(func(p *managementProvider) { p.schedule = "sched_fixture" })
			f.signedUpdate("evt_scheduled")
			for _, tc := range []struct {
				change        func(p *managementProvider)
				status        int
				code, message string
			}{
				{func(p *managementProvider) { p.scheduleError = &stripeFailure{400, "parameter_missing", "Missing."} }, 400, "parameter_missing", "Stripe rejected this subscription change"},
				{func(p *managementProvider) {
					p.scheduleError = &stripeFailure{404, "resource_missing", "No such schedule."}
				}, 400, "SUBSCRIPTION_NOT_FOUND", "Subscription not found"},
				{func(p *managementProvider) { p.releaseError = &stripeFailure{400, "parameter_missing", "Missing."} }, 400, "parameter_missing", "Stripe rejected this subscription change"},
				{func(p *managementProvider) { p.scheduleStatus = "completed" }, 409, "CHECKOUT_RECONCILIATION_REQUIRED", "Waiting for checkout reconciliation"},
			} {
				f.set(func(p *managementProvider) { p.scheduleError, p.releaseError, p.scheduleStatus = nil, nil, "" })
				f.set(tc.change)
				_, err := f.owner.Restore(ctx, "sub_fixture")
				f.expectError(err, tc.status, tc.code, tc.message)
				if _, _, _, releases := f.calls(); releases != 0 || f.listed().ScheduleID == nil {
					t.Fatal("a refused schedule release lost the schedule", tc.code, releases)
				}
			}
			// (i) The release succeeds once the errors clear.
			f.set(func(p *managementProvider) { p.scheduleError, p.releaseError, p.scheduleStatus = nil, nil, "" })
			result, err = f.owner.Restore(ctx, "sub_fixture")
			if row := f.listed(); err != nil || result.Schedule != nil || row.ScheduleID != nil || row.Plan != "pro" || row.PriceID != "price_pro" {
				t.Fatal("a schedule release did not persist the plan", result, err, row)
			}
			if _, _, _, releases := f.calls(); releases != 1 {
				t.Fatal("the schedule was not released once", releases)
			}
			// (j) A stored schedule Stripe no longer reports is cleared without a
			// schedule request.
			f.exec(`UPDATE "subscription" SET "stripeScheduleId"='sched_stale' WHERE "id"='local_fixture'`)
			calls, _, _, releases := f.calls()
			result, err = f.owner.Restore(ctx, "sub_fixture")
			if now, _, _, released := f.calls(); err != nil || result.ID != "sub_fixture" || f.listed().ScheduleID != nil || released != releases || now != calls+1 {
				t.Fatal("a stale schedule was not cleared from Stripe's answer", result, err, now-calls)
			}
			// (k) A subscription Stripe reports missing is left unchanged.
			_, _, updates, _ := f.calls()
			f.set(func(p *managementProvider) { p.missing = true })
			_, err = f.owner.Restore(ctx, "sub_fixture")
			f.expectError(err, 400, "SUBSCRIPTION_NOT_FOUND", "Subscription not found")
			if _, _, now, _ := f.calls(); now != updates || f.listed().Status != "active" {
				t.Fatal("a missing subscription was changed")
			}
			// (l) One Stripe reports past due is not restored.
			f.set(func(p *managementProvider) { p.missing, p.status, p.atEnd = false, "past_due", true })
			_, err = f.owner.Restore(ctx, "sub_fixture")
			f.expectError(err, 400, "SUBSCRIPTION_NOT_FOUND", "Subscription not found")
			if _, _, now, _ := f.calls(); now != updates {
				t.Fatal("a past due subscription was restored")
			}
		})
	}
}
