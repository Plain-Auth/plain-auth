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
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/organization"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

// itemsProvider holds one subscription's items and applies direct updates
// as Stripe does, answering a repeated idempotency key with its first result.
type itemsProvider struct {
	mu      sync.Mutex
	items   []map[string]any
	next    int
	end     int64
	updates []url.Values
	keys    []string
	portals []url.Values
	answers map[string]string
	calls   int
	// status and schedule are the subscription's; getHook runs on each read.
	status, schedule string
	getHook          func()
	// mode is "" to apply, "lostAfter" to apply and lose the response,
	// "lostBefore" to fail before Stripe, "refuse" for a coded 400, or
	// "ignore" to answer without applying.
	mode string
	// hook runs on each update before it is applied.
	hook func()
}

var meteredPrices = map[string]bool{"price_requests": true, "price_meter_shared": true, "price_meter_a": true, "price_meter_b": true, "price_metered": true, "price_metered_bad": true}

func (p *itemsProvider) price(id string) map[string]any {
	usage := "licensed"
	if meteredPrices[id] {
		usage = "metered"
	}
	return map[string]any{"id": id, "object": "price", "active": true, "recurring": map[string]any{"interval": "month", "interval_count": 1, "usage_type": usage}}
}

func (p *itemsProvider) add(price string, quantity int64) {
	p.next++
	item := map[string]any{"id": fmt.Sprintf("si_%d", p.next), "object": "subscription_item", "price": price}
	if quantity > 0 {
		item["quantity"] = quantity
	}
	p.items = append(p.items, item)
}

// subscription is the current object; the caller holds mu.
func (p *itemsProvider) subscription() map[string]any {
	data := make([]any, 0, len(p.items))
	for _, item := range p.items {
		v := map[string]any{"current_period_start": 1000, "current_period_end": p.end}
		for k, x := range item {
			v[k] = x
		}
		v["price"] = p.price(item["price"].(string))
		data = append(data, v)
	}
	status := p.status
	if status == "" {
		status = "active"
	}
	sub := map[string]any{"object": "subscription", "id": "sub_items", "customer": "cus_items", "status": status, "metadata": map[string]string{},
		"items": map[string]any{"object": "list", "has_more": false, "data": data}}
	if p.schedule != "" {
		sub["schedule"] = p.schedule
	}
	return sub
}

func (p *itemsProvider) set(prices ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.items = nil
	for i := 0; i < len(prices); i += 2 {
		p.add(prices[i].(string), int64(prices[i+1].(int)))
	}
}

func (p *itemsProvider) apply(form url.Values) {
	for i := 0; ; i++ {
		at := func(k string) string { return form.Get(fmt.Sprintf("items[%d][%s]", i, k)) }
		id, price, quantity := at("id"), at("price"), at("quantity")
		if id == "" && price == "" {
			return
		}
		var n int64
		fmt.Sscan(quantity, &n)
		if id == "" {
			p.add(price, n)
			continue
		}
		for j, item := range p.items {
			if item["id"] != id {
				continue
			}
			if at("deleted") == "true" {
				p.items = append(p.items[:j], p.items[j+1:]...)
				break
			}
			if price != "" {
				item["price"] = price
				if meteredPrices[price] {
					delete(item, "quantity")
				}
			}
			if quantity != "" {
				item["quantity"] = n
			}
			break
		}
	}
}

func (p *itemsProvider) handle(r *http.Request) (*http.Response, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	// A real transport fails a request whose deadline has passed.
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	switch {
	case r.Method == "GET" && r.URL.Path == "/v1/subscriptions/sub_items":
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.getHook != nil {
			p.getHook()
		}
		return stripeJSON(200, p.subscription()), nil
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/prices/"):
		return stripeJSON(200, p.price(strings.TrimPrefix(r.URL.Path, "/v1/prices/"))), nil
	case r.Method == "POST" && r.URL.Path == "/v1/billing_portal/sessions":
		p.mu.Lock()
		p.portals = append(p.portals, r.PostForm)
		p.mu.Unlock()
		return stripeJSON(200, map[string]any{"id": "bps_items", "object": "billing_portal.session", "customer": "cus_items", "url": "https://billing.stripe.test/confirm"}), nil
	case r.Method == "POST" && r.URL.Path == "/v1/subscriptions/sub_items":
		p.mu.Lock()
		hook, mode, key := p.hook, p.mode, r.Header.Get("Idempotency-Key")
		p.updates = append(p.updates, r.PostForm)
		p.keys = append(p.keys, key)
		p.mu.Unlock()
		if hook != nil {
			hook()
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if answer, ok := p.answers[key]; ok {
			// Stripe replays a server error under its key.
			if answer == "server-error" {
				return stripeJSON(500, map[string]any{"error": map[string]string{"type": "api_error", "message": "Server error"}}), nil
			}
			if answer != r.PostForm.Encode() {
				return stripeJSON(400, map[string]any{"error": map[string]string{"type": "idempotency_error", "message": "Keys for idempotent requests can only be used with the same parameters"}}), nil
			}
			return stripeJSON(200, p.subscription()), nil
		}
		switch mode {
		case "server":
			p.answers[key] = "server-error"
			return stripeJSON(500, map[string]any{"error": map[string]string{"type": "api_error", "message": "Server error"}}), nil
		case "ignore":
			return stripeJSON(200, p.subscription()), nil
		case "lostBefore":
			return nil, errors.New("connection reset before Stripe")
		case "refuse":
			return stripeJSON(400, map[string]any{"error": map[string]string{"type": "invalid_request_error", "code": "subscription_update_refused", "message": "Refused"}}), nil
		}
		p.apply(r.PostForm)
		p.answers[key] = r.PostForm.Encode()
		if mode == "lostAfter" {
			return nil, errors.New("connection reset after Stripe")
		}
		return stripeJSON(200, p.subscription()), nil
	}
	return nil, fmt.Errorf("unexpected Stripe call %s %s", r.Method, r.URL.Path)
}

// withoutPlanChanges hides plan change storage from the plugin.
type withoutPlanChanges struct{ *Store }

func (withoutPlanChanges) ReserveStripePlanChange() {}

// A subscription with several items, or one moving to or from several, is
// changed directly: the update follows the target plan's items, carries its
// proration, is reserved under one idempotency key across servers and
// retries, blocks other changes and schedules while open, and leaves the
// row synchronized from Stripe. Single-item changes keep the portal.
func TestDirectSubscriptionPlanChanges(t *testing.T) {
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
			const secret = "whsec_items_local"
			remote := &itemsProvider{end: time.Now().Add(30 * 24 * time.Hour).Unix(), answers: map[string]string{}}
			remote.set("price_basic", 1)
			client := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: localBillingTransport(remote.handle)}, MaxNetworkRetries: sdk.Int64(0)})))
			fixed := []billing.LineItem{{Price: "price_requests"}, {Price: "price_support", Quantity: 2}}
			plans := []billing.Plan{
				{Name: "basic", PriceID: "price_basic"}, {Name: "pro2", PriceID: "price_pro2"}, {Name: "metered", PriceID: "price_metered"},
				{Name: "platform", PriceID: "price_platform", LineItems: fixed}, {Name: "platform2", PriceID: "price_platform2", LineItems: fixed},
				{Name: "adda", PriceID: "price_a", MeteredPriceIDs: []string{"price_meter_shared", "price_meter_a"}},
				{Name: "addb", PriceID: "price_b", MeteredPriceIDs: []string{"price_meter_shared", "price_meter_b"}},
				{Name: "always", PriceID: "price_always", LineItems: []billing.LineItem{{Price: "price_requests"}}, ProrationBehavior: "always_invoice"},
				{Name: "nothing", PriceID: "price_none", LineItems: []billing.LineItem{{Price: "price_requests"}}, ProrationBehavior: "none"},
				{Name: "badmeter", PriceID: "price_metered_bad", LineItems: []billing.LineItem{{Price: "price_requests"}}},
			}
			const origin = "https://items.example"
			off := false
			node := func(s auth.Store) *auth.Auth {
				t.Helper()
				a, err := auth.New(auth.Options{Store: s, Secret: strings.Repeat("i", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off,
					Plugins: []auth.Plugin{billing.New(billing.Options{WebhookSecret: secret, Subscriptions: &billing.SubscriptionOptions{Client: client, Plans: plans}})}})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			a, b := node(store), node(store)
			hit, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: "items", Email: "items@example.test", Password: "local fixture password"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			owner := hit.User.ID
			if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`), "cus_items", owner); err != nil {
				t.Fatal(err)
			}
			events := 0
			deliver := func() {
				t.Helper()
				events++
				remote.mu.Lock()
				object := remote.subscription()
				remote.mu.Unlock()
				kind := "customer.subscription.updated"
				if events == 1 {
					kind = "customer.subscription.created"
				}
				raw, _ := json.Marshal(map[string]any{"id": fmt.Sprintf("evt_items_%d", events), "object": "event", "api_version": sdk.APIVersion, "created": events, "type": kind, "data": map[string]any{"object": object}})
				r := httptest.NewRequest("POST", origin+"/api/auth/stripe/webhook", bytes.NewReader(raw))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Stripe-Signature", webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: raw, Secret: secret}).Header)
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatal("webhook", w.Code, w.Body.String())
				}
			}
			deliver()
			token := hit.Token
			call := func(on *auth.Auth, plan string, extra map[string]any) (int, map[string]any) {
				t.Helper()
				body := map[string]any{"plan": plan, "subscriptionId": "sub_items", "successUrl": "/done", "cancelUrl": "/cancel", "returnUrl": "/account", "disableRedirect": true}
				for k, v := range extra {
					body[k] = v
				}
				raw, _ := json.Marshal(body)
				r := httptest.NewRequest("POST", origin+"/api/auth/subscription/upgrade", bytes.NewReader(raw))
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "application/json")
				r.AddCookie(on.SessionCookie(token, true))
				w := httptest.NewRecorder()
				on.ServeHTTP(w, r)
				var out map[string]any
				json.Unmarshal(w.Body.Bytes(), &out)
				return w.Code, out
			}
			counts := func() (int, int) {
				remote.mu.Lock()
				defer remote.mu.Unlock()
				return len(remote.updates), len(remote.portals)
			}
			last := func() (url.Values, string) {
				remote.mu.Lock()
				defer remote.mu.Unlock()
				return remote.updates[len(remote.updates)-1], remote.keys[len(remote.keys)-1]
			}
			row := func() (string, string, int64) {
				t.Helper()
				var plan, status string
				var seats int64
				if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "plan","status","seats" FROM "subscription" WHERE "stripeSubscriptionId"=?`), "sub_items").Scan(&plan, &status, &seats); err != nil {
					t.Fatal(err)
				}
				return plan, status, seats
			}
			record := func() bool {
				t.Helper()
				var n int
				if err := store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "verification" WHERE "id"=?`), stripeRecordID("plan-change", "sub_items")).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n == 1
			}
			age := func(field string, by time.Duration) {
				t.Helper()
				var raw string
				id := stripeRecordID("plan-change", "sub_items")
				if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "value" FROM "verification" WHERE "id"=?`), id).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var v map[string]any
				json.Unmarshal([]byte(raw), &v)
				v[field] = v[field].(float64) - by.Seconds()
				changed, _ := json.Marshal(v)
				if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "verification" SET "value"=? WHERE "id"=?`), string(changed), id); err != nil {
					t.Fatal(err)
				}
			}
			ok := func(status int, out map[string]any, name string) {
				t.Helper()
				if status != 200 || out["url"] != origin+"/account" || out["redirect"] != false {
					t.Fatal(name, status, out)
				}
			}
			refused := func(status int, out map[string]any, want int, code, name string) {
				t.Helper()
				if status != want || out["code"] != code {
					t.Fatal(name, status, out)
				}
			}
			form := func(pairs ...string) string {
				v := url.Values{}
				for i := 0; i < len(pairs); i += 2 {
					v.Set(pairs[i], pairs[i+1])
				}
				return v.Encode()
			}

			// A single item moves to a plan with line items in one update, with
			// no portal, and the row follows Stripe at once.
			status, out := call(a, "platform", nil)
			ok(status, out, "single to several items")
			sent, key := last()
			if sent.Encode() != form("items[0][id]", "si_1", "items[0][price]", "price_platform", "items[0][quantity]", "1", "items[1][price]", "price_requests",
				"items[2][price]", "price_support", "items[2][quantity]", "2", "proration_behavior", "create_prorations") || !strings.HasPrefix(key, "plainauth-plan-change-") {
				t.Fatal("the line item change was not sent exactly", sent, key)
			}
			if _, portals := counts(); portals != 0 {
				t.Fatal("a several-item change opened the portal")
			}
			if plan, _, _ := row(); plan != "platform" || record() {
				t.Fatal("the row did not follow the change or the reservation stayed", plan, record())
			}

			// A seat change follows a drifted fixed quantity back to configuration.
			remote.mu.Lock()
			remote.items[2]["quantity"] = int64(5)
			remote.mu.Unlock()
			deliver()
			status, out = call(a, "platform", map[string]any{"seats": 3})
			ok(status, out, "seat change")
			if sent, _ := last(); sent.Encode() != form("items[0][id]", "si_1", "items[0][price]", "price_platform", "items[0][quantity]", "3", "items[1][id]", "si_3", "items[1][quantity]", "2", "proration_behavior", "create_prorations") {
				t.Fatal("the seat change did not restore the fixed quantity", sent)
			}
			// Plans with the same line items change only the base.
			status, out = call(a, "platform2", map[string]any{"seats": 3})
			ok(status, out, "base-only change")
			if sent, _ := last(); sent.Encode() != form("items[0][id]", "si_1", "items[0][price]", "price_platform2", "items[0][quantity]", "3", "proration_behavior", "create_prorations") {
				t.Fatal("a base-only change sent other items", sent)
			}
			// A plan without line items deletes them, in Stripe's item order.
			status, out = call(a, "basic", nil)
			ok(status, out, "several to single item")
			if sent, _ := last(); sent.Encode() != form("items[0][id]", "si_1", "items[0][price]", "price_basic", "items[0][quantity]", "1", "items[1][id]", "si_2", "items[1][deleted]", "true",
				"items[2][id]", "si_3", "items[2][deleted]", "true", "proration_behavior", "create_prorations") {
				t.Fatal("the line items were not deleted", sent)
			}
			if plan, _, seats := row(); plan != "basic" || seats != 1 {
				t.Fatal("the row did not return to the single plan", plan, seats)
			}

			// Single items keep the portal: a metered target without a quantity,
			// a metered subscription moving to a licensed one with it.
			updates, _ := counts()
			status, out = call(a, "metered", nil)
			if status != 200 || out["url"] != "https://billing.stripe.test/confirm" {
				t.Fatal("a metered target did not open the portal", status, out)
			}
			remote.mu.Lock()
			confirm := remote.portals[len(remote.portals)-1]
			remote.mu.Unlock()
			if confirm.Get("flow_data[subscription_update_confirm][items][0][price]") != "price_metered" || confirm.Has("flow_data[subscription_update_confirm][items][0][quantity]") {
				t.Fatal("a metered target was confirmed with a quantity", confirm)
			}
			remote.set("price_metered", 0)
			deliver()
			status, _ = call(a, "basic", nil)
			remote.mu.Lock()
			confirm = remote.portals[len(remote.portals)-1]
			remote.mu.Unlock()
			if status != 200 || confirm.Get("flow_data[subscription_update_confirm][items][0][quantity]") != "1" {
				t.Fatal("a licensed target was confirmed without a quantity", status, confirm)
			}
			if now, _ := counts(); now != updates {
				t.Fatal("a single-item change was sent directly")
			}
			remote.set("price_basic", 1)
			deliver()

			// Add-on plans sharing a meter keep it, delete the other and add their own.
			status, out = call(a, "adda", nil)
			ok(status, out, "add-on plan")
			status, out = call(a, "addb", nil)
			ok(status, out, "add-on to add-on")
			remote.mu.Lock()
			first, firstItems := remote.updates[len(remote.updates)-1], len(remote.items)
			remote.mu.Unlock()
			if first.Encode() != form("items[0][id]", "si_5", "items[0][price]", "price_b", "items[0][quantity]", "1", "items[1][id]", "si_7", "items[1][deleted]", "true",
				"items[2][price]", "price_meter_b", "proration_behavior", "create_prorations") || firstItems != 3 {
				t.Fatal("the shared meter was not kept", first, firstItems)
			}
			// Each plan's proration is sent exactly.
			status, out = call(a, "always", nil)
			ok(status, out, "always_invoice")
			if sent, _ := last(); sent.Get("proration_behavior") != "always_invoice" {
				t.Fatal("always_invoice was not sent", sent)
			}
			status, out = call(a, "nothing", nil)
			ok(status, out, "none")
			if sent, _ := last(); sent.Get("proration_behavior") != "none" {
				t.Fatal("none was not sent", sent)
			}

			// Refusals reach no update: an unknown item, a metered base with
			// line items, a scheduled change from line items, and a store
			// without plan change storage.
			updates, _ = counts()
			remote.mu.Lock()
			remote.add("price_unknown", 1)
			remote.mu.Unlock()
			status, out = call(a, "basic", nil)
			refused(status, out, 409, "UNSUPPORTED_SUBSCRIPTION_ITEM", "an unknown item was changed")
			remote.mu.Lock()
			remote.items = remote.items[:len(remote.items)-1]
			remote.mu.Unlock()
			deliver()
			status, out = call(a, "badmeter", nil)
			refused(status, out, 409, "UNSUPPORTED_SUBSCRIPTION_ITEM", "a metered base with line items was accepted")
			status, out = call(a, "basic", map[string]any{"scheduleAtPeriodEnd": true})
			refused(status, out, 409, "UNSUPPORTED_SUBSCRIPTION_ITEM", "a scheduled change rewrote line items")
			status, out = call(node(withoutPlanChanges{store}), "always", nil)
			refused(status, out, 409, "PLAN_CHANGE_UNAVAILABLE", "a store without plan change storage changed items")
			if now, _ := counts(); now != updates {
				t.Fatal("a refused change reached Stripe", now-updates)
			}

			// A coded refusal answers its code, changes nothing and releases the
			// reservation, so another target proceeds at once.
			remote.mode = "refuse"
			status, out = call(a, "basic", nil)
			refused(status, out, 400, "subscription_update_refused", "a refused update")
			remote.mode = ""
			if plan, _, _ := row(); plan != "nothing" || record() {
				t.Fatal("a refused update changed the row or kept its reservation", plan)
			}
			status, out = call(a, "always", nil)
			ok(status, out, "a change after a refusal")
			// A metered target from several items is sent without a quantity.
			remote.mu.Lock()
			base, extra := remote.items[0]["id"].(string), remote.items[1]["id"].(string)
			remote.mu.Unlock()
			status, out = call(a, "metered", nil)
			ok(status, out, "several items to a metered base")
			if sent, _ := last(); sent.Encode() != form("items[0][id]", base, "items[0][price]", "price_metered", "items[1][id]", extra, "items[1][deleted]", "true", "proration_behavior", "create_prorations") {
				t.Fatal("a metered target was sent with a quantity", sent)
			}

			// An update applied with its response lost: a retry on another
			// server sends nothing more and succeeds.
			remote.mode = "lostAfter"
			status, out = call(a, "nothing", nil)
			refused(status, out, 502, "STRIPE_SUBSCRIPTION_UNAVAILABLE", "a lost response")
			remote.mode = ""
			updates, _ = counts()
			status, out = call(b, "nothing", nil)
			ok(status, out, "a retry after an applied update")
			if now, _ := counts(); now != updates || record() {
				t.Fatal("an applied update was sent again or kept its reservation")
			}
			if plan, _, _ := row(); plan != "nothing" {
				t.Fatal("the retry did not synchronize the row", plan)
			}
			// The same holds while trialing.
			remote.mu.Lock()
			remote.status = "trialing"
			remote.mu.Unlock()
			deliver()
			remote.mode = "lostAfter"
			status, out = call(a, "always", nil)
			refused(status, out, 502, "STRIPE_SUBSCRIPTION_UNAVAILABLE", "a lost trialing response")
			remote.mode = ""
			updates, _ = counts()
			status, out = call(b, "always", nil)
			ok(status, out, "a trialing retry after an applied update")
			if now, _ := counts(); now != updates || record() {
				t.Fatal("a trialing applied update was sent again or kept its reservation")
			}
			remote.mu.Lock()
			remote.status = ""
			remote.mu.Unlock()
			deliver()
			// Stripe replays a server error under its key, so a retry sends a new one.
			remote.mode = "server"
			status, out = call(a, "nothing", nil)
			refused(status, out, 502, "STRIPE_SUBSCRIPTION_UNAVAILABLE", "a Stripe server error")
			remote.mode = ""
			_, failedKey := last()
			status, out = call(a, "nothing", nil)
			if _, key := last(); status != 200 || key == failedKey {
				t.Fatal("a retry after a Stripe server error reused its key", status, out)
			}

			// Concurrent different targets: one update, the other waits.
			entered, release := make(chan struct{}), make(chan struct{})
			remote.mu.Lock()
			remote.hook = func() { close(entered); <-release }
			remote.mu.Unlock()
			updates, _ = counts()
			done := make(chan int)
			go func() { status, _ := call(a, "always", nil); done <- status }()
			<-entered
			remote.mu.Lock()
			remote.hook = nil
			remote.mu.Unlock()
			status, out = call(b, "platform", nil)
			refused(status, out, 409, "SUBSCRIPTION_PENDING_CHANGE", "a concurrent different change")
			close(release)
			if got := <-done; got != 200 {
				t.Fatal("the first concurrent change failed", got)
			}
			if now, _ := counts(); now != updates+1 {
				t.Fatal("concurrent targets sent more than one update", now-updates)
			}
			// Concurrent identical requests share one key.
			entered, release = make(chan struct{}), make(chan struct{})
			remote.mu.Lock()
			remote.hook = func() { close(entered); <-release }
			remote.mu.Unlock()
			go func() { status, _ := call(a, "nothing", nil); done <- status }()
			<-entered
			remote.mu.Lock()
			remote.hook = nil
			remote.mu.Unlock()
			status, out = call(b, "nothing", nil)
			close(release)
			if got := <-done; got != 200 || status != 200 {
				t.Fatal("identical concurrent changes failed", got, status, out)
			}
			remote.mu.Lock()
			keys := remote.keys[len(remote.keys)-2:]
			remote.mu.Unlock()
			if keys[0] != keys[1] {
				t.Fatal("identical concurrent changes used two keys", keys)
			}

			// Back to one item for the schedule rules.
			status, out = call(a, "basic", nil)
			ok(status, out, "back to one item")
			// A change lost before Stripe stays reserved: a schedule waits for
			// it, and its retry sends the same key and form.
			remote.mode = "lostBefore"
			status, out = call(a, "platform", nil)
			refused(status, out, 502, "STRIPE_SUBSCRIPTION_UNAVAILABLE", "a change lost before Stripe")
			remote.mode = ""
			lost, lostKey := last()
			if !record() {
				t.Fatal("a change lost before Stripe was not kept")
			}
			status, out = call(a, "pro2", map[string]any{"scheduleAtPeriodEnd": true})
			refused(status, out, 409, "SUBSCRIPTION_PENDING_CHANGE", "a schedule during an open change")
			// A retry after the hold reuses the key with a fresh send deadline.
			age("Started", 31*time.Minute)
			status, out = call(b, "platform", nil)
			ok(status, out, "the retry of a change lost before Stripe")
			if sent, key := last(); sent.Encode() != lost.Encode() || key != lostKey {
				t.Fatal("the retry changed its key or form", key, lostKey)
			}
			// A stale reservation: sent over 30 minutes ago, it no longer
			// blocks another target; created a day ago, its key is not reused.
			remote.mode = "lostBefore"
			status, _ = call(a, "basic", nil)
			remote.mode = ""
			_, staleKey := last()
			age("Started", 31*time.Minute)
			status, out = call(a, "adda", nil)
			if _, key := last(); status != 200 || key == staleKey {
				t.Fatal("a stale reservation blocked another target", status, out)
			}
			remote.mode = "lostBefore"
			call(a, "basic", nil)
			remote.mode = ""
			_, oldKey := last()
			age("Created", 24*time.Hour)
			age("Started", 31*time.Minute)
			status, out = call(a, "basic", nil)
			if _, key := last(); status != 200 || key == oldKey {
				t.Fatal("a day-old key was reused", status, out)
			}
			// An unbound schedule reservation blocks a direct change.
			var localID string
			var start, end time.Time
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "id","periodStart","periodEnd" FROM "subscription" WHERE "stripeSubscriptionId"=?`), "sub_items").Scan(&localID, &start, &end); err != nil {
				t.Fatal(err)
			}
			remote.mu.Lock()
			base = remote.items[0]["id"].(string)
			remote.mu.Unlock()
			pending, err := store.ReserveStripeSchedule(ctx, token, billing.ScheduleChange{Owner: owner, Customer: "cus_items", LocalID: localID, Subscription: "sub_items", Item: base,
				Current: "price_basic", Target: "price_pro2", CurrentPlan: "basic", CurrentInterval: "month", Start: start.Unix(), End: end.Unix()}, "", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			updates, _ = counts()
			status, out = call(a, "platform", nil)
			refused(status, out, 409, "SUBSCRIPTION_PENDING_CHANGE", "a change during an unbound schedule")
			if now, _ := counts(); now != updates {
				t.Fatal("a change during a schedule reached Stripe")
			}
			// Bound to a schedule Stripe no longer shows, it blocks nothing.
			if err := store.BindStripeSchedule(ctx, token, pending, "sub_sched_released", time.Now()); err != nil {
				t.Fatal(err)
			}
			status, out = call(a, "adda", nil)
			ok(status, out, "a change after a released schedule")
			// Unbound but older than a day, its key can no longer create one.
			scheduleID := stripeRecordID("schedule-change", "sub_items")
			var stored string
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "value" FROM "verification" WHERE "id"=?`), scheduleID).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			var schedule map[string]any
			json.Unmarshal([]byte(stored), &schedule)
			schedule["Schedule"], schedule["Created"] = "", schedule["Created"].(float64)-(25*time.Hour).Seconds()
			aged, _ := json.Marshal(schedule)
			if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "verification" SET "value"=? WHERE "id"=?`), string(aged), scheduleID); err != nil {
				t.Fatal(err)
			}
			status, out = call(a, "addb", nil)
			ok(status, out, "a change after a day-old unbound schedule")
			if _, err := store.db.ExecContext(ctx, store.bind(`DELETE FROM "verification" WHERE "id"=?`), scheduleID); err != nil {
				t.Fatal(err)
			}
			// A schedule attached after the subscription was read is caught
			// before the update is sent.
			reads := 0
			remote.mu.Lock()
			remote.getHook = func() {
				if reads++; reads == 2 {
					remote.schedule = "sub_sched_late"
				}
			}
			remote.mu.Unlock()
			updates, _ = counts()
			status, out = call(a, "platform", nil)
			refused(status, out, 409, "SUBSCRIPTION_PENDING_CHANGE", "a change raced a new schedule")
			if now, _ := counts(); now != updates {
				t.Fatal("a change raced a new schedule to Stripe")
			}
			remote.mu.Lock()
			remote.getHook, remote.schedule = nil, ""
			remote.mu.Unlock()

			// A session revoked during the update: 401; after the signed
			// update, a retry with a new session succeeds with no update.
			remote.mu.Lock()
			remote.hook = func() {
				if _, err := store.db.ExecContext(context.Background(), store.bind(`DELETE FROM "session" WHERE "token"=?`), token); err != nil {
					t.Error(err)
				}
			}
			remote.mu.Unlock()
			status, out = call(a, "platform", nil)
			refused(status, out, 401, "UNAUTHORIZED", "a revoked session completed a change")
			remote.mu.Lock()
			remote.hook = nil
			remote.mu.Unlock()
			deliver()
			again, err := a.SignInEmail(ctx, auth.SignInInput{Email: "items@example.test", Password: "local fixture password"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			token = again.Token
			updates, _ = counts()
			status, out = call(b, "platform", nil)
			ok(status, out, "the retry after a revoked session")
			if now, _ := counts(); now != updates || record() {
				t.Fatal("the retry after a revoked session updated again or kept its reservation")
			}
			// Stripe answering without the target asks for reconciliation.
			remote.mode = "ignore"
			status, out = call(a, "basic", nil)
			refused(status, out, 409, "CHECKOUT_RECONCILIATION_REQUIRED", "an unapplied update was reported done")
			remote.mode = ""
		})
	}
}

// An organization's add-on plan changes directly under its scope, and a
// non-member is refused before any Stripe call.
func TestOrganizationDirectPlanChange(t *testing.T) {
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
			remote := &itemsProvider{end: time.Now().Add(30 * 24 * time.Hour).Unix(), answers: map[string]string{}}
			remote.set("price_a", 1, "price_meter_shared", 0, "price_meter_a", 0)
			client := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: localBillingTransport(remote.handle)}, MaxNetworkRetries: sdk.Int64(0)})))
			orgs, err := organization.New(organization.Options{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			const origin = "https://items-org.example"
			off := false
			a, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("o", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off, Plugins: []auth.Plugin{orgs,
				billing.New(billing.Options{WebhookSecret: "whsec_items_org", Organization: &billing.OrganizationOptions{AuthorizeReference: func(r billing.ReferenceAuthorization) bool { return r.Role == "owner" }},
					Subscriptions: &billing.SubscriptionOptions{Client: client, Plans: []billing.Plan{
						{Name: "adda", PriceID: "price_a", MeteredPriceIDs: []string{"price_meter_shared", "price_meter_a"}},
						{Name: "addb", PriceID: "price_b", MeteredPriceIDs: []string{"price_meter_shared", "price_meter_b"}},
					}}})}})
			if err != nil {
				t.Fatal(err)
			}
			post := func(path, token string, body map[string]any) (int, map[string]any) {
				t.Helper()
				raw, _ := json.Marshal(body)
				r := httptest.NewRequest("POST", origin+"/api/auth"+path, bytes.NewReader(raw))
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "application/json")
				r.AddCookie(a.SessionCookie(token, true))
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var out map[string]any
				json.Unmarshal(w.Body.Bytes(), &out)
				return w.Code, out
			}
			signup := func(name string) string {
				t.Helper()
				hit, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: name, Email: name + "@example.test", Password: "local fixture password"}, auth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				return hit.Token
			}
			admin, peer := signup("admin"), signup("peer")
			status, created := post("/organization/create", admin, map[string]any{"name": "Items group", "slug": "items-group"})
			group, _ := created["id"].(string)
			if status != 200 || group == "" {
				t.Fatal("organization", status, created)
			}
			for _, q := range []string{`UPDATE "organization" SET "stripeCustomerId"='cus_items' WHERE "id"=?`,
				`INSERT INTO "subscription" ("id","plan","referenceId","stripeCustomerId","stripeSubscriptionId","status","seats","billingInterval") VALUES('local_group','adda',?,'cus_items','sub_items','active',1,'month')`} {
				if _, err := store.db.ExecContext(ctx, store.bind(q), group); err != nil {
					t.Fatal(err)
				}
			}
			change := map[string]any{"plan": "addb", "subscriptionId": "sub_items", "referenceId": group, "customerType": "organization", "successUrl": "/done", "cancelUrl": "/cancel", "returnUrl": "/account", "disableRedirect": true}
			if status, out := post("/subscription/upgrade", peer, change); status != 403 || remote.calls != 0 {
				t.Fatal("a non-member reached the organization's subscription", status, out, remote.calls)
			}
			status, out := post("/subscription/upgrade", admin, change)
			want := url.Values{"items[0][id]": {"si_1"}, "items[0][price]": {"price_b"}, "items[0][quantity]": {"1"}, "items[1][id]": {"si_3"}, "items[1][deleted]": {"true"},
				"items[2][price]": {"price_meter_b"}, "proration_behavior": {"create_prorations"}}
			if status != 200 || len(remote.updates) != 1 || remote.updates[0].Encode() != want.Encode() {
				t.Fatal("the organization's add-on plan was not changed directly", status, out, remote.updates)
			}
			var plan string
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "plan" FROM "subscription" WHERE "id"='local_group'`)).Scan(&plan); err != nil || plan != "addb" {
				t.Fatal("the organization's row did not follow the change", plan, err)
			}
		})
	}
}
