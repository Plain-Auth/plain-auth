package polar

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	polargo "github.com/polarsource/polar-go"
	"github.com/polarsource/polar-go/models/components"
)

// OnEvent receives every verified delivery with its type, timestamp and
// body, with no purchase for an event that is not a reserved checkout; a
// failing or panicking handler answers 400 without its text, an unsigned
// delivery never reaches it, and a node without a handler answers 200.
func TestEventHandlerReceivesVerifiedDeliveries(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			db, _ := database(t, dialect)
			ledger, err := OpenLedger(ctx, db, dialect)
			if err != nil {
				t.Fatal(err)
			}
			const merchant = "11111111-1111-4111-8111-111111111111"
			var mu sync.Mutex
			var events []Event
			fail, explode := false, false
			var logs bytes.Buffer
			node := func(handler func(context.Context, Event) error) *auth.Auth {
				t.Helper()
				plugin, err := New(Options{Client: polargo.New(polargo.WithSecurity("fixture")), OrganizationID: merchant, Ledger: ledger,
					Webhooks: &WebhookOptions{Secret: dashboardSecret, OnEvent: handler}})
				if err != nil {
					t.Fatal(err)
				}
				a, err := auth.New(auth.Options{BaseURL: host, Secret: strings.Repeat("w", 40), Store: memory.New(), Logger: slog.New(slog.NewTextHandler(&logs, nil)), Plugins: []auth.Plugin{plugin}})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			a := node(func(_ context.Context, e Event) error {
				mu.Lock()
				defer mu.Unlock()
				events = append(events, e)
				if explode {
					panic("host panic detail")
				}
				if fail {
					return context.DeadlineExceeded
				}
				return nil
			})
			last := func() Event {
				mu.Lock()
				defer mu.Unlock()
				return events[len(events)-1]
			}
			stamp := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
			paid := `{"api_version":"2026-10","timestamp":"` + stamp.Format(time.RFC3339) + `","type":"order.paid","data":{"id":"order_1"}}`
			if body := expect(t, call(a, "/polar/webhooks", paid, "", nil, signed(paid, "order-paid", time.Now(), false)), 200); strings.TrimSpace(body) != `{"received":true}` {
				t.Fatal("the delivery was not acknowledged", body)
			}
			if e := last(); e.DeliveryID != "order-paid" || e.Type != components.WebhookEventTypeOrderPaid || !e.Timestamp.Equal(stamp) || string(e.Body) != paid || e.Purchase != nil {
				t.Fatalf("the order event was not delivered whole: %+v", e)
			}
			// An untagged checkout and a bad timestamp reach the handler without a purchase.
			untagged, _ := json.Marshal(map[string]any{"api_version": apiVersion, "timestamp": "not-a-time", "type": "checkout.created",
				"data": map[string]any{"id": "33333333-3333-4333-8333-333333333333", "status": "open"}})
			expect(t, call(a, "/polar/webhooks", string(untagged), "", nil, signed(string(untagged), "untagged", time.Now(), false)), 200)
			if e := last(); e.Type != components.WebhookEventTypeCheckoutCreated || e.Purchase != nil || !e.Timestamp.IsZero() {
				t.Fatalf("an untagged checkout was delivered wrongly: %+v", e)
			}
			// An undefined type keeps its wire value.
			future := `{"api_version":"2027-01","type":"future.event","data":{}}`
			expect(t, call(a, "/polar/webhooks", future, "", nil, signed(future, "future", time.Now(), false)), 200)
			if e := last(); string(e.Type) != "future.event" {
				t.Fatalf("an undefined type was not kept: %+v", e)
			}
			// A failing or panicking handler answers 400 without its text.
			for _, mode := range []string{"error", "panic"} {
				mu.Lock()
				fail, explode = mode == "error", mode == "panic"
				mu.Unlock()
				w := call(a, "/polar/webhooks", paid, "", nil, signed(paid, "failing-"+mode, time.Now(), false))
				if w.Code != 400 || !strings.Contains(w.Body.String(), "POLAR_WEBHOOK_ERROR") || strings.Contains(w.Body.String(), "detail") || strings.Contains(w.Body.String(), "deadline") {
					t.Fatal("a failing handler was answered wrongly", mode, w.Code, w.Body.String())
				}
			}
			mu.Lock()
			fail, explode = false, false
			count := len(events)
			mu.Unlock()
			if out := logs.String(); !strings.Contains(out, "Polar webhook handler failed") || !strings.Contains(out, "delivery_id=failing-panic") || strings.Contains(out, "host panic detail") {
				t.Fatal("the handler failure was not logged by delivery alone", out)
			}
			// An unsigned delivery never reaches the handler.
			expect(t, call(a, "/polar/webhooks", paid, "", nil, signed(paid+" ", "tampered", time.Now(), false)), 403)
			mu.Lock()
			unchanged := len(events) == count
			mu.Unlock()
			if !unchanged {
				t.Fatal("an unsigned delivery reached the handler")
			}
			// A node without a handler answers 200.
			quiet := node(nil)
			expect(t, call(quiet, "/polar/webhooks", paid, "", nil, signed(paid, "quiet", time.Now(), false)), 200)
		})
	}
}

// customerFixture is an individual customer as Polar sends it.
func customerFixture(external, name string, at time.Time) map[string]any {
	return map[string]any{"id": "44444444-4444-4444-8444-444444444444", "created_at": at, "modified_at": nil, "metadata": map[string]any{}, "external_id": external,
		"email": name + "@example.test", "email_verified": true, "type": "individual", "name": name, "billing_address": nil, "tax_id": nil,
		"organization_id": "11111111-1111-4111-8111-111111111111", "deleted_at": nil, "avatar_url": "https://avatars.example.test/" + name}
}

// customerStateFixture is an individual customer's full state.
func customerStateFixture(external, name, product string, at time.Time) map[string]any {
	state := customerFixture(external, name, at)
	state["active_subscriptions"] = []any{map[string]any{"id": "55555555-5555-4555-8555-555555555555", "created_at": at, "modified_at": nil, "metadata": map[string]any{},
		"status": "active", "amount": 1000, "currency": "usd", "recurring_interval": "month", "current_period_start": at, "current_period_end": at.Add(720 * time.Hour),
		"trial_start": nil, "trial_end": nil, "cancel_at_period_end": false, "canceled_at": nil, "started_at": at, "ends_at": nil, "product_id": product, "discount_id": nil, "meters": []any{}}}
	state["granted_benefits"], state["active_meters"] = []any{}, []any{}
	return state
}

// typedFields counts an event's set typed fields.
func typedFields(e Event) int {
	n := 0
	for _, set := range []bool{e.Checkout != nil, e.Order != nil, e.Refund != nil, e.Subscription != nil, e.Product != nil, e.Organization != nil, e.Benefit != nil,
		e.BenefitGrant != nil, e.Customer != nil, e.CustomerState != nil, e.Member != nil, e.CustomerSeat != nil} {
		if set {
			n++
		}
	}
	return n
}

// Every event type of the pinned SDK reaches OnEvent with exactly its typed
// field; undefined types, other API versions and data the SDK rejects reach
// it with the body alone.
func TestTypedWebhookEvents(t *testing.T) {
	ctx := t.Context()
	db, _ := database(t, "sqlite")
	ledger, err := OpenLedger(ctx, db, "sqlite")
	if err != nil {
		t.Fatal(err)
	}
	const merchant = "11111111-1111-4111-8111-111111111111"
	const id = "66666666-6666-4666-8666-666666666666"
	const product = "77777777-7777-4777-8777-777777777777"
	var mu sync.Mutex
	var got []Event
	plugin, err := New(Options{Client: polargo.New(polargo.WithSecurity("fixture")), OrganizationID: merchant, Ledger: ledger,
		Webhooks: &WebhookOptions{Secret: dashboardSecret, OnEvent: func(_ context.Context, e Event) error {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, e)
			return nil
		}}})
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.New(auth.Options{BaseURL: host, Secret: strings.Repeat("t", 40), Store: memory.New(), Plugins: []auth.Plugin{plugin}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	plain := func() map[string]any { return map[string]any{"id": id, "created_at": now} }
	checkout := func() map[string]any {
		return map[string]any{"id": id, "status": "open", "organization_id": merchant, "created_at": now, "expires_at": now.Add(time.Hour), "url": "https://checkout.example.test/" + id}
	}
	benefit := func() map[string]any {
		return map[string]any{"type": "custom", "id": id, "created_at": now, "modified_at": nil, "description": "Support", "selectable": true, "deletable": true,
			"organization_id": merchant, "metadata": map[string]any{}, "properties": map[string]any{"note": nil}}
	}
	grant := func() map[string]any {
		return map[string]any{"created_at": now, "modified_at": nil, "id": id, "is_granted": true, "is_revoked": false, "customer_id": "44444444-4444-4444-8444-444444444444",
			"benefit_id": id, "customer": customerFixture("user-1", "alice", now), "benefit": benefit(), "properties": map[string]any{}}
	}
	with := func(base func() map[string]any, extra map[string]any) func() map[string]any {
		return func() map[string]any {
			m := base()
			for k, v := range extra {
				m[k] = v
			}
			return m
		}
	}
	order := with(plain, map[string]any{"status": "paid"})
	subscription := with(plain, map[string]any{"status": "active", "product_id": product})
	seat := with(plain, map[string]any{"status": "claimed"})
	member := with(plain, map[string]any{"customer_id": "44444444-4444-4444-8444-444444444444", "email": "member@example.test", "role": "member"})
	customer := func() map[string]any { return customerFixture("user-1", "alice", now) }
	state := func() map[string]any { return customerStateFixture("user-1", "alice", product, now) }
	idOf := map[string]func(Event) string{
		"checkout": func(e Event) string { return ptrID(e.Checkout, func(v *components.Checkout) string { return v.ID }) },
		"order":    func(e Event) string { return ptrID(e.Order, func(v *components.Order) string { return v.ID }) },
		"refund":   func(e Event) string { return ptrID(e.Refund, func(v *components.Refund) string { return v.ID }) },
		"subscription": func(e Event) string {
			return ptrID(e.Subscription, func(v *components.Subscription) string { return v.ID })
		},
		"product": func(e Event) string { return ptrID(e.Product, func(v *components.Product) string { return v.ID }) },
		"organization": func(e Event) string {
			return ptrID(e.Organization, func(v *components.Organization) string { return v.ID })
		},
		"benefit": func(e Event) string {
			return ptrID(e.Benefit, func(v *components.Benefit) string {
				if v.BenefitCustom == nil {
					return ""
				}
				return v.BenefitCustom.ID
			})
		},
		"grant": func(e Event) string {
			return ptrID(e.BenefitGrant, func(v *components.BenefitGrantWebhook) string {
				if v.BenefitGrantCustomWebhook == nil {
					return ""
				}
				return v.BenefitGrantCustomWebhook.ID
			})
		},
		"customer": func(e Event) string {
			return ptrID(e.Customer, func(v *components.Customer) string {
				if v.CustomerIndividual == nil || v.CustomerIndividual.ExternalID == nil || *v.CustomerIndividual.ExternalID != "user-1" {
					return ""
				}
				return v.CustomerIndividual.ID
			})
		},
		"state": func(e Event) string {
			return ptrID(e.CustomerState, func(v *components.CustomerState) string {
				if v.CustomerStateIndividual == nil || len(v.CustomerStateIndividual.ActiveSubscriptions) != 1 || v.CustomerStateIndividual.ActiveSubscriptions[0].ProductID != product {
					return ""
				}
				return v.CustomerStateIndividual.ID
			})
		},
		"member": func(e Event) string { return ptrID(e.Member, func(v *components.Member) string { return v.ID }) },
		"seat": func(e Event) string {
			return ptrID(e.CustomerSeat, func(v *components.CustomerSeat) string { return v.ID })
		},
	}
	customerID := "44444444-4444-4444-8444-444444444444"
	rows := []struct {
		typ  components.WebhookEventType
		data func() map[string]any
		kind string
		want string
	}{
		{components.WebhookEventTypeCheckoutCreated, checkout, "checkout", id},
		{components.WebhookEventTypeCheckoutUpdated, checkout, "checkout", id},
		{components.WebhookEventTypeCheckoutExpired, with(checkout, map[string]any{"status": "expired"}), "checkout", id},
		{components.WebhookEventTypeOrderCreated, order, "order", id},
		{components.WebhookEventTypeOrderUpdated, order, "order", id},
		{components.WebhookEventTypeOrderPaid, order, "order", id},
		{components.WebhookEventTypeOrderRefunded, with(plain, map[string]any{"status": "refunded"}), "order", id},
		{components.WebhookEventTypeRefundCreated, plain, "refund", id},
		{components.WebhookEventTypeRefundUpdated, plain, "refund", id},
		{components.WebhookEventTypeSubscriptionCreated, subscription, "subscription", id},
		{components.WebhookEventTypeSubscriptionUpdated, subscription, "subscription", id},
		{components.WebhookEventTypeSubscriptionActive, subscription, "subscription", id},
		{components.WebhookEventTypeSubscriptionCanceled, subscription, "subscription", id},
		{components.WebhookEventTypeSubscriptionUncanceled, subscription, "subscription", id},
		{components.WebhookEventTypeSubscriptionRevoked, subscription, "subscription", id},
		{components.WebhookEventTypeSubscriptionPastDue, subscription, "subscription", id},
		{components.WebhookEventTypeProductCreated, plain, "product", id},
		{components.WebhookEventTypeProductUpdated, plain, "product", id},
		{components.WebhookEventTypeOrganizationUpdated, plain, "organization", id},
		{components.WebhookEventTypeBenefitCreated, benefit, "benefit", id},
		{components.WebhookEventTypeBenefitUpdated, benefit, "benefit", id},
		{components.WebhookEventTypeBenefitGrantCreated, grant, "grant", id},
		{components.WebhookEventTypeBenefitGrantCycled, grant, "grant", id},
		{components.WebhookEventTypeBenefitGrantUpdated, grant, "grant", id},
		{components.WebhookEventTypeBenefitGrantRevoked, grant, "grant", id},
		{components.WebhookEventTypeCustomerCreated, customer, "customer", customerID},
		{components.WebhookEventTypeCustomerUpdated, customer, "customer", customerID},
		{components.WebhookEventTypeCustomerDeleted, customer, "customer", customerID},
		{components.WebhookEventTypeCustomerStateChanged, state, "state", customerID},
		{components.WebhookEventTypeMemberCreated, member, "member", id},
		{components.WebhookEventTypeMemberUpdated, member, "member", id},
		{components.WebhookEventTypeMemberDeleted, member, "member", id},
		{components.WebhookEventTypeCustomerSeatAssigned, seat, "seat", id},
		{components.WebhookEventTypeCustomerSeatClaimed, seat, "seat", id},
		{components.WebhookEventTypeCustomerSeatRevoked, seat, "seat", id},
	}
	deliver := func(delivery, raw string) Event {
		t.Helper()
		mu.Lock()
		before := len(got)
		mu.Unlock()
		expect(t, call(a, "/polar/webhooks", raw, "", nil, signed(raw, delivery, time.Now(), false)), 200)
		mu.Lock()
		defer mu.Unlock()
		if len(got) != before+1 {
			t.Fatal("the delivery did not reach the handler once", delivery)
		}
		return got[len(got)-1]
	}
	for i, row := range rows {
		raw, _ := json.Marshal(map[string]any{"api_version": apiVersion, "timestamp": now, "type": row.typ, "data": row.data()})
		e := deliver(fmt.Sprintf("typed-%d", i), string(raw))
		if idOf[row.kind](e) != row.want || typedFields(e) != 1 || e.Purchase != nil {
			t.Errorf("%s did not decode into its typed field alone: %d fields", row.typ, typedFields(e))
		}
	}
	// Data the pinned SDK cannot type reaches the handler with the body alone.
	bad := []map[string]any{
		{"api_version": "2025-01", "type": "order.paid", "data": order()},
		{"api_version": apiVersion, "type": "order.paid", "data": nil},
		{"api_version": apiVersion, "type": "order.paid", "data": with(order, map[string]any{"status": "not-a-status"})()},
		{"api_version": apiVersion, "type": "member.created", "data": with(plain, map[string]any{"customer_id": customerID, "role": "member"})()},
		{"api_version": apiVersion, "type": "customer.created", "data": with(customer, map[string]any{"type": "organization"})()},
		{"api_version": apiVersion, "type": "unrelated.new.event", "data": plain()},
	}
	for i, payload := range bad {
		raw, _ := json.Marshal(payload)
		if e := deliver(fmt.Sprintf("untyped-%d", i), string(raw)); typedFields(e) != 0 || !bytes.Equal(e.Body, raw) {
			t.Errorf("undefined or undecodable data set a typed field: %d %s", i, raw)
		}
	}
}

func ptrID[T any](v *T, id func(*T) string) string {
	if v == nil {
		return ""
	}
	return id(v)
}
