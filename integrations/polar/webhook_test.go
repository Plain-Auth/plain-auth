package polar

import (
	"bytes"
	"context"
	"encoding/json"
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
