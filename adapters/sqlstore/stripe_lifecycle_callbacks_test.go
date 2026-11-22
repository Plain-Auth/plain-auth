package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	billing "github.com/Plain-Auth/plain-auth/plugins/stripe"
	sdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

type lifecycleSnapshot struct {
	status    string
	periodEnd bool
	at        int64
}

func (s lifecycleSnapshot) object(tag string) map[string]any {
	return map[string]any{"id": "sub_" + tag, "customer": "cus_" + tag, "object": "subscription", "status": s.status,
		"cancel_at_period_end": s.periodEnd, "cancel_at": s.at, "cancellation_details": map[string]string{"reason": "cancellation_requested", "comment": "fixture note"},
		"items": map[string]any{"data": []any{map[string]any{"id": "si_base", "price": map[string]string{"id": "price_pro"}, "quantity": 3}}}}
}

func TestStripeLifecycleCallbacks(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			var mu sync.Mutex
			current := map[string]lifecycleSnapshot{"buyer": {status: "active"}, "group": {status: "active"}}
			triggers := map[string]int{}
			owners := map[string]string{}
			known := map[string]string{}
			record := func(kind string, p billing.SubscriptionEvent) {
				t.Helper()
				mu.Lock()
				defer mu.Unlock()
				if p.Subscription.ID == "" || p.Subscription.ReferenceID != owners[p.StripeSubscription.ID] || p.Subscription.SubscriptionID == nil || *p.Subscription.SubscriptionID != p.StripeSubscription.ID {
					t.Errorf("callback crossed provider/local ownership: %s %+v", kind, p.Subscription)
				}
				triggers[kind+":"+p.Event.ID]++
				known[kind+":"+p.Event.ID] = p.Subscription.ID
			}
			handler := func(f *returnFixture, r *http.Request) (*http.Response, error) {
				tag := strings.TrimPrefix(r.URL.Path, "/v1/subscriptions/sub_")
				mu.Lock()
				state, found := current[tag]
				mu.Unlock()
				if found && r.Method == "GET" {
					return stripeJSON(200, state.object(tag)), nil
				}
				return f.provider(r)
			}
			f := configuredReturnFixture(t, dialect, billing.Plan{Name: "pro", PriceID: "price_pro"}, true, handler, func(o *billing.Options) {
				o.Subscriptions.OnSubscriptionCreated = func(ctx context.Context, p billing.SubscriptionCreated) error {
					if p.Plan.Name != "pro" || p.Plan.PriceID != "price_pro" {
						t.Error("creation omitted its configured plan")
					}
					record("created", p.SubscriptionEvent)
					return nil
				}
				o.Subscriptions.OnSubscriptionCancel = func(ctx context.Context, p billing.SubscriptionCancellation) error {
					if p.CancellationDetails == nil || p.CancellationDetails.Comment != "fixture note" {
						t.Error("pending cancellation lost its signed details")
					}
					record("cancel", p.SubscriptionEvent)
					*p.Subscription.Seats = 999
					p.StripeSubscription.Status = "canceled"
					return nil
				}
				o.Subscriptions.OnSubscriptionUpdate = func(ctx context.Context, p billing.SubscriptionUpdate) error {
					if p.Subscription.Seats == nil || *p.Subscription.Seats == 999 || p.StripeSubscription.Status == "canceled" && p.Event.ID == "evt_period" {
						t.Error("cancellation observer corrupted the independent update payload")
					}
					record("update", p)
					return nil
				}
				o.Subscriptions.OnSubscriptionDeleted = func(ctx context.Context, p billing.SubscriptionEvent) error {
					if p.Subscription.Status != "canceled" {
						t.Error("deletion notified before durable cancellation")
					}
					record("delete", p)
					return nil
				}
				o.OnEvent = func(ctx context.Context, e sdk.Event) error {
					mu.Lock()
					defer mu.Unlock()
					triggers["event:"+e.ID]++
					return nil
				}
			})
			buyer := f.user("buyer")
			owners["sub_buyer"] = buyer.User.ID
			owner := meteredClient(t, f.a, buyer.Token)
			var group struct{ ID string }
			if err := owner.Auth.Do(t.Context(), "POST", "/organization/create", map[string]string{"name": "Callback org", "slug": "callback-org"}, &group); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.db.ExecContext(t.Context(), f.store.bind(`UPDATE "organization" SET "stripeCustomerId"=? WHERE "id"=?`), "cus_group", group.ID); err != nil {
				t.Fatal(err)
			}
			owners["sub_group"] = group.ID
			send := func(a *auth.Auth, id, kind string, obj map[string]any) int {
				raw, _ := json.Marshal(map[string]any{"id": id, "object": "event", "type": "customer.subscription." + kind, "api_version": sdk.APIVersion, "data": map[string]any{"object": obj}})
				req := httptest.NewRequest("POST", returnOrigin+returnMount+"/stripe/webhook", bytes.NewReader(raw)).WithContext(t.Context())
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Stripe-Signature", webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: raw, Secret: returnSecret}).Header)
				res := httptest.NewRecorder()
				a.ServeHTTP(res, req)
				return res.Code
			}
			both := func(id, kind string, obj map[string]any) {
				t.Helper()
				codes := make(chan int, 2)
				for _, a := range []*auth.Auth{f.a, f.b} {
					go func() { codes <- send(a, id, kind, obj) }()
				}
				if x, y := <-codes, <-codes; x != 200 || y != 200 {
					t.Fatalf("%s duplicate statuses %d and %d", id, x, y)
				}
			}
			count := func(key string, n int) {
				t.Helper()
				mu.Lock()
				defer mu.Unlock()
				if triggers[key] != n {
					t.Fatalf("%s called %d times, want %d", key, triggers[key], n)
				}
			}
			for _, tag := range []string{"buyer", "group"} {
				id := "evt_new_" + tag
				both(id, "created", current[tag].object(tag))
				count("created:"+id, 1)
				count("event:"+id, 2)
			}
			set := func(s lifecycleSnapshot) { mu.Lock(); current["group"] = s; mu.Unlock() }
			groupState := lifecycleSnapshot{status: "active", periodEnd: true}
			set(groupState)
			both("evt_period", "updated", groupState.object("group"))
			count("cancel:evt_period", 1)
			count("update:evt_period", 2)
			count("event:evt_period", 2)
			both("evt_already_pending", "updated", groupState.object("group"))
			count("cancel:evt_already_pending", 0)
			groupState.periodEnd = false
			set(groupState)
			both("evt_restored", "updated", groupState.object("group"))
			// A delayed signed cancellation while the actual subscription no longer
			// has a pending cancellation must not produce a fresh transition.
			both("evt_stale", "updated", lifecycleSnapshot{status: "active", periodEnd: true}.object("group"))
			count("cancel:evt_stale", 0)
			groupState.at = 1800000000
			set(groupState)
			both("evt_dated", "updated", groupState.object("group"))
			count("cancel:evt_dated", 1)
			count("update:evt_dated", 2)
			groupState.status, groupState.at = "canceled", 0
			set(groupState)
			both("evt_terminal", "updated", groupState.object("group"))
			both("evt_removed", "deleted", groupState.object("group"))
			count("delete:evt_removed", 2)
			count("event:evt_removed", 2)
			if known["created:evt_new_group"] != known["delete:evt_removed"] {
				t.Fatal("deletion changed the local organization subscription identity")
			}
			// A Checkout-created subscription already owns an incomplete local row.
			cart := f.user("cart")
			rec := f.start(cart)
			obj := lifecycleSnapshot{status: "active"}.object("cart")
			obj["metadata"] = rec.meta
			if send(f.a, "evt_cart", "created", obj) != 200 || send(f.b, "evt_cart", "created", obj) != 200 {
				t.Fatal("known checkout creation did not reconcile")
			}
			count("created:evt_cart", 0)
		})
	}
}
