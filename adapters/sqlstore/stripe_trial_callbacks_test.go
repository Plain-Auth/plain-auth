package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	stripeclient "github.com/Plain-Auth/plain-auth/client/stripe"
	billing "github.com/Plain-Auth/plain-auth/plugins/stripe"
	sdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

func TestStripePlanTrialCallbacks(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			var mu sync.Mutex
			counts := map[string]int{}
			record := func(key string) { mu.Lock(); defer mu.Unlock(); counts[key]++ }
			expect := func(key string, n int) {
				t.Helper()
				mu.Lock()
				defer mu.Unlock()
				if counts[key] != n {
					t.Fatalf("%s ran %d times; want %d", key, counts[key], n)
				}
			}
			current := map[string]string{}
			owners := map[string]string{}
			object := func(rec returnCheckout, status string) map[string]any {
				return map[string]any{"id": rec.remote, "object": "subscription", "customer": rec.customer, "status": status, "metadata": rec.meta,
					"trial_start": 1700000000, "trial_end": 1701209600, "items": map[string]any{"data": []any{map[string]any{"id": "si_base", "quantity": 1, "price": map[string]string{"id": "price_pro"}}}}}
			}
			handler := func(f *returnFixture, r *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				if remote, ok := strings.CutPrefix(r.URL.Path, "/v1/subscriptions/"); ok && r.Method == "GET" {
					return stripeJSON(200, object(f.sessions["cs_"+strings.TrimPrefix(remote, "sub_")], current[remote])), nil
				}
				return f.provider(r)
			}
			trial := &billing.FreeTrial{Days: 14}
			trial.OnTrialStart = func(ctx context.Context, row billing.Subscription) error {
				if row.TrialStart == nil || row.TrialEnd == nil || row.ReferenceID != owners[*row.SubscriptionID] {
					t.Error("trial start lost its settled purchase or provider dates")
				}
				record("start:" + row.ReferenceID)
				if *row.SubscriptionID == "sub_failure" {
					return errors.New("private start failure")
				}
				*row.Seats = 999
				return nil
			}
			transition := func(kind string) func(context.Context, billing.TrialTransition) error {
				return func(ctx context.Context, p billing.TrialTransition) error {
					if p.Subscription.ReferenceID != owners[*p.Subscription.SubscriptionID] || p.Request.URL.Path != returnMount+"/stripe/webhook" || p.Request.Context() != ctx || p.Request.Body != http.NoBody {
						t.Error("trial transition lost its owner or webhook context")
					}
					record(kind + ":" + p.Subscription.ReferenceID)
					if kind == "expired" {
						panic("private expiry failure")
					}
					return nil
				}
			}
			trial.OnTrialEnd = transition("end")
			trial.OnTrialExpired = transition("expired")
			f := configuredReturnFixture(t, dialect, billing.Plan{Name: "pro", PriceID: "price_pro", FreeTrial: trial}, true, handler, func(o *billing.Options) {
				o.Subscriptions.OnSubscriptionComplete = func(ctx context.Context, p billing.SubscriptionComplete) error {
					record("complete:" + p.Subscription.ReferenceID)
					if *p.Subscription.Seats == 999 {
						t.Error("trial start mutated the completion payload")
					}
					return nil
				}
				o.Subscriptions.OnSubscriptionUpdate = func(ctx context.Context, p billing.SubscriptionUpdate) error {
					record("update:" + p.Event.ID)
					if p.Event.ID == "evt_failed_update" {
						return errors.New("private update failure")
					}
					return nil
				}
				o.OnEvent = func(_ context.Context, e sdk.Event) error { record("event:" + e.ID); return nil }
			})
			owner := f.user("owner")
			first := f.start(owner)
			owners[first.remote] = owner.User.ID
			current[first.remote] = "trialing"
			f.notify(first)
			f.notify(first)
			expect("start:"+owner.User.ID, 2)
			expect("complete:"+owner.User.ID, 2)

			admin := meteredClient(t, f.a, owner.Token)
			var group struct{ ID string }
			if err := admin.Auth.Do(ctx, "POST", "/organization/create", map[string]string{"name": "Trial team", "slug": "trial-team"}, &group); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.db.ExecContext(ctx, f.store.bind(`UPDATE "organization" SET "stripeCustomerId"=? WHERE "id"=?`), "cus_group", group.ID); err != nil {
				t.Fatal(err)
			}
			page, err := admin.Upgrade(ctx, stripeclient.Checkout{Plan: "pro", CustomerType: "organization", ReferenceID: group.ID, DisableRedirect: true})
			if err != nil {
				t.Fatal(err)
			}
			org := f.sessions[page.ID]
			owners[org.remote] = group.ID
			current[org.remote] = "trialing"
			f.notify(org)
			expect("start:"+group.ID, 1)
			send := func(node *auth.Auth, id string, rec returnCheckout, status string) int {
				raw, err := json.Marshal(map[string]any{"id": id, "object": "event", "api_version": sdk.APIVersion, "type": sdk.EventTypeCustomerSubscriptionUpdated, "data": map[string]any{"object": object(rec, status)}})
				if err != nil {
					t.Error(err)
					return 0
				}
				r := httptest.NewRequest("POST", returnOrigin+returnMount+"/stripe/webhook", bytes.NewReader(raw)).WithContext(ctx)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Stripe-Signature", webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: raw, Secret: returnSecret}).Header)
				w := httptest.NewRecorder()
				node.ServeHTTP(w, r)
				return w.Code
			}
			if code := send(f.a, "evt_stale_trial", first, "active"); code != 200 {
				t.Fatal(code)
			}
			expect("end:"+owner.User.ID, 0)
			expect("update:evt_stale_trial", 1)
			for _, tc := range []struct {
				rec                 returnCheckout
				owner, target, kind string
			}{
				{first, owner.User.ID, "active", "end"}, {org, group.ID, "incomplete_expired", "expired"},
			} {
				current[tc.rec.remote] = tc.target
				id := "evt_trial_" + tc.kind
				res := make(chan int, 2)
				for _, node := range []*auth.Auth{f.a, f.b} {
					go func() { res <- send(node, id, tc.rec, tc.target) }()
				}
				for range 2 {
					if code := <-res; code != 200 {
						t.Fatalf("%s delivery: %d", tc.kind, code)
					}
				}
				expect(tc.kind+":"+tc.owner, 1)
				expect("update:"+id, 2)
				expect("event:"+id, 2)
				if got := f.state(tc.owner); got != tc.target {
					t.Fatalf("trial callback ran without committed %s status: %s", tc.target, got)
				}
			}
			failed := f.user("failure")
			last := f.start(failed)
			owners[last.remote] = failed.User.ID
			current[last.remote] = "trialing"
			f.notify(last)
			expect("start:"+failed.User.ID, 1)
			expect("complete:"+failed.User.ID, 0)
			expect("event:evt_"+last.id, 1)
			current[last.remote] = "active"
			if code := send(f.a, "evt_failed_update", last, "active"); code != 200 {
				t.Fatal(code)
			}
			expect("end:"+failed.User.ID, 0)
			expect("event:evt_failed_update", 1)
		})
	}
}
