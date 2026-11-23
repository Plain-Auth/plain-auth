package sqlstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

func TestStripeSubscriptionReconciliation(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"stripe-subscriptions"})
			if err != nil {
				t.Fatal(err)
			}
			open := func() *Store {
				t.Helper()
				s, err := OpenWithSchema(ctx, dialect, dsn, ddl)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				return s
			}
			db := open()
			peer := open()
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := db.db.ExecContext(ctx, db.bind(q), args...); err != nil {
					t.Fatal(err)
				}
			}
			count := func(n int, q string, args ...any) {
				t.Helper()
				var got int
				if err := db.db.QueryRowContext(ctx, db.bind(q), args...).Scan(&got); err != nil || got != n {
					t.Fatalf("expected %d, got %d for %s: %v", n, got, q, err)
				}
			}
			const customer = "cus_lifecycle"
			const remote = "sub_dashboard"
			const secret = "whsec_lifecycle_local"
			type state struct {
				id, cust, status, price string
				period                  int64
				cancel                  bool
				schedule                string
				meta                    map[string]string
			}
			metadata := map[string]string{}
			current := state{remote, customer, "trialing", "price_base", 1000, false, "", metadata}
			marshal := func(x state) map[string]any {
				obj := map[string]any{"object": "subscription", "id": x.id, "customer": x.cust, "status": x.status,
					"metadata": x.meta, "schedule": x.schedule, "cancel_at_period_end": x.cancel, "items": map[string]any{"data": []any{map[string]any{"quantity": int64(3), "price": map[string]any{"id": x.price}, "current_period_start": x.period, "current_period_end": x.period + 1000}}}}
				if x.status == "trialing" {
					obj["trial_start"], obj["trial_end"] = x.period, x.period+900
				}
				if x.status == "canceled" {
					obj["canceled_at"], obj["ended_at"] = x.period, x.period
				}
				if x.cancel {
					obj["cancel_at"] = x.period + 1000
				}
				return obj
			}
			var mu sync.Mutex
			var requests int
			var pause, release chan struct{}
			get := func() state { mu.Lock(); defer mu.Unlock(); return current }
			set := func(x state) { mu.Lock(); defer mu.Unlock(); current = x }
			transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				snap := current
				requests++
				started, unblock := pause, release
				pause = nil
				mu.Unlock()
				if r.Method != "GET" || r.URL.Path != "/v1/subscriptions/"+snap.id {
					return nil, fmt.Errorf("unexpected provider request")
				}
				if started != nil {
					close(started)
					select {
					case <-unblock:
					case <-r.Context().Done():
						return nil, r.Context().Err()
					}
				}
				return stripeJSON(200, marshal(snap)), nil
			})
			backend := sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})
			plug := billing.New(billing.Options{WebhookSecret: secret, Subscriptions: &billing.SubscriptionOptions{Client: sdk.NewClient("sk_test_local", sdk.WithBackends(backend)), Plans: []billing.Plan{{Name: "basic", PriceID: "price_base"}, {Name: "pro", PriceID: "price_pro", AnnualPriceID: "price_year"}}}})
			newAuth := func(s *Store) *auth.Auth {
				t.Helper()
				off := false
				a, err := auth.New(auth.Options{Store: s, Secret: strings.Repeat("s", 32), BaseURL: "https://bill.example", EmailAndPassword: true, Plugins: []auth.Plugin{plug}, RateLimit: &off})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			a, b := newAuth(db), newAuth(peer)
			signup := func(name string) auth.AuthResult {
				t.Helper()
				u, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: name, Email: name + "@example.test", Password: "fixture-password"}, auth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				return u
			}
			owner, foreign := signup("owner"), signup("foreign")
			exec(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`, customer, owner.User.ID)
			deliver := func(a *auth.Auth, id, kind string, created int64, obj map[string]any, signed bool) int {
				raw, _ := json.Marshal(map[string]any{"id": id, "object": "event", "api_version": sdk.APIVersion, "created": created, "type": kind, "data": map[string]any{"object": obj}})
				req := httptest.NewRequest("POST", "https://bill.example/api/auth/stripe/webhook", bytes.NewReader(raw))
				req.Header.Set("Content-Type", "application/json")
				if signed {
					req.Header.Set("Stripe-Signature", webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: raw, Secret: secret}).Header)
				}
				w := httptest.NewRecorder()
				a.ServeHTTP(w, req)
				return w.Code
			}
			send := func(a *auth.Auth, id, kind string, created int64, snap state, signed bool) int {
				return deliver(a, id, kind, created, marshal(snap), signed)
			}
			check := func(code int, id, kind string, at int64, snap state) {
				t.Helper()
				if got := send(b, id, kind, at, snap, true); got != code {
					t.Fatalf("%s %s: got %d expected %d", kind, id, got, code)
				}
			}
			const created = "customer.subscription.created"
			const updated = "customer.subscription.updated"
			const deleted = "customer.subscription.deleted"
			if send(a, "evt_unsigned", created, 1, current, false) != 400 {
				t.Fatal("accepted unsigned lifecycle event")
			}
			unknown := current
			unknown.cust = "cus_unmapped"
			check(200, "evt_unknown", created, 1, unknown)
			if requests != 0 {
				t.Fatal("unknown customer triggered provider lookup")
			}
			check(200, "evt_create", created, 2, current)
			check(200, "evt_create", created, 2, current)
			if requests != 1 {
				t.Fatal("replay repeated provider lookup")
			}
			read := func(id string) billing.Subscription {
				t.Helper()
				r, err := scanStripeSubscription(db.db.QueryRowContext(ctx, db.bind(`SELECT `+subscriptionFields+` FROM "subscription" WHERE "stripeSubscriptionId"=?`), id))
				if err != nil {
					t.Fatal(err)
				}
				return r
			}
			row := read(remote)
			if row.ReferenceID != owner.User.ID || row.Plan != "basic" || row.Status != "trialing" || row.TrialStart == nil || row.TrialEnd.Unix() != 1900 || row.PeriodEnd.Unix() != 2000 || *row.Seats != 3 {
				t.Fatalf("dashboard creation: %+v", row)
			}
			initial := row.ID
			x := get()
			x.status = "past_due"
			x.period = 2000
			set(x)
			check(200, "evt_payment", updated, 3, x)
			if rows, err := db.ListStripeSubscriptions(ctx, owner.User.ID, owner.Token, time.Now()); err != nil || len(rows) != 0 {
				t.Fatal("past-due subscription still listed", err)
			}
			x.status, x.price, x.period = "active", "price_year", 3000
			x.schedule = "sub_sched"
			x.cancel = true
			set(x)
			check(200, "evt_renew", updated, 4, x)
			row = read(remote)
			if row.ID != initial || row.Plan != "pro" || row.Status != "active" || *row.Interval != "year" || row.PeriodStart.Unix() != 3000 || !*row.CancelAtPeriodEnd || row.CancelAt.Unix() != 4000 || (row.TrialEnd == nil || row.TrialEnd.Unix() != 1900) || *row.ScheduleID != "sub_sched" {
				t.Fatalf("renewal and plan change: %+v", row)
			}
			x.price = "price_unknown"
			set(x)
			check(200, "evt_unknown_price", updated, 5, x)
			if read(remote).Status != "unmapped" {
				t.Fatal("old plan entitlement survived unknown price")
			}
			x.price, x.cancel, x.schedule = "price_base", false, ""
			set(x)
			check(200, "evt_restore", updated, 6, x)
			if row = read(remote); row.Plan != "basic" || row.Status != "active" || *row.CancelAtPeriodEnd || row.CancelAt != nil || row.ScheduleID != nil {
				t.Fatal("restore failed", row)
			}
			// An older provider GET, already inflight on another replica, must
			// not overwrite a newer snapshot in the same Stripe event second.
			x.status = "past_due"
			set(x)
			started, unblock := make(chan struct{}), make(chan struct{})
			mu.Lock()
			pause, release = started, unblock
			mu.Unlock()
			result := make(chan int, 1)
			go func(snap state) { result <- send(a, "evt_inflight", updated, 7, snap, true) }(x)
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("provider read did not start")
			}
			x.status, x.price = "active", "price_pro"
			set(x)
			if got := send(b, "evt_other", updated, 7, x, true); got != 200 {
				close(unblock)
				t.Fatal("racing update", got)
			}
			close(unblock)
			if got := <-result; got != 200 {
				t.Fatal("replica reconciliation retry", got)
			}
			if row = read(remote); row.Plan != "pro" || row.Status != "active" {
				t.Fatal("delayed same-second provider response regressed row", row)
			}
			before := requests
			check(200, "evt_other", updated, 7, x)
			check(200, "evt_inflight", updated, 7, x)
			if requests != before {
				t.Fatal("already-applied notifications triggered another read")
			}
			check(200, "evt_late", updated, 6, x)
			if requests != before+1 || read(remote).Plan != "pro" {
				t.Fatal("unseen late event did not reconcile current provider state")
			}
			foreignSnap := x
			foreignSnap.cust = "cus_elsewhere"
			check(500, "evt_wrong_customer", updated, 8, foreignSnap)
			x.meta = map[string]string{"referenceId": foreign.User.ID}
			set(x)
			check(500, "evt_wrong_owner", updated, 8, x)
			if read(remote).ReferenceID != owner.User.ID {
				t.Fatal("subscription changed owner")
			}
			x.meta = nil
			set(x)
			check(200, "evt_wrong_owner", updated, 8, x) // an error must leave the receipt retryable
			exec(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`, customer, foreign.User.ID)
			check(500, "evt_duplicate_customer", updated, 8, x)
			exec(`UPDATE "user" SET "stripeCustomerId"=NULL WHERE "id"=?`, foreign.User.ID)
			exec(`INSERT INTO "subscription" ("id","plan","referenceId","stripeCustomerId","stripeSubscriptionId","status") VALUES('conflict','pro',?,?,?,'active')`, owner.User.ID, customer, remote)
			check(500, "evt_duplicate_remote", updated, 8, x)
			exec(`DELETE FROM "subscription" WHERE "id"='conflict'`)
			x.status = "canceled"
			x.period = 5000
			check(200, "evt_deleted", deleted, 9, x)
			check(200, "evt_deleted", deleted, 9, x)
			x.status = "active"
			set(x)
			check(200, "evt_after_delete", updated, 10, x)
			if row = read(remote); row.Status != "canceled" || row.CanceledAt.Unix() != 5000 || row.EndedAt.Unix() != 5000 || row.ScheduleID != nil {
				t.Fatal("terminal lifecycle state regressed", row)
			}
			// A delete delivered before its create is a terminal tombstone.
			x.id = "sub_deleted_first"
			x.status = "canceled"
			check(200, "evt_deleted_first", deleted, 12, x)
			x.status = "active"
			set(x)
			check(200, "evt_late_create", created, 11, x)
			count(0, `SELECT COUNT(*) FROM "subscription" WHERE "stripeSubscriptionId"=?`, x.id)
			x.id = "sub_unknown_plan"
			x.price = "price_external"
			set(x)
			check(200, "evt_new_unknown", created, 14, x)
			count(0, `SELECT COUNT(*) FROM "subscription" WHERE "stripeSubscriptionId"=?`, x.id)
			// The signed lifecycle event may beat Checkout. The existing row
			// and the attempt survive until the matching checkout is settled.
			exec(`UPDATE "user" SET "stripeCustomerId"='cus_checkout' WHERE "id"=?`, foreign.User.ID)
			attempt, err := peer.ReserveStripeCheckout(ctx, foreign.User.ID, foreign.Token, billing.CheckoutAttempt{Plan: "basic", Interval: "month", Price: "price_base"}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			x = state{"sub_checkout", "cus_checkout", "trialing", "price_base", 6000, false, "", map[string]string{"userId": attempt.Owner, "referenceId": attempt.Owner, "subscriptionId": attempt.LocalSubscription, "checkoutAttemptId": attempt.ID}}
			set(x)
			check(200, "evt_checkout_first", created, 15, x)
			if row = read(x.id); row.ID != attempt.LocalSubscription || row.Status != "trialing" {
				t.Fatal("did not bind existing checkout", row)
			}
			if _, err := db.FindStripeCheckout(ctx, attempt.Owner, attempt.ID); err != nil {
				t.Fatal("lost pending checkout", err)
			}
			if err := db.SaveStripeCheckoutResult(ctx, attempt, foreign.Token, "cs_early", "https://checkout.example.test", time.Now()); err != nil {
				t.Fatal(err)
			}
			obj := map[string]any{"id": "cs_early", "object": "checkout.session", "mode": "subscription", "customer": x.cust, "subscription": x.id, "client_reference_id": attempt.Owner, "metadata": x.meta}
			if code := deliver(b, "evt_checkout_completed", "checkout.session.completed", 16, obj, true); code != 200 {
				t.Fatal("signed Checkout completion could not settle a reconciled subscription", code)
			}
			if err := peer.ApplyStripeCheckout(ctx, attempt, "cs_early", x.id, "active", 1, 2, 0, 0); err != nil {
				t.Fatal(err)
			}
			if read(x.id).Status != "trialing" {
				t.Fatal("old checkout superseded lifecycle state")
			}
			var left int
			if err := db.db.QueryRowContext(ctx, db.bind(`SELECT COUNT(*) FROM "verification" WHERE "identifier"=?`), "stripe-checkout:"+attempt.Owner).Scan(&left); err != nil || left != 0 {
				t.Fatal("checkout reservation was not released", err)
			}
			// A signed deletion without Checkout metadata still fences a
			// checkout response that had already fetched an active resource.
			early := signup("before")
			exec(`UPDATE "user" SET "stripeCustomerId"='cus_before' WHERE "id"=?`, early.User.ID)
			firstAttempt, err := db.ReserveStripeCheckout(ctx, early.User.ID, early.Token, billing.CheckoutAttempt{Plan: "basic", Interval: "month", Price: "price_base"}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			x = state{"sub_before", "cus_before", "canceled", "price_base", 7000, false, "", nil}
			check(200, "evt_deleted_during_checkout", deleted, 18, x)
			if err := peer.ApplyStripeCheckout(ctx, firstAttempt, "cs_before", x.id, "active", 6000, 7000, 0, 0); err != nil {
				t.Fatal(err)
			}
			if row := read(x.id); row.ID != firstAttempt.LocalSubscription || row.Status != "canceled" {
				t.Fatal("stale checkout revived a deleted subscription")
			}
		})
	}
}
