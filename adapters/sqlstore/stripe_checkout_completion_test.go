package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	stripeclient "github.com/Stonewrit/stonewrit-auth/client/stripe"
	billing "github.com/Stonewrit/stonewrit-auth/plugins/stripe"
	sdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

func sendCheckoutCompletion(t *testing.T, node *auth.Auth, id string, purchase returnCheckout) int {
	t.Helper()
	object := map[string]any{"id": purchase.id, "object": "checkout.session", "mode": "subscription", "status": "complete",
		"customer": purchase.customer, "subscription": purchase.remote, "client_reference_id": purchase.meta["referenceId"], "metadata": purchase.meta}
	raw, err := json.Marshal(map[string]any{"id": id, "object": "event", "type": sdk.EventTypeCheckoutSessionCompleted, "api_version": sdk.APIVersion, "data": map[string]any{"object": object}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", returnOrigin+returnMount+"/stripe/webhook", bytes.NewReader(raw)).WithContext(t.Context())
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Stripe-Signature", webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: raw, Secret: returnSecret}).Header)
	w := httptest.NewRecorder()
	node.ServeHTTP(w, r)
	return w.Code
}

func TestStripeCheckoutCompletionObserver(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			var transportMu, callsMu sync.Mutex
			calls := map[string][]string{}
			owners := map[string]string{}
			handler := func(f *returnFixture, r *http.Request) (*http.Response, error) {
				transportMu.Lock()
				defer transportMu.Unlock()
				return f.provider(r)
			}
			f := configuredReturnFixture(t, dialect, billing.Plan{Name: "pro", PriceID: "price_pro"}, true, handler, func(o *billing.Options) {
				o.Subscriptions.OnSubscriptionComplete = func(ctx context.Context, p billing.SubscriptionComplete) error {
					if p.Request == nil || p.Request.Context() != ctx || p.Request.URL.Path != returnMount+"/stripe/webhook" || p.Request.Body != http.NoBody {
						t.Error("completion omitted the mounted webhook request context")
					}
					remote := p.StripeSubscription
					if remote == nil || remote.Object != "subscription" || p.Subscription.SubscriptionID == nil || remote.ID != *p.Subscription.SubscriptionID || owners[remote.ID] != p.Subscription.ReferenceID || p.Subscription.Status != string(remote.Status) || p.Plan.Name != "pro" {
						t.Errorf("completion lost its bound purchase or plan: %+v", p.Subscription)
					}
					if p.Event.GetObjectValue("object") != "checkout.session" || p.Event.GetObjectValue("metadata", "subscriptionId") != p.Subscription.ID {
						t.Errorf("completion event was not the signed, matching Checkout: %s", p.Event.ID)
					}
					callsMu.Lock()
					calls[p.Event.ID] = append(calls[p.Event.ID], "complete")
					callsMu.Unlock()
					p.Event.Data.Object["object"] = "modified"
					switch p.Event.ID {
					case "evt_browser":
						return errors.New("host observer failed")
					case "evt_org":
						panic("host observer panicked")
					}
					return nil
				}
				o.OnEvent = func(_ context.Context, event sdk.Event) error {
					if event.GetObjectValue("object") != "checkout.session" {
						t.Error("completion callback mutated the generic observer's event")
					}
					callsMu.Lock()
					calls[event.ID] = append(calls[event.ID], "event")
					callsMu.Unlock()
					return nil
				}
			})
			expect := func(id, want string) {
				t.Helper()
				callsMu.Lock()
				defer callsMu.Unlock()
				if got := strings.Join(calls[id], ","); got != want {
					t.Fatalf("delivery %s: got %s, want %s", id, got, want)
				}
			}
			verify := func(node *auth.Auth, id string, purchase returnCheckout, code int) {
				t.Helper()
				if got := sendCheckoutCompletion(t, node, id, purchase); got != code {
					t.Fatalf("%s returned HTTP %d, want %d", id, got, code)
				}
			}

			buyer := f.user("buyer")
			rec := f.start(buyer)
			owners[rec.remote] = buyer.User.ID
			verify(f.a, "evt_first", rec, 200)
			f.back(rec.id, returnTemplate, f.b.SessionCookie(buyer.Token, true), 302, strings.ReplaceAll(returnTemplate, "{CHECKOUT_SESSION_ID}", rec.id))
			expect("evt_first", "complete,event")

			// A customer return can commit before the first signed delivery.
			browser := f.user("browser")
			second := f.start(browser)
			owners[second.remote] = browser.User.ID
			f.back(second.id, returnTemplate, f.b.SessionCookie(browser.Token, true), 302, strings.ReplaceAll(returnTemplate, "{CHECKOUT_SESSION_ID}", second.id))
			expect("evt_browser", "")
			f.mode = "sub-fail"
			verify(f.a, "evt_browser", second, 500)
			expect("evt_browser", "")
			f.mode = ""
			verify(f.a, "evt_browser", second, 200)
			expect("evt_browser", "complete,event")

			// A new, validly signed event still needs the original attempt and actor.
			otherActor := second
			otherActor.meta = maps.Clone(second.meta)
			otherActor.meta["userId"] = buyer.User.ID
			verify(f.b, "evt_wrong_actor", otherActor, 500)
			expect("evt_wrong_actor", "")
			verify(f.b, "evt_browser", otherActor, 500)
			expect("evt_browser", "complete,event")

			owner := meteredClient(t, f.a, buyer.Token)
			var group struct{ ID string }
			if err := owner.Auth.Do(ctx, "POST", "/organization/create", map[string]string{"name": "Billing team", "slug": "billing-completion"}, &group); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.db.ExecContext(ctx, f.store.bind(`UPDATE "organization" SET "stripeCustomerId"=? WHERE "id"=?`), "cus_group", group.ID); err != nil {
				t.Fatal(err)
			}
			purchase, err := owner.Upgrade(ctx, stripeclient.Checkout{Plan: "pro", CustomerType: "organization", ReferenceID: group.ID, SuccessURL: returnTemplate, CancelURL: "/cancel", DisableRedirect: true})
			if err != nil {
				t.Fatal(err)
			}
			org := f.sessions[purchase.ID]
			owners[org.remote] = group.ID
			verify(f.b, "evt_org", org, 200)
			expect("evt_org", "complete,event")
			f.mode = "trial"
			verify(f.a, "evt_org", org, 200)
			if f.state(group.ID) != "trialing" {
				t.Fatal("redelivery did not commit the latest organization subscription")
			}
			expect("evt_org", "complete,event,complete,event")
			f.mode = ""
			bad := org
			bad.meta = maps.Clone(org.meta)
			bad.meta["organizationId"] = browser.User.ID
			verify(f.a, "evt_wrong_org", bad, 500)
			expect("evt_wrong_org", "")

			responses := make(chan int, 2)
			for _, node := range []*auth.Auth{f.a, f.b} {
				go func() { responses <- sendCheckoutCompletion(t, node, "evt_race", rec) }()
			}
			for range 2 {
				if code := <-responses; code != 200 {
					t.Fatalf("concurrent signed delivery returned %d", code)
				}
			}
			entries := calls["evt_race"]
			if len(entries) != 4 || strings.Count(strings.Join(entries, ","), "complete") != 2 {
				t.Fatalf("each concurrent delivery must observe one committed checkout: %v", entries)
			}
			var count int
			err = f.store.db.QueryRowContext(ctx, f.store.bind(`SELECT COUNT(*) FROM "verification" WHERE "id"=?`), stripeRecordID("subscription-update-receipt", "evt_race")).Scan(&count)
			if err != nil || count != 1 {
				t.Fatal("concurrent deliveries lost the shared event receipt", count, err)
			}

			var until time.Time
			err = f.store.db.QueryRowContext(ctx, f.store.bind(`SELECT "expiresAt" FROM "verification" WHERE "id"=?`), stripeRecordID("return", rec.id)).Scan(&until)
			if err != nil || time.Until(until) < 44*24*time.Hour {
				t.Fatal("signed completion lost its original purchase retention", until, err)
			}
			if _, err = f.store.db.ExecContext(ctx, f.store.bind(`UPDATE "session" SET "expiresAt"=? WHERE "userId"=?`), f.store.date(time.Now().Add(20*24*time.Hour)), buyer.User.ID); err != nil {
				t.Fatal(err)
			}
			if _, err = f.store.FindStripeCheckoutReturn(ctx, buyer.User.ID, buyer.Token, rec.id, time.Now().Add(6*24*time.Hour)); err != nil {
				t.Fatal(err)
			}
			if _, err = f.store.FindStripeCheckoutReturn(ctx, buyer.User.ID, buyer.Token, rec.id, time.Now().Add(8*24*time.Hour)); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("completion receipt extended customer access to the hosted return")
			}
			// The immutable event receipt still authenticates this exact retry after
			// the original purchase record is gone. It cannot authorize a new event.
			if _, err = f.store.db.ExecContext(ctx, f.store.bind(`DELETE FROM "verification" WHERE "id"=?`), stripeRecordID("return", rec.id)); err != nil {
				t.Fatal(err)
			}
			verify(f.a, "evt_first", rec, 200)
			expect("evt_first", "complete,event,complete,event")
			verify(f.b, "evt_missing_proof", rec, 200)
			expect("evt_missing_proof", "event")
			// Losing customer ownership during a retry's provider lookup suppresses the callback.
			f.duringSubscriptionGet = func() {
				if _, err := f.store.db.ExecContext(ctx, f.store.bind(`UPDATE "user" SET "stripeCustomerId"=NULL WHERE "id"=?`), buyer.User.ID); err != nil {
					t.Fatal(err)
				}
			}
			verify(f.b, "evt_first", rec, 500)
			expect("evt_first", "complete,event,complete,event")
		})
	}
}
