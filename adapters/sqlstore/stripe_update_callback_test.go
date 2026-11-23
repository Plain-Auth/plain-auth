package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

type unavailableUpdateReader struct{ *Store }

func (s unavailableUpdateReader) ReadStripeSubscriptionUpdate(context.Context, billing.SubscriptionIdentity) (*billing.Subscription, error) {
	return nil, errors.New("fixture receipt read failed")
}

func TestStripePostCommitSubscriptionUpdate(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"stripe-organization"})
			if err != nil {
				t.Fatal(err)
			}
			open := func() *Store {
				s, err := OpenWithSchema(ctx, dialect, dsn, ddl)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				return s
			}
			store, observer := open(), open()
			var mu sync.Mutex
			var currentStatus = "active"
			var unavailable bool
			var providerReads atomic.Int32
			object := func(id, customer, status string) map[string]any {
				return map[string]any{"object": "subscription", "id": id, "customer": customer, "status": status,
					"metadata": map[string]string{"provider-only": "fixture-secret"}, "items": map[string]any{"data": []any{map[string]any{
						"id": "si_base", "price": map[string]string{"id": "price_base"}, "quantity": 4, "current_period_start": 1000, "current_period_end": 2000}}}}
			}
			round := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				providerReads.Add(1)
				id := strings.TrimPrefix(r.URL.Path, "/v1/subscriptions/")
				if r.Method != "GET" || (id != "sub_personal" && id != "sub_group") {
					return nil, errors.New("unknown fixture request")
				}
				mu.Lock()
				defer mu.Unlock()
				if unavailable {
					return stripeJSON(503, map[string]any{"error": map[string]string{"message": "fixture unavailable"}}), nil
				}
				return stripeJSON(200, object(id, "cus_"+strings.TrimPrefix(id, "sub_"), currentStatus)), nil
			})
			back := sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: round}, MaxNetworkRetries: sdk.Int64(0)})
			provider := sdk.NewClient("sk_test_update", sdk.WithBackends(back))
			var calls []billing.SubscriptionUpdate
			var general atomic.Int32
			var hookMode string
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			newNode := func(db auth.Store, enabled bool) *auth.Auth {
				so := &billing.SubscriptionOptions{Client: provider, Plans: []billing.Plan{{Name: "pro", PriceID: "price_base"}}}
				if enabled {
					so.OnSubscriptionUpdate = func(hctx context.Context, u billing.SubscriptionUpdate) error {
						lockCtx, cancel := context.WithTimeout(hctx, time.Second)
						defer cancel()
						// This independent connection must be able to acquire the same row
						// and see the committed subscription while the callback is running.
						res, err := observer.db.ExecContext(lockCtx, observer.bind(`UPDATE "subscription" SET "status"="status" WHERE "id"=?`), u.Subscription.ID)
						if err != nil || res == nil {
							t.Errorf("callback ran before billing transaction released its row: %v", err)
						}
						mu.Lock()
						calls = append(calls, u)
						mode := hookMode
						mu.Unlock()
						if !bytes.Contains(u.Event.Data.Raw, []byte("fixture-secret")) || u.StripeSubscription.Metadata["provider-only"] != "fixture-secret" {
							t.Error("signed provider fields missing")
						}
						u.Event.Data.Raw[0] = '!'
						switch mode {
						case "panic":
							panic("fixture-secret must stay private")
						case "error":
							return errors.New("fixture-secret must stay private")
						}
						return nil
					}
				}
				plug := billing.New(billing.Options{WebhookSecret: returnSecret, Subscriptions: so, Organization: &billing.OrganizationOptions{AuthorizeReference: func(billing.ReferenceAuthorization) bool { return false }},
					OnEvent: func(ctx context.Context, e sdk.Event) error {
						if !json.Valid(e.Data.Raw) {
							t.Error("specific hook altered the generic hook's event")
						}
						general.Add(1)
						return nil
					}})
				off := false
				a, err := auth.New(auth.Options{Store: db, BaseURL: returnOrigin, Secret: strings.Repeat("r", 32), EmailAndPassword: true, RateLimit: &off, Logger: logger, Plugins: []auth.Plugin{plug}})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			first, second, disabled := newNode(store, true), newNode(observer, true), newNode(observer, false)
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := store.db.ExecContext(ctx, store.bind(q), args...); err != nil {
					t.Fatal(err)
				}
			}
			account, err := first.SignUpEmail(ctx, auth.SignUpInput{Name: "User", Email: "notice@example.test", Password: "test-password"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			exec(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`, "cus_personal", account.User.ID)
			exec(`INSERT INTO "organization" ("id","name","slug","createdAt","stripeCustomerId") VALUES(?,?,?,?,?)`, "group", "Fixture", "fixture", store.date(time.Now()), "cus_group")
			send := func(a *auth.Auth, id, kind, customer, status string, signed bool) int {
				remote := "sub_" + strings.TrimPrefix(customer, "cus_")
				data, _ := json.Marshal(map[string]any{"object": "event", "type": kind, "id": id, "api_version": sdk.APIVersion, "data": map[string]any{"object": object(remote, customer, status)}})
				r := httptest.NewRequest("POST", returnOrigin+"/api/auth/stripe/webhook", bytes.NewReader(data)).WithContext(ctx)
				r.Header.Set("Content-Type", "application/json")
				if signed {
					r.Header.Set("Stripe-Signature", webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: data, Secret: returnSecret}).Header)
				}
				out := httptest.NewRecorder()
				a.ServeHTTP(out, r)
				return out.Code
			}
			const update = "customer.subscription.updated"
			must := func(want, got int) {
				t.Helper()
				if got != want {
					t.Fatalf("webhook response %d, want %d", got, want)
				}
			}
			must(200, send(first, "evt_create_personal", "customer.subscription.created", "cus_personal", "active", true))
			// An update for a Dashboard subscription can establish its local row.
			// The update hook begins on subsequent updates to that known row.
			must(200, send(first, "evt_first_group", update, "cus_group", "active", true))
			must(400, send(first, "evt_unsigned", update, "cus_personal", "active", false))
			must(200, send(first, "evt_unknown", update, "cus_unknown", "active", true))
			must(200, send(disabled, "evt_disabled", update, "cus_personal", "active", true))
			must(200, send(second, "evt_disabled", update, "cus_personal", "active", true))
			if len(calls) != 0 {
				t.Fatal("callback fired for an unavailable, disabled or non-update event")
			}
			mu.Lock()
			unavailable = true
			mu.Unlock()
			must(500, send(first, "evt_pending", update, "cus_personal", "past_due", true))
			if len(calls) != 0 {
				t.Fatal("uncommitted provider failure notified")
			}
			mu.Lock()
			unavailable = false
			hookMode = "error"
			mu.Unlock()
			must(200, send(first, "evt_pending", update, "cus_personal", "past_due", true))
			if len(calls) != 1 {
				t.Fatalf("expected one committed update, got %d", len(calls))
			}
			u := calls[0]
			if u.Event.ID != "evt_pending" || u.Subscription.ReferenceID != account.User.ID || u.Subscription.Status != "active" || u.StripeSubscription.Status != "past_due" ||
				u.Subscription.SubscriptionID == nil || *u.Subscription.SubscriptionID != u.StripeSubscription.ID || u.Subscription.Seats == nil || *u.Subscription.Seats != 4 {
				t.Fatalf("wrong signed snapshot or committed user subscription: %+v", u)
			}
			mu.Lock()
			currentStatus = "past_due"
			hookMode = "panic"
			mu.Unlock()
			must(200, send(second, "evt_newer", update, "cus_personal", "past_due", true))
			mu.Lock()
			hookMode = ""
			mu.Unlock()
			reads := providerReads.Load()
			must(200, send(second, "evt_pending", update, "cus_personal", "past_due", true))
			if len(calls) != 3 || calls[1].Subscription.Status != "past_due" || calls[2].Subscription.Status != "active" || providerReads.Load() != reads {
				t.Fatal("redelivery lost its own committed snapshot or synchronized the provider again")
			}
			must(500, send(first, "evt_pending", update, "cus_personal", "trialing", true))
			must(500, send(first, "evt_pending", update, "cus_group", "past_due", true))
			if len(calls) != 3 || strings.Contains(logs.String(), "fixture-secret") || strings.Count(logs.String(), "Stripe subscription update callback failed") != 2 {
				t.Fatal("misbound delivery notified the host or callback diagnostics exposed private data")
			}
			genericBefore := general.Load()
			done := make(chan int, 2)
			for _, a := range []*auth.Auth{first, second} {
				go func() { done <- send(a, "evt_group", update, "cus_group", "past_due", true) }()
			}
			must(200, <-done)
			must(200, <-done)
			if len(calls) != 5 || calls[3].Subscription.ID != calls[4].Subscription.ID || calls[3].Subscription.ReferenceID != "group" || general.Load() != genericBefore+2 {
				t.Fatal("concurrent signed organization deliveries did not publish the same committed receipt")
			}
			unreadable := newNode(unavailableUpdateReader{store}, true)
			must(500, send(unreadable, "evt_read_failure", update, "cus_personal", "past_due", true))
			if len(calls) != 5 {
				t.Fatal("failed post-commit read exposed a callback")
			}
			reads = providerReads.Load()
			must(200, send(second, "evt_read_failure", update, "cus_personal", "past_due", true))
			if len(calls) != 6 || providerReads.Load() != reads {
				t.Fatal("a retry could not deliver the already committed update")
			}
			must(200, send(first, "evt_terminal", "customer.subscription.deleted", "cus_personal", "canceled", true))
			must(200, send(second, "evt_late", update, "cus_personal", "past_due", true))
			if len(calls) != 6 {
				t.Fatal("terminal resource generated a new update callback")
			}
			must(200, send(second, "evt_pending", update, "cus_personal", "past_due", true))
			if len(calls) != 7 || calls[6].Subscription.Status != "active" {
				t.Fatal("terminal cleanup lost an already acknowledged event receipt")
			}
		})
	}
}
