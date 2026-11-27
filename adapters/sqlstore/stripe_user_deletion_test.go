package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Plain-Org/plain-auth"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
)

// The guide's BeforeDeleteUser recipe blocks account deletion while Stripe
// reports any subscription other than canceled, incomplete or
// incomplete_expired, across result pages, denies it when the lookup
// fails, and allows it otherwise.
func TestStripeUserDeletionGuard(t *testing.T) {
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
			var mu sync.Mutex
			var statuses []string
			var lists int
			var fail bool
			transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				if r.URL.Path != "/v1/subscriptions" || r.Method != "GET" {
					return nil, fmt.Errorf("unexpected Stripe call %s %s", r.Method, r.URL.Path)
				}
				lists++
				if fail {
					return stripeJSON(500, map[string]any{"error": map[string]string{"type": "api_error", "message": "down"}}), nil
				}
				if r.URL.Query().Get("status") != "all" || r.URL.Query().Get("customer") == "" {
					return nil, errors.New("wrong subscription listing")
				}
				// One subscription per page, continued with starting_after.
				next := 0
				if after := r.URL.Query().Get("starting_after"); after != "" {
					next, _ = strconv.Atoi(strings.TrimPrefix(after, "sub_"))
					next++
				}
				var data []any
				if next < len(statuses) {
					data = []any{map[string]any{"id": "sub_" + strconv.Itoa(next), "object": "subscription", "status": statuses[next]}}
				}
				return stripeJSON(200, map[string]any{"object": "list", "url": "/v1/subscriptions", "has_more": next+1 < len(statuses), "data": data}), nil
			})
			remote := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})))
			// The recipe from the guide.
			guard := func(ctx context.Context, user plainauth.User, _ *http.Request) error {
				customer, err := store.StripeCustomer(ctx, user.ID)
				if errors.Is(err, plainauth.ErrNotFound) {
					return nil
				}
				if err != nil {
					return err
				}
				for sub, err := range remote.V1Subscriptions.List(ctx, &sdk.SubscriptionListParams{Customer: sdk.String(customer), Status: sdk.String("all")}).All(ctx) {
					if err != nil {
						return err
					}
					switch sub.Status {
					case sdk.SubscriptionStatusCanceled, sdk.SubscriptionStatusIncomplete, sdk.SubscriptionStatusIncompleteExpired:
					default:
						return &plainauth.APIError{Status: 400, Code: "ACTIVE_SUBSCRIPTION", Message: "Cancel your active subscription before deleting your account"}
					}
				}
				return nil
			}
			const origin = "https://billing.example"
			off := false
			open := func(hook func(context.Context, plainauth.User, *http.Request) error) *plainauth.Auth {
				t.Helper()
				a, err := plainauth.New(plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off, DeleteUserEnabled: true, BeforeDeleteUser: hook,
					Plugins: []plainauth.Plugin{billing.New(billing.Options{WebhookSecret: "whsec_deletion", Subscriptions: &billing.SubscriptionOptions{Client: remote, Plans: []billing.Plan{{Name: "pro", PriceID: "price_pro"}}}})}})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			guarded, unguarded := open(guard), open(nil)
			users := 0
			remove := func(a *plainauth.Auth, customer string, pages ...string) (int, string, bool) {
				t.Helper()
				users++
				name := "user" + strconv.Itoa(users)
				hit, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: name, Email: name + "@example.test", Password: "local fixture password"}, plainauth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				if customer != "" {
					if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`), customer, hit.User.ID); err != nil {
						t.Fatal(err)
					}
				}
				mu.Lock()
				statuses, lists = pages, 0
				mu.Unlock()
				raw, _ := json.Marshal(map[string]string{"password": "local fixture password"})
				r := httptest.NewRequest("POST", origin+"/api/auth/delete-user", bytes.NewReader(raw))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", origin)
				r.AddCookie(a.SessionCookie(hit.Token, true))
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var out map[string]any
				json.Unmarshal(w.Body.Bytes(), &out)
				code, _ := out["code"].(string)
				var remains bool
				if err := store.db.QueryRowContext(ctx, store.bind(`SELECT EXISTS(SELECT 1 FROM "user" WHERE "id"=?)`), hit.User.ID).Scan(&remains); err != nil {
					t.Fatal(err)
				}
				return w.Code, code, remains
			}
			listed := func() int {
				mu.Lock()
				defer mu.Unlock()
				return lists
			}
			if status, _, remains := remove(guarded, ""); status != 200 || remains || listed() != 0 {
				t.Fatal("a user without a customer was not deleted without a lookup", status, remains, listed())
			}
			if status, code, remains := remove(guarded, "cus_two", "canceled", "active"); status != 400 || code != "ACTIVE_SUBSCRIPTION" || !remains || listed() != 2 {
				t.Fatal("an active subscription on a later page did not block deletion", status, code, remains, listed())
			}
			for _, live := range []string{"trialing", "past_due"} {
				if status, code, remains := remove(guarded, "cus_"+live, live); status != 400 || code != "ACTIVE_SUBSCRIPTION" || !remains {
					t.Fatal("a live subscription did not block deletion", live, status, code, remains)
				}
			}
			if status, _, remains := remove(guarded, "cus_ended", "canceled", "incomplete", "incomplete_expired"); status != 200 || remains {
				t.Fatal("ended subscriptions blocked deletion", status, remains)
			}
			mu.Lock()
			fail = true
			mu.Unlock()
			if status, _, remains := remove(guarded, "cus_down", "active"); status < 400 || !remains {
				t.Fatal("a failed lookup allowed deletion", status, remains)
			}
			mu.Lock()
			fail = false
			mu.Unlock()
			if status, _, remains := remove(unguarded, "cus_open", "active"); status != 200 || remains {
				t.Fatal("an instance without the hook did not delete the user", status, remains)
			}
		})
	}
}
