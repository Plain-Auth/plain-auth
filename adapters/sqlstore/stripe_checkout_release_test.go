package sqlstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Plain-Org/plain-auth"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
)

// A purchase Stripe definitively refused is released with its unsent row,
// so the next request starts a new one; idempotency and lock failures keep
// it for a retry with the same key; the release asks no policy.
func TestRefusedCheckoutReleasesReservation(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		for _, organization := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/organization=%v", dialect, organization), func(t *testing.T) {
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
				var mu sync.Mutex
				var refusal *stripeFailure
				var keys []string
				transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
					mu.Lock()
					defer mu.Unlock()
					if err := r.ParseForm(); err != nil {
						return nil, err
					}
					switch {
					case r.URL.Path == "/v1/prices/price_basic":
						return stripeJSON(200, map[string]any{"id": "price_basic", "active": true, "recurring": map[string]any{"interval": "month", "interval_count": 1, "usage_type": "licensed"}}), nil
					case r.URL.Path == "/v1/customers/search", r.URL.Path == "/v1/customers" && r.Method == "GET":
						return stripeJSON(200, map[string]any{"object": "list", "has_more": false, "data": []any{}}), nil
					case r.URL.Path == "/v1/customers" && r.Method == "POST":
						meta := map[string]string{"userId": r.PostForm.Get("metadata[userId]"), "organizationId": r.PostForm.Get("metadata[organizationId]"), "customerType": r.PostForm.Get("metadata[customerType]")}
						return stripeJSON(200, map[string]any{"id": "cus_release", "object": "customer", "metadata": meta}), nil
					case r.URL.Path == "/v1/checkout/sessions":
						keys = append(keys, r.Header.Get("Idempotency-Key"))
						if refusal != nil {
							body := map[string]string{"type": "invalid_request_error", "message": "secret provider detail", "param": "locale", "request_log_url": "https://dashboard.stripe.test/logs/req_release"}
							if refusal.code != "" {
								body["code"] = refusal.code
							}
							if refusal.status == 400 && refusal.code == "idempotency_error" {
								body["type"] = "idempotency_error"
							}
							res := stripeJSON(refusal.status, map[string]any{"error": body})
							res.Header.Set("Request-Id", "req_release")
							return res, nil
						}
						return stripeJSON(200, map[string]any{"id": "cs_release", "object": "checkout.session", "url": "https://checkout.stripe.test/release"}), nil
					}
					return nil, fmt.Errorf("unexpected Stripe call %s %s", r.Method, r.URL.Path)
				})
				remote := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})))
				var policies atomic.Int32
				var logs bytes.Buffer
				var logMu sync.Mutex
				orgPlugin, err := org.New(org.Options{Store: store})
				if err != nil {
					t.Fatal(err)
				}
				const origin = "https://billing.example"
				off := false
				a, err := plainauth.New(plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off,
					Logger: slog.New(slog.NewTextHandler(lockedWriter{&logMu, &logs}, nil)),
					Plugins: []plainauth.Plugin{orgPlugin, billing.New(billing.Options{WebhookSecret: "whsec_release",
						Organization:  &billing.OrganizationOptions{AuthorizeReference: func(billing.ReferenceAuthorization) bool { policies.Add(1); return true }},
						Subscriptions: &billing.SubscriptionOptions{Client: remote, Plans: []billing.Plan{{Name: "basic", PriceID: "price_basic"}}}})}})
				if err != nil {
					t.Fatal(err)
				}
				hit, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: "owner", Email: "owner@example.test", Password: "local fixture password"}, plainauth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				cookie := a.SessionCookie(hit.Token, true)
				call := func(path string, body map[string]any) (int, map[string]any) {
					t.Helper()
					var src bytes.Buffer
					json.NewEncoder(&src).Encode(body)
					r := httptest.NewRequest("POST", origin+"/api/auth"+path, &src)
					r.Header.Set("Origin", origin)
					r.Header.Set("Content-Type", "application/json")
					r.AddCookie(cookie)
					w := httptest.NewRecorder()
					a.ServeHTTP(w, r)
					var out map[string]any
					json.Unmarshal(w.Body.Bytes(), &out)
					return w.Code, out
				}
				owner, kind := hit.User.ID, "stripe-checkout:"
				body := map[string]any{"plan": "basic", "successUrl": "/done", "cancelUrl": "/cancel", "disableRedirect": true}
				if organization {
					status, out := call("/organization/create", map[string]any{"name": "Release", "slug": "release"})
					id, _ := out["id"].(string)
					if status != 200 || id == "" {
						t.Fatal("organization create", status, out)
					}
					owner, kind = id, "stripe-org-checkout:"
					body["customerType"], body["referenceId"] = "organization", id
				}
				count := func(q string, args ...any) int {
					t.Helper()
					var n int
					if err := store.db.QueryRowContext(ctx, store.bind(q), args...).Scan(&n); err != nil {
						t.Fatal(err)
					}
					return n
				}
				rows := func() int { return count(`SELECT COUNT(*) FROM "subscription" WHERE "referenceId"=?`, owner) }
				reservations := func() int { return count(`SELECT COUNT(*) FROM "verification" WHERE "identifier"=?`, kind+owner) }
				// A definitive refusal releases the purchase each time.
				mu.Lock()
				refusal = &stripeFailure{status: 400, code: "parameter_unknown"}
				mu.Unlock()
				for range 3 {
					before := policies.Load()
					status, out := call("/subscription/upgrade", body)
					if status != 502 || out["code"] != "CHECKOUT_CREATION_FAILED" {
						t.Fatal("a refused Checkout was not answered with 502", status, out)
					}
					if rows() != 0 || reservations() != 0 {
						t.Fatal("refused checkout kept its reservation", rows(), reservations())
					}
					if organization && policies.Load() == before {
						t.Fatal("the organization purchase asked no policy")
					}
				}
				logMu.Lock()
				logged := logs.String()
				logMu.Unlock()
				if !strings.Contains(logged, "Stripe checkout creation failed") || !strings.Contains(logged, "code=parameter_unknown") || !strings.Contains(logged, "param=locale") || !strings.Contains(logged, "request=req_release") || strings.Contains(logged, "secret provider detail") {
					t.Fatal("the refusal was not logged by code alone", logged)
				}
				// Idempotency and lock failures keep the purchase, and the retry
				// reuses its key.
				for _, kept := range []stripeFailure{{status: 400, code: "idempotency_error"}, {status: 429, code: "lock_timeout"}} {
					mu.Lock()
					refusal, keys = &kept, nil
					mu.Unlock()
					status, _ := call("/subscription/upgrade", body)
					if status != 502 || rows() != 1 || reservations() != 1 {
						t.Fatal("a retryable failure released the purchase", kept.code, status, rows(), reservations())
					}
					mu.Lock()
					refusal = nil
					mu.Unlock()
					if status, out := call("/subscription/upgrade", body); status != 200 || out["id"] != "cs_release" {
						t.Fatal("a kept purchase could not be retried", kept.code, status, out)
					}
					mu.Lock()
					same := len(keys) == 2 && keys[0] == keys[1] && keys[0] != ""
					mu.Unlock()
					if !same {
						t.Fatal("the retry used another idempotency key", keys)
					}
					// Settle the reservation for the next case.
					if _, err := store.db.ExecContext(ctx, store.bind(`DELETE FROM "subscription" WHERE "referenceId"=?`), owner); err != nil {
						t.Fatal(err)
					}
					if _, err := store.db.ExecContext(ctx, store.bind(`DELETE FROM "verification" WHERE "identifier"=?`), kind+owner); err != nil {
						t.Fatal(err)
					}
				}
				// The store refuses to release a purchase with a Checkout and
				// ignores a stale attempt.
				if status, _ := call("/subscription/upgrade", body); status != 200 {
					t.Fatal("upgrade", status)
				}
				if organization {
					return
				}
				pending, err := store.PendingStripeCheckout(ctx, owner)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.ReleaseStripeCheckout(ctx, pending); !errors.Is(err, billing.ErrCheckoutReconcile) || rows() != 1 {
					t.Fatal("a purchase with a Checkout was released", err)
				}
				stale := pending
				stale.ID, stale.CheckoutID = "stale_attempt", ""
				if err := store.ReleaseStripeCheckout(ctx, stale); err != nil || rows() != 1 || reservations() != 1 {
					t.Fatal("a stale attempt released the pending purchase", err)
				}
			})
		}
	}
}

// lockedWriter serializes log writes from concurrent requests.
type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// A reservation too large for every store's column is refused before any
// row or Stripe call; one just under the limit is stored intact.
func TestCheckoutReservationSize(t *testing.T) {
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
			var paths []string
			transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				paths = append(paths, r.Method+" "+r.URL.Path)
				if err := r.ParseForm(); err != nil {
					return nil, err
				}
				switch {
				case r.URL.Path == "/v1/prices/price_basic":
					return stripeJSON(200, map[string]any{"id": "price_basic", "active": true, "recurring": map[string]any{"interval": "month", "interval_count": 1, "usage_type": "licensed"}}), nil
				case r.URL.Path == "/v1/customers" && r.Method == "POST":
					return stripeJSON(200, map[string]any{"id": "cus_size", "object": "customer", "metadata": map[string]string{"userId": r.PostForm.Get("metadata[userId]"), "customerType": "user"}}), nil
				case r.URL.Path == "/v1/checkout/sessions":
					return stripeJSON(200, map[string]any{"id": "cs_size", "object": "checkout.session", "url": "https://checkout.stripe.test/size"}), nil
				}
				return nil, fmt.Errorf("unexpected Stripe call %s %s", r.Method, r.URL.Path)
			})
			remote := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})))
			const origin = "https://billing.example"
			off := false
			a, err := plainauth.New(plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off,
				Plugins: []plainauth.Plugin{billing.New(billing.Options{WebhookSecret: "whsec_size", Subscriptions: &billing.SubscriptionOptions{Client: remote, Plans: []billing.Plan{{Name: "basic", PriceID: "price_basic"}}}})}})
			if err != nil {
				t.Fatal(err)
			}
			upgrade := func(name, path string) (string, int, map[string]any) {
				t.Helper()
				hit, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: name, Email: name + "@example.test", Password: "local fixture password"}, plainauth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				var src bytes.Buffer
				json.NewEncoder(&src).Encode(map[string]any{"plan": "basic", "successUrl": path, "cancelUrl": path, "disableRedirect": true})
				r := httptest.NewRequest("POST", origin+"/api/auth/subscription/upgrade", &src)
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "application/json")
				r.AddCookie(a.SessionCookie(hit.Token, true))
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var out map[string]any
				json.Unmarshal(w.Body.Bytes(), &out)
				return hit.User.ID, w.Code, out
			}
			count := func(q string, args ...any) int {
				var n int
				if err := store.db.QueryRowContext(ctx, store.bind(q), args...).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			// Each "&" encodes as six bytes in the stored reservation.
			huge := "/done?" + strings.Repeat("&", 5000)
			id, status, out := upgrade("huge", huge)
			// Only the price check, a read, reaches Stripe.
			mu.Lock()
			called := 0
			for _, p := range paths {
				if strings.HasPrefix(p, "POST ") {
					called++
				}
			}
			mu.Unlock()
			if status != 400 || out["code"] != "CHECKOUT_TOO_LARGE" || count(`SELECT COUNT(*) FROM "subscription" WHERE "referenceId"=?`, id) != 0 || count(`SELECT COUNT(*) FROM "verification" WHERE "identifier"=?`, "stripe-checkout:"+id) != 0 || called != 0 {
				t.Fatal("an oversized reservation was not refused before any row or Stripe call", status, out, called)
			}
			large := "/done?" + strings.Repeat("&", 2000)
			id, status, out = upgrade("large", large)
			if status != 200 {
				t.Fatal("a large reservation under the limit was refused", status, out)
			}
			pending, err := store.PendingStripeCheckout(ctx, id)
			if err != nil || pending.SuccessURL != origin+large || pending.CheckoutID != "cs_size" {
				t.Fatal("a large reservation was not stored intact", err, len(pending.SuccessURL), pending.CheckoutID)
			}
		})
	}
}
