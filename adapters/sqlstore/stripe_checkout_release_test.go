package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// Checkout receives the requested locale, stored with the purchase so a
// retry reopens it unchanged, and saves the buyer's address, and a
// person's name, onto the customer; an invalid locale or an unknown key is
// refused before Stripe or a reservation.
func TestCheckoutLocale(t *testing.T) {
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
			var mu sync.Mutex
			var forms []url.Values
			var posts int
			lose := false
			transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				if err := r.ParseForm(); err != nil {
					return nil, err
				}
				if r.Method == "POST" {
					posts++
				}
				if lose && r.URL.Path == "/v1/checkout/sessions" {
					forms = append(forms, r.PostForm)
					return stripeJSON(500, map[string]any{"error": map[string]string{"type": "api_error"}}), nil
				}
				switch {
				case r.URL.Path == "/v1/prices/price_basic":
					return stripeJSON(200, map[string]any{"id": "price_basic", "active": true, "recurring": map[string]any{"interval": "month", "interval_count": 1, "usage_type": "licensed"}}), nil
				case r.URL.Path == "/v1/customers/search", r.URL.Path == "/v1/customers" && r.Method == "GET":
					return stripeJSON(200, map[string]any{"object": "list", "has_more": false, "data": []any{}}), nil
				case r.URL.Path == "/v1/customers" && r.Method == "POST":
					meta := map[string]string{"userId": r.PostForm.Get("metadata[userId]"), "organizationId": r.PostForm.Get("metadata[organizationId]"), "customerType": r.PostForm.Get("metadata[customerType]")}
					return stripeJSON(200, map[string]any{"id": fmt.Sprintf("cus_%s_%d", meta["customerType"], posts), "object": "customer", "metadata": meta}), nil
				case r.URL.Path == "/v1/checkout/sessions":
					forms = append(forms, r.PostForm)
					return stripeJSON(200, map[string]any{"id": fmt.Sprintf("cs_locale_%d", len(forms)), "object": "checkout.session", "url": "https://checkout.stripe.test/locale"}), nil
				}
				return nil, fmt.Errorf("unexpected Stripe call %s %s", r.Method, r.URL.Path)
			})
			remote := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})))
			orgPlugin, err := org.New(org.Options{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			const origin = "https://billing.example"
			off := false
			a, err := plainauth.New(plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off,
				Plugins: []plainauth.Plugin{orgPlugin, billing.New(billing.Options{WebhookSecret: "whsec_locale",
					Organization:  &billing.OrganizationOptions{AuthorizeReference: func(m billing.ReferenceAuthorization) bool { return m.Role == "owner" }},
					Subscriptions: &billing.SubscriptionOptions{Client: remote, Plans: []billing.Plan{{Name: "basic", PriceID: "price_basic"}}}})}})
			if err != nil {
				t.Fatal(err)
			}
			users := 0
			newCookie := func() (*http.Cookie, string) {
				users++
				name := fmt.Sprintf("buyer%d", users)
				hit, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: name, Email: name + "@example.test", Password: "local fixture password"}, plainauth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				return a.SessionCookie(hit.Token, true), hit.User.ID
			}
			call := func(cookie *http.Cookie, path string, body map[string]any) (int, map[string]any) {
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
			checkout := func(extra map[string]any) map[string]any {
				body := map[string]any{"plan": "basic", "successUrl": "/done", "cancelUrl": "/cancel", "disableRedirect": true}
				maps.Copy(body, extra)
				return body
			}
			last := func() url.Values {
				mu.Lock()
				defer mu.Unlock()
				return forms[len(forms)-1]
			}
			// A locale reaches Checkout, with the person's customer updates.
			cookie, _ := newCookie()
			if status, out := call(cookie, "/subscription/upgrade", checkout(map[string]any{"locale": "ko"})); status != 200 {
				t.Fatal("upgrade", status, out)
			}
			if f := last(); f.Get("locale") != "ko" || f.Get("customer_update[name]") != "auto" || f.Get("customer_update[address]") != "auto" {
				t.Fatal("the Checkout form lacked the locale or customer updates", f)
			}
			// A retry with another locale reopens the stored purchase.
			mu.Lock()
			creates := len(forms)
			mu.Unlock()
			if status, out := call(cookie, "/subscription/upgrade", checkout(map[string]any{"locale": "en"})); status != 200 || out["id"] != "cs_locale_1" || len(forms) != creates {
				t.Fatal("a retry with another locale did not reopen the purchase", status, out)
			}
			// Invalid locales and unknown keys are refused before Stripe.
			fresh, freshID := newCookie()
			mu.Lock()
			before := posts
			mu.Unlock()
			for _, body := range []map[string]any{checkout(map[string]any{"locale": 11}), checkout(map[string]any{"locale": strings.Repeat("a", 36)})} {
				if status, out := call(fresh, "/subscription/upgrade", body); status != 400 || out["code"] != "VALIDATION_ERROR" || out["message"] != "[body.locale] Invalid input" {
					t.Fatal("an invalid locale was not refused", status, out)
				}
			}
			if status, out := call(fresh, "/subscription/upgrade", checkout(map[string]any{"foo": 1})); status != 400 || out["code"] != "UNSUPPORTED_CHECKOUT_OPTION" {
				t.Fatal("an unknown key was not refused", status, out)
			}
			var reserved int
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "subscription" WHERE "referenceId"=?`), freshID).Scan(&reserved); err != nil || reserved != 0 || posts != before {
				t.Fatal("a refused request reached Stripe or reserved a purchase", reserved, posts-before, err)
			}
			// An empty locale asks for the browser's language.
			if status, out := call(fresh, "/subscription/upgrade", checkout(map[string]any{"locale": ""})); status != 200 || last().Get("locale") != "auto" {
				t.Fatal("an empty locale did not ask for the browser's language", status, out, last())
			}
			// The customer updates are stored with the purchase, so a retry
			// after a lost response sends what the first request sent, and a
			// purchase reserved by an earlier release, without them, sends none.
			lost, lostID := newCookie()
			mu.Lock()
			lose = true
			mu.Unlock()
			if status, out := call(lost, "/subscription/upgrade", checkout(nil)); status != 502 || last().Get("customer_update[address]") != "auto" {
				t.Fatal("a lost Checkout was not kept", status, out)
			}
			var value string
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "value" FROM "verification" WHERE "identifier"=?`), "stripe-checkout:"+lostID).Scan(&value); err != nil || !strings.Contains(value, `"customer_update"`) {
				t.Fatal("the customer updates were not stored with the purchase", err, value)
			}
			var stored map[string]any
			json.Unmarshal([]byte(value), &stored)
			delete(stored, "checkoutParams")
			earlier, _ := json.Marshal(stored)
			if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "verification" SET "value"=? WHERE "identifier"=?`), string(earlier), "stripe-checkout:"+lostID); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			lose = false
			mu.Unlock()
			if status, out := call(lost, "/subscription/upgrade", checkout(nil)); status != 200 || last().Has("customer_update[address]") || last().Has("customer_update[name]") {
				t.Fatal("an earlier release's purchase was sent with other parameters", status, out, last())
			}
			// An organization's Checkout saves only its address.
			status, out := call(cookie, "/organization/create", map[string]any{"name": "Locale", "slug": "locale"})
			group, _ := out["id"].(string)
			if status != 200 || group == "" {
				t.Fatal("organization create", status, out)
			}
			if status, out := call(cookie, "/subscription/upgrade", checkout(map[string]any{"customerType": "organization", "referenceId": group, "locale": "fr"})); status != 200 {
				t.Fatal("organization upgrade", status, out)
			}
			if f := last(); f.Get("locale") != "fr" || f.Get("customer_update[address]") != "auto" || f.Has("customer_update[name]") {
				t.Fatal("an organization's Checkout form was wrong", f)
			}
		})
	}
}

// The upgrade answers Stripe's Checkout Session with a redirect preference;
// a retry of a pending purchase reads it again without a second creation
// while it is open, answering the stored ID and URL once it is complete or
// when that read fails, and nothing from Stripe is stored.
func TestCheckoutSessionResponse(t *testing.T) {
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
			status, creates, reads := "open", 0, 0
			var total float64 = 900
			var hosted any = "https://checkout.stripe.test/full"
			failRead := false
			session := func() map[string]any {
				return map[string]any{"id": "cs_full", "object": "checkout.session", "url": hosted, "status": status, "mode": "subscription", "amount_total": total, "sentinel_field": "provider_only"}
			}
			transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				if err := r.ParseForm(); err != nil {
					return nil, err
				}
				switch {
				case r.URL.Path == "/v1/prices/price_basic":
					return stripeJSON(200, map[string]any{"id": "price_basic", "active": true, "recurring": map[string]any{"interval": "month", "interval_count": 1, "usage_type": "licensed"}}), nil
				case r.URL.Path == "/v1/customers" && r.Method == "POST":
					return stripeJSON(200, map[string]any{"id": "cus_full", "object": "customer", "metadata": map[string]string{"userId": r.PostForm.Get("metadata[userId]"), "customerType": "user"}}), nil
				case r.URL.Path == "/v1/checkout/sessions" && r.Method == "POST":
					creates++
					return stripeJSON(200, session()), nil
				case r.URL.Path == "/v1/checkout/sessions/cs_full" && r.Method == "GET":
					reads++
					if failRead {
						return stripeJSON(500, map[string]any{"error": map[string]string{"type": "api_error"}}), nil
					}
					return stripeJSON(200, session()), nil
				}
				return nil, fmt.Errorf("unexpected Stripe call %s %s", r.Method, r.URL.Path)
			})
			remote := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})))
			const origin = "https://billing.example"
			off := false
			open := func(s *Store) *plainauth.Auth {
				a, err := plainauth.New(plainauth.Options{Store: s, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off,
					Plugins: []plainauth.Plugin{billing.New(billing.Options{WebhookSecret: "whsec_full", Subscriptions: &billing.SubscriptionOptions{Client: remote, Plans: []billing.Plan{{Name: "basic", PriceID: "price_basic"}}}})}})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			a := open(store)
			hit, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: "owner", Email: "owner@example.test", Password: "local fixture password"}, plainauth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			upgrade := func(a *plainauth.Auth) (int, map[string]any) {
				t.Helper()
				var src bytes.Buffer
				json.NewEncoder(&src).Encode(map[string]any{"plan": "basic", "successUrl": "/done", "cancelUrl": "/cancel"})
				r := httptest.NewRequest("POST", origin+"/api/auth/subscription/upgrade", &src)
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "application/json")
				r.AddCookie(a.SessionCookie(hit.Token, true))
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var out map[string]any
				json.Unmarshal(w.Body.Bytes(), &out)
				return w.Code, out
			}
			code, out := upgrade(a)
			want := session()
			want["redirect"] = true
			if code != 200 || !reflect.DeepEqual(out, want) {
				t.Fatal("the upgrade did not answer Stripe's Checkout Session", code, out)
			}
			// A retry on another replica reads the open session again.
			mu.Lock()
			total = 1200
			mu.Unlock()
			code, out = upgrade(a)
			mu.Lock()
			created, read := creates, reads
			mu.Unlock()
			if code != 200 || out["amount_total"] != 1200.0 || out["redirect"] != true || created != 1 || read != 1 {
				t.Fatal("a pending retry did not read the session again", code, out, created, read)
			}
			// A completed session, which has no URL and carries the buyer's
			// details, and a failed read answer the stored ID and URL.
			stored := map[string]any{"id": "cs_full", "url": "https://checkout.stripe.test/full", "redirect": true}
			mu.Lock()
			status, hosted = "complete", nil
			mu.Unlock()
			if code, out = upgrade(a); code != 200 || !reflect.DeepEqual(out, stored) {
				t.Fatal("a completed session was answered whole", code, out)
			}
			mu.Lock()
			failRead = true
			mu.Unlock()
			if code, out = upgrade(a); code != 200 || !reflect.DeepEqual(out, stored) {
				t.Fatal("a failed read did not answer the stored session", code, out)
			}
			var value string
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "value" FROM "verification" WHERE "identifier"=?`), "stripe-checkout:"+hit.User.ID).Scan(&value); err != nil || strings.Contains(value, "provider_only") {
				t.Fatal("Stripe's answer was stored with the purchase", err)
			}
		})
	}
}

// The host's Checkout parameters reach a new purchase's Checkout once,
// beneath the plugin's owned fields and metadata keys, and a refusal or
// failure of the hook reserves nothing.
func TestCheckoutSessionParams(t *testing.T) {
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
				var forms []url.Values
				var keys []string
				var created int
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
						created++
						meta := map[string]string{"userId": r.PostForm.Get("metadata[userId]"), "organizationId": r.PostForm.Get("metadata[organizationId]"), "customerType": r.PostForm.Get("metadata[customerType]")}
						return stripeJSON(200, map[string]any{"id": fmt.Sprintf("cus_params_%d", created), "object": "customer", "metadata": meta}), nil
					case r.URL.Path == "/v1/checkout/sessions" && r.Method == "POST":
						forms, keys = append(forms, r.PostForm), append(keys, r.Header.Get("Idempotency-Key"))
						return stripeJSON(200, map[string]any{"id": fmt.Sprintf("cs_params_%d", len(forms)), "object": "checkout.session", "url": "https://checkout.stripe.test/params"}), nil
					case strings.HasPrefix(r.URL.Path, "/v1/checkout/sessions/") && r.Method == "GET":
						return stripeJSON(200, map[string]any{"id": strings.TrimPrefix(r.URL.Path, "/v1/checkout/sessions/"), "object": "checkout.session", "url": "https://checkout.stripe.test/params"}), nil
					}
					return nil, fmt.Errorf("unexpected Stripe call %s %s", r.Method, r.URL.Path)
				})
				remote := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})))
				var hookMu sync.Mutex
				var calls int
				var seen billing.CheckoutSessionInput
				var hook func(billing.CheckoutSessionInput) (*sdk.CheckoutSessionCreateParams, error)
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
					Plugins: []plainauth.Plugin{orgPlugin, billing.New(billing.Options{WebhookSecret: "whsec_params",
						Organization: &billing.OrganizationOptions{AuthorizeReference: func(m billing.ReferenceAuthorization) bool { return m.Role == "owner" }},
						Subscriptions: &billing.SubscriptionOptions{Client: remote, Plans: []billing.Plan{{Name: "basic", PriceID: "price_basic"}},
							CheckoutSessionParams: func(ctx context.Context, in billing.CheckoutSessionInput) (*sdk.CheckoutSessionCreateParams, error) {
								hookMu.Lock()
								calls, seen = calls+1, in
								h := hook
								hookMu.Unlock()
								// No store transaction is open while the hook runs.
								probe, cancel := context.WithTimeout(ctx, 2*time.Second)
								defer cancel()
								if _, err := store.ListStripeSubscriptions(probe, in.ReferenceID, in.Session.Token, time.Now()); err != nil {
									return nil, err
								}
								return h(in)
							}}})}})
				if err != nil {
					t.Fatal(err)
				}
				users := 0
				newBuyer := func() (*http.Cookie, string, map[string]any) {
					t.Helper()
					users++
					name := fmt.Sprintf("buyer%d", users)
					hit, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: name, Email: name + "@example.test", Password: "local fixture password"}, plainauth.RequestMeta{})
					if err != nil {
						t.Fatal(err)
					}
					cookie := a.SessionCookie(hit.Token, true)
					body := map[string]any{"plan": "basic", "successUrl": "/done", "cancelUrl": "/cancel", "disableRedirect": true}
					reference := hit.User.ID
					if organization {
						var src bytes.Buffer
						json.NewEncoder(&src).Encode(map[string]string{"name": name, "slug": name})
						r := httptest.NewRequest("POST", origin+"/api/auth/organization/create", &src)
						r.Header.Set("Origin", origin)
						r.Header.Set("Content-Type", "application/json")
						r.AddCookie(cookie)
						w := httptest.NewRecorder()
						a.ServeHTTP(w, r)
						var group struct{ ID string }
						if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &group) != nil {
							t.Fatal("organization create", w.Code, w.Body)
						}
						reference = group.ID
						body["customerType"], body["referenceId"] = "organization", group.ID
					}
					return cookie, reference, body
				}
				upgrade := func(cookie *http.Cookie, body map[string]any) (int, map[string]any) {
					t.Helper()
					var src bytes.Buffer
					json.NewEncoder(&src).Encode(body)
					r := httptest.NewRequest("POST", origin+"/api/auth/subscription/upgrade", &src)
					r.Header.Set("Origin", origin)
					r.Header.Set("Content-Type", "application/json")
					r.AddCookie(cookie)
					w := httptest.NewRecorder()
					a.ServeHTTP(w, r)
					var out map[string]any
					json.Unmarshal(w.Body.Bytes(), &out)
					return w.Code, out
				}
				last := func() (url.Values, string) {
					mu.Lock()
					defer mu.Unlock()
					return forms[len(forms)-1], keys[len(keys)-1]
				}
				setHook := func(h func(billing.CheckoutSessionInput) (*sdk.CheckoutSessionCreateParams, error)) {
					hookMu.Lock()
					defer hookMu.Unlock()
					hook, calls = h, 0
				}
				// Forwarded fields, merged metadata and overridden owned fields.
				setHook(func(billing.CheckoutSessionInput) (*sdk.CheckoutSessionCreateParams, error) {
					p := &sdk.CheckoutSessionCreateParams{
						AllowPromotionCodes: sdk.Bool(true), TaxIDCollection: &sdk.CheckoutSessionCreateTaxIDCollectionParams{Enabled: sdk.Bool(true)},
						AutomaticTax: &sdk.CheckoutSessionCreateAutomaticTaxParams{Enabled: sdk.Bool(true)}, BillingAddressCollection: sdk.String("required"),
						CustomText:       &sdk.CheckoutSessionCreateCustomTextParams{Submit: &sdk.CheckoutSessionCreateCustomTextSubmitParams{Message: sdk.String("Thanks")}},
						Metadata:         map[string]string{"planType": "business", "userId": "spoof", "organizationId": "spoof", "__proto__": "x"},
						SubscriptionData: &sdk.CheckoutSessionCreateSubscriptionDataParams{Description: sdk.String("Plan"), Metadata: map[string]string{"planType": "business", "referenceId": "spoof"}, TrialPeriodDays: sdk.Int64(99)},
						Mode:             sdk.String("payment"), Customer: sdk.String("cus_spoof"), CustomerEmail: sdk.String("spoof@example.test"), SuccessURL: sdk.String("https://spoof.example/ok"),
						CancelURL: sdk.String("https://spoof.example/cancel"), ClientReferenceID: sdk.String("spoof"), ExpiresAt: sdk.Int64(1), UIMode: sdk.String("embedded"), ReturnURL: sdk.String("https://spoof.example/return"),
						LineItems: []*sdk.CheckoutSessionCreateLineItemParams{{Price: sdk.String("price_spoof"), Quantity: sdk.Int64(9)}},
						Locale:    sdk.String("fr"), CustomerUpdate: &sdk.CheckoutSessionCreateCustomerUpdateParams{Shipping: sdk.String("auto")},
					}
					p.SetIdempotencyKey("host")
					return p, nil
				})
				cookie, reference, body := newBuyer()
				_ = body
				if status, out := upgrade(cookie, body); status != 200 {
					t.Fatal("upgrade", status, out)
				}
				f, key := last()
				success := origin + "/api/auth/subscription/success?callbackURL=" + url.QueryEscape(origin+"/done") + "&checkoutSessionId={CHECKOUT_SESSION_ID}"
				if organization {
					success += "&organizationId=" + reference
				}
				for field, want := range map[string]string{"allow_promotion_codes": "true", "tax_id_collection[enabled]": "true", "automatic_tax[enabled]": "true", "billing_address_collection": "required",
					"custom_text[submit][message]": "Thanks", "subscription_data[description]": "Plan", "metadata[planType]": "business", "subscription_data[metadata][planType]": "business",
					"mode": "subscription", "client_reference_id": reference, "success_url": success,
					"cancel_url": origin + "/cancel", "line_items[0][price]": "price_basic", "locale": "fr", "customer_update[shipping]": "auto", "metadata[referenceId]": reference, "subscription_data[metadata][referenceId]": reference} {
					if f.Get(field) != want {
						t.Error("the Checkout form field was wrong", field, f.Get(field), want)
					}
				}
				for _, field := range []string{"customer_email", "ui_mode", "return_url", "line_items[1][price]", "subscription_data[trial_period_days]", "metadata[__proto__]", "customer_update[address]"} {
					if f.Has(field) {
						t.Error("the Checkout form carried an owned or dropped field", field, f.Get(field))
					}
				}
				if f.Get("customer") == "cus_spoof" || f.Get("metadata[userId]") == "spoof" || !strings.HasPrefix(key, "auth-checkout-") {
					t.Error("the hook replaced the customer, a plugin metadata key or the idempotency key", f.Get("customer"), key)
				}
				if organization && f.Get("metadata[organizationId]") != reference || !organization && f.Has("metadata[organizationId]") {
					t.Error("the organization metadata was wrong", f.Get("metadata[organizationId]"))
				}
				hookMu.Lock()
				input := seen
				hookMu.Unlock()
				if _, err := json.Marshal(input); err != nil || input.ReferenceID != reference || input.Organization != organization || input.Interval != "month" || input.Seats != 1 || input.Plan.Name != "basic" ||
					input.Request == nil || !strings.HasSuffix(input.Request.URL.Path, "/subscription/upgrade") || input.Request.Body != http.NoBody || input.User.ID == "" {
					t.Error("the hook input was wrong", input, err)
				}
				// A retry reuses the stored parameters without the hook, and a
				// body locale wins over the hook's.
				setHook(func(billing.CheckoutSessionInput) (*sdk.CheckoutSessionCreateParams, error) {
					return &sdk.CheckoutSessionCreateParams{Metadata: map[string]string{"planType": "changed"}}, nil
				})
				if status, _ := upgrade(cookie, body); status != 200 || calls != 0 {
					t.Fatal("a retry asked the hook again", status, calls)
				}
				cookie2, _, body2 := newBuyer()
				maps.Copy(body2, map[string]any{"locale": "ko"})
				if status, _ := upgrade(cookie2, body2); status != 200 {
					t.Fatal("upgrade with a body locale", status)
				}
				if f, _ := last(); f.Get("locale") != "ko" || f.Get("metadata[planType]") != "changed" {
					t.Error("a body locale did not win over the hook's", f.Get("locale"), f.Get("metadata[planType]"))
				}
				// The embedded Params' metadata reaches Checkout beneath the
				// plugin's keys, a returned CustomerUpdate replaces the default
				// whole, and an empty body locale asks for the browser's language
				// over the hook's.
				setHook(func(billing.CheckoutSessionInput) (*sdk.CheckoutSessionCreateParams, error) {
					p := &sdk.CheckoutSessionCreateParams{Locale: sdk.String("de"), CustomerUpdate: &sdk.CheckoutSessionCreateCustomerUpdateParams{Name: sdk.String("auto")}}
					p.Params.Metadata = map[string]string{"orderRef": "r1", "userId": "spoof"}
					return p, nil
				})
				cookie3, _, body3 := newBuyer()
				body3["locale"] = ""
				if status, _ := upgrade(cookie3, body3); status != 200 {
					t.Fatal("upgrade with an empty body locale", status)
				}
				if f, _ := last(); f.Get("locale") != "auto" || f.Get("metadata[orderRef]") != "r1" || f.Get("metadata[userId]") == "spoof" || f.Get("customer_update[name]") != "auto" || f.Has("customer_update[address]") {
					t.Error("the hook's embedded metadata, customer updates or locale were wrong", f)
				}
				cookie4, _, body4 := newBuyer()
				if status, _ := upgrade(cookie4, body4); status != 200 {
					t.Fatal("upgrade without a body locale", status)
				}
				if f, _ := last(); f.Get("locale") != "de" {
					t.Error("the hook's locale did not apply without a body locale", f.Get("locale"))
				}
				// Refusals and failures reserve nothing.
				count := func(ref string) int {
					var n int
					if err := store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "subscription" WHERE "referenceId"=?`), ref).Scan(&n); err != nil {
						t.Fatal(err)
					}
					return n
				}
				for name, tc := range map[string]struct {
					hook   func(billing.CheckoutSessionInput) (*sdk.CheckoutSessionCreateParams, error)
					status int
					code   string
					log    string
				}{
					"refusal": {func(billing.CheckoutSessionInput) (*sdk.CheckoutSessionCreateParams, error) {
						return nil, &plainauth.APIError{Status: 403, Code: "TAX_REQUIRED", Message: "Tax details required"}
					}, 403, "TAX_REQUIRED", ""},
					"failure": {func(billing.CheckoutSessionInput) (*sdk.CheckoutSessionCreateParams, error) {
						return nil, errors.New("private hook failure")
					}, 500, "", "Stripe CheckoutSessionParams failed"},
					"account": {func(billing.CheckoutSessionInput) (*sdk.CheckoutSessionCreateParams, error) {
						p := &sdk.CheckoutSessionCreateParams{}
						p.SetStripeAccount("acct_other")
						return p, nil
					}, 500, "", "unsupported options"},
					"too large": {func(billing.CheckoutSessionInput) (*sdk.CheckoutSessionCreateParams, error) {
						return &sdk.CheckoutSessionCreateParams{CustomText: &sdk.CheckoutSessionCreateCustomTextParams{Submit: &sdk.CheckoutSessionCreateCustomTextSubmitParams{Message: sdk.String(strings.Repeat("a", 17<<10))}}}, nil
					}, 500, "", "cannot be stored"},
				} {
					setHook(tc.hook)
					mu.Lock()
					before := len(forms)
					mu.Unlock()
					logMu.Lock()
					logs.Reset()
					logMu.Unlock()
					buyer, ref, body := newBuyer()
					status, out := upgrade(buyer, body)
					logMu.Lock()
					logged := logs.String()
					logMu.Unlock()
					if status != tc.status || tc.code != "" && out["code"] != tc.code || count(ref) != 0 || len(forms) != before || strings.Contains(logged, "private hook failure") || tc.log != "" && !strings.Contains(logged, tc.log) {
						t.Error("a refused or failed hook reserved a purchase or leaked its error", name, status, out, count(ref), logged)
					}
				}
			})
		}
	}
}

// A customer a concurrent identical purchase created is deleted when the
// purchase it would bind to was released meanwhile by a refused Checkout.
func TestReleasedPurchaseDeletesUnboundCustomer(t *testing.T) {
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
			var arrivals int
			var deletes []string
			both, firstDone := make(chan struct{}), make(chan struct{})
			transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				if err := r.ParseForm(); err != nil {
					return nil, err
				}
				switch {
				case r.URL.Path == "/v1/prices/price_basic":
					return stripeJSON(200, map[string]any{"id": "price_basic", "active": true, "recurring": map[string]any{"interval": "month", "interval_count": 1, "usage_type": "licensed"}}), nil
				case r.URL.Path == "/v1/customers" && r.Method == "POST":
					// Both purchases create a customer; the second answers only
					// once the first purchase was refused and released.
					mu.Lock()
					arrivals++
					n := arrivals
					if n == 2 {
						close(both)
					}
					mu.Unlock()
					<-both
					if n == 2 {
						<-firstDone
					}
					return stripeJSON(200, map[string]any{"id": fmt.Sprintf("cus_race_%d", n), "object": "customer", "metadata": map[string]string{"userId": r.PostForm.Get("metadata[userId]"), "customerType": "user"}}), nil
				case strings.HasPrefix(r.URL.Path, "/v1/customers/") && r.Method == "DELETE":
					mu.Lock()
					deletes = append(deletes, strings.TrimPrefix(r.URL.Path, "/v1/customers/"))
					mu.Unlock()
					return stripeJSON(200, map[string]any{"id": strings.TrimPrefix(r.URL.Path, "/v1/customers/"), "object": "customer", "deleted": true}), nil
				case r.URL.Path == "/v1/checkout/sessions" && r.Method == "POST":
					return stripeJSON(400, map[string]any{"error": map[string]string{"type": "invalid_request_error", "code": "parameter_invalid"}}), nil
				}
				return nil, fmt.Errorf("unexpected Stripe call %s %s", r.Method, r.URL.Path)
			})
			remote := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})))
			const origin = "https://billing.example"
			off := false
			a, err := plainauth.New(plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off,
				Plugins: []plainauth.Plugin{billing.New(billing.Options{WebhookSecret: "whsec_race", Subscriptions: &billing.SubscriptionOptions{Client: remote, Plans: []billing.Plan{{Name: "basic", PriceID: "price_basic"}}}})}})
			if err != nil {
				t.Fatal(err)
			}
			hit, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: "racer", Email: "racer@example.test", Password: "local fixture password"}, plainauth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			results := make(chan int, 2)
			for range 2 {
				go func() {
					raw, _ := json.Marshal(map[string]any{"plan": "basic", "successUrl": "/done", "cancelUrl": "/cancel", "disableRedirect": true})
					r := httptest.NewRequest("POST", origin+"/api/auth/subscription/upgrade", bytes.NewReader(raw))
					r.Header.Set("Origin", origin)
					r.Header.Set("Content-Type", "application/json")
					r.AddCookie(a.SessionCookie(hit.Token, true))
					w := httptest.NewRecorder()
					a.ServeHTTP(w, r)
					results <- w.Code
				}()
			}
			wait := func() int {
				t.Helper()
				select {
				case code := <-results:
					return code
				case <-time.After(30 * time.Second):
					t.Fatal("a purchase did not finish")
				}
				return 0
			}
			first := wait()
			close(firstDone)
			second := wait()
			mu.Lock()
			defer mu.Unlock()
			if first != 502 || second != 409 || len(deletes) != 1 || deletes[0] != "cus_race_2" {
				t.Fatal("the customer created for a released purchase was not deleted", first, second, deletes)
			}
		})
	}
}
