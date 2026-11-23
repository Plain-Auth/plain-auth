package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/organization"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

const returnOrigin = "https://billing.example"
const returnMount = "/custom/auth"
const returnSecret = "whsec_local_return"
const returnTemplate = returnOrigin + "/done/{CHECKOUT_SESSION_ID}?id={CHECKOUT_SESSION_ID}&result=ok"

type returnCheckout struct {
	id, remote, customer, callback string
	meta                           map[string]string
}

type returnFixture struct {
	t                            *testing.T
	store                        *Store
	a, b                         *auth.Auth
	sessions                     map[string]returnCheckout
	mode                         string
	getCheckout, getSub, onEvent int
	duringSubscriptionGet        func()
}

func (f *returnFixture) event(context.Context, sdk.Event) error { f.onEvent++; return nil }

func (f *returnFixture) provider(r *http.Request) (*http.Response, error) {
	const sessions = "/v1/checkout/sessions"
	if r.Method == "GET" && r.URL.Path == "/v1/prices/price_pro" {
		return stripeJSON(200, map[string]any{"id": "price_pro", "active": true, "recurring": map[string]any{"usage_type": "licensed", "interval": "month", "interval_count": 1}}), nil
	}
	if r.Method == "POST" && r.URL.Path == sessions {
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		customer := r.Form.Get("customer")
		node := strings.TrimPrefix(customer, "cus_")
		rec := returnCheckout{id: "cs_" + node, remote: "sub_" + node, customer: customer, callback: r.Form.Get("success_url"), meta: map[string]string{}}
		for _, k := range []string{"userId", "referenceId", "subscriptionId", "checkoutAttemptId", "organizationId", "customerType"} {
			rec.meta[k] = r.Form.Get("metadata[" + k + "]")
		}
		f.sessions[rec.id] = rec
		return stripeJSON(200, map[string]any{"id": rec.id, "object": "checkout.session", "url": "https://checkout.example/" + rec.id}), nil
	}
	if id, ok := strings.CutPrefix(r.URL.Path, sessions+"/"); ok && r.Method == "GET" {
		f.getCheckout++
		rec, ok := f.sessions[id]
		if !ok || f.mode == "checkout-fail" {
			return stripeJSON(404, map[string]any{"error": map[string]string{"code": "resource_missing", "message": "local unavailable"}}), nil
		}
		status, payment, customer := "complete", "paid", rec.customer
		if f.mode == "unpaid" {
			payment = "unpaid"
		}
		if f.mode == "trial" {
			payment = "no_payment_required"
		}
		if f.mode == "open" {
			status = "open"
		}
		if f.mode == "wrong-customer" {
			customer = "cus_other"
		}
		originalPrice := "price_pro"
		if f.mode == "wrong-price" {
			originalPrice = "price_foreign"
		}
		return stripeJSON(200, map[string]any{"line_items": map[string]any{"data": []any{map[string]any{"quantity": 1, "price": map[string]string{"id": originalPrice}}}}, "id": id, "object": "checkout.session", "mode": "subscription", "status": status, "payment_status": payment, "customer": customer, "client_reference_id": rec.meta["referenceId"], "metadata": rec.meta, "subscription": rec.remote}), nil
	}
	if remote, ok := strings.CutPrefix(r.URL.Path, "/v1/subscriptions/"); ok && r.Method == "GET" {
		f.getSub++
		if f.duringSubscriptionGet != nil {
			action := f.duringSubscriptionGet
			f.duringSubscriptionGet = nil
			action()
		}
		rec := f.sessions["cs_"+strings.TrimPrefix(remote, "sub_")]
		if f.mode == "sub-fail" {
			return stripeJSON(404, map[string]any{"error": map[string]string{"code": "resource_missing", "message": "local unavailable"}}), nil
		}
		price, status := "price_pro", "active"
		if f.mode == "wrong-price" {
			price = "price_foreign"
		}
		if f.mode == "trial" {
			status = "trialing"
		}
		return stripeJSON(200, map[string]any{"id": remote, "object": "subscription", "customer": rec.customer, "metadata": rec.meta, "status": status, "items": map[string]any{"data": []any{map[string]any{"quantity": 1, "price": map[string]any{"id": price}, "current_period_start": 1000, "current_period_end": 2000}}}}), nil
	}
	return stripeJSON(404, map[string]any{"error": map[string]string{"code": "unexpected_route"}}), nil
}

func newReturnFixture(t *testing.T, dialect string) *returnFixture {
	t.Helper()
	return configuredReturnFixture(t, dialect, billing.Plan{Name: "pro", PriceID: "price_pro"}, false, (*returnFixture).provider)
}

func configuredReturnFixture(t *testing.T, dialect string, plan billing.Plan, organizations bool, provider func(*returnFixture, *http.Request) (*http.Response, error), configure ...func(*billing.Options)) *returnFixture {
	t.Helper()
	f := &returnFixture{t: t, sessions: map[string]returnCheckout{}}
	dsn := organizationTestDSN(t, dialect)
	profile := "stripe-subscriptions"
	if organizations {
		profile = "stripe-organization"
	}
	ddl, err := schema.Generate(dialect, []string{profile, "anonymous"})
	if err != nil {
		t.Fatal(err)
	}
	newStore := func() *Store {
		s, err := OpenWithSchema(t.Context(), dialect, dsn, ddl)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	f.store = newStore()
	back := sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: localBillingTransport(func(r *http.Request) (*http.Response, error) { return provider(f, r) })}, MaxNetworkRetries: sdk.Int64(0)})
	stripeOptions := billing.Options{WebhookSecret: returnSecret, Subscriptions: &billing.SubscriptionOptions{Client: sdk.NewClient("sk_test_local", sdk.WithBackends(back)), Plans: []billing.Plan{plan}}, OnEvent: f.event}
	guest, err := auth.NewAnonymous(auth.AnonymousOptions{})
	if err != nil {
		t.Fatal(err)
	}
	plugins := []auth.Plugin{guest}
	if organizations {
		stripeOptions.Organization = &billing.OrganizationOptions{AuthorizeReference: func(member billing.ReferenceAuthorization) bool { return member.Role == "owner" }}
		group, err := organization.New(organization.Options{Store: f.store})
		if err != nil {
			t.Fatal(err)
		}
		plugins = append(plugins, group)
	}
	for _, apply := range configure {
		apply(&stripeOptions)
	}
	plugins = append(plugins, billing.New(stripeOptions))
	off := false
	opts := auth.Options{Store: f.store, BaseURL: returnOrigin + returnMount, Secret: strings.Repeat("s", 32), EmailAndPassword: true, Plugins: plugins, RateLimit: &off}
	f.a, err = auth.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	opts.Store = newStore()
	f.b, err = auth.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *returnFixture) user(name string) auth.AuthResult {
	f.t.Helper()
	got, err := f.a.SignUpEmail(f.t.Context(), auth.SignUpInput{Name: name, Email: name + "@example.test", Password: "fixture password"}, auth.RequestMeta{})
	if err != nil {
		f.t.Fatal(err)
	}
	_, err = f.store.db.ExecContext(f.t.Context(), f.store.bind(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`), "cus_"+name, got.User.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	return got
}
func (f *returnFixture) hit(a *auth.Auth, path string, body io.Reader, cookie *http.Cookie) *httptest.ResponseRecorder {
	method := "GET"
	if body != nil {
		method = "POST"
	}
	req := httptest.NewRequest(method, returnOrigin+returnMount+path, body)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", returnOrigin)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	return w
}
func (f *returnFixture) start(u auth.AuthResult) returnCheckout {
	f.t.Helper()
	raw, _ := json.Marshal(map[string]string{"plan": "pro", "successUrl": returnTemplate, "cancelUrl": "/cancel"})
	w := f.hit(f.a, "/subscription/upgrade", bytes.NewReader(raw), f.a.SessionCookie(u.Token, true))
	if w.Code != 200 {
		f.t.Fatalf("upgrade: %d %s", w.Code, w.Body)
	}
	var out struct{ ID string }
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		f.t.Fatal(err)
	}
	return f.sessions[out.ID]
}
func (f *returnFixture) back(id, callback string, c *http.Cookie, status int, location string) {
	f.t.Helper()
	params := url.Values{"checkoutSessionId": {id}, "callbackURL": {callback}}
	w := f.hit(f.b, "/subscription/success?"+params.Encode(), nil, c)
	if w.Code != status || w.Header().Get("Location") != location {
		f.t.Fatalf("return %s: %d %q, expected %d %q, body %s", id, w.Code, w.Header().Get("Location"), status, location, w.Body)
	}
}
func (f *returnFixture) state(owner string) string {
	f.t.Helper()
	var status string
	err := f.store.db.QueryRowContext(f.t.Context(), f.store.bind(`SELECT "status" FROM "subscription" WHERE "referenceId"=?`), owner).Scan(&status)
	if err != nil {
		f.t.Fatal(err)
	}
	return status
}
func (f *returnFixture) notify(rec returnCheckout) {
	f.t.Helper()
	obj := map[string]any{"id": rec.id, "object": "checkout.session", "mode": "subscription", "customer": rec.customer, "client_reference_id": rec.meta["referenceId"], "metadata": rec.meta, "subscription": rec.remote}
	raw, _ := json.Marshal(map[string]any{"id": "evt_" + rec.id, "object": "event", "api_version": sdk.APIVersion, "type": "checkout.session.completed", "data": map[string]any{"object": obj}})
	req := httptest.NewRequest("POST", returnOrigin+returnMount+"/stripe/webhook", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: raw, Secret: returnSecret}).Header)
	w := httptest.NewRecorder()
	f.a.ServeHTTP(w, req)
	if w.Code != 200 {
		f.t.Fatal("signed notification", w.Code, w.Body)
	}
}

func TestHostedCheckoutReturn(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			f := newReturnFixture(t, dialect)
			owner, other := f.user("owner"), f.user("other")
			c := f.a.SessionCookie(owner.Token, true)
			rec := f.start(owner)
			expected := returnOrigin + returnMount + "/subscription/success?callbackURL=" + url.QueryEscape(returnTemplate) + "&checkoutSessionId={CHECKOUT_SESSION_ID}"
			if rec.callback != expected {
				t.Fatal("Stripe received a different success URL", rec.callback)
			}
			filled := strings.ReplaceAll(returnTemplate, "{CHECKOUT_SESSION_ID}", rec.id)
			f.back(rec.id, returnTemplate, nil, 302, returnTemplate)
			guest := f.hit(f.b, "/sign-in/anonymous", strings.NewReader("{}"), nil)
			if guest.Code != 200 || len(guest.Result().Cookies()) == 0 {
				t.Fatal("guest sign-in", guest.Code, guest.Body)
			}
			f.back(rec.id, returnTemplate, guest.Result().Cookies()[0], 302, returnTemplate)
			f.back("", returnTemplate, c, 302, returnTemplate)
			f.back(rec.id, returnTemplate, f.a.SessionCookie(other.Token, true), 404, "")
			f.back("cs_unknown", returnTemplate, c, 404, "")
			f.back(rec.id, "https://other.example/paid?ref={CHECKOUT_SESSION_ID}", c, 403, "")
			f.back(rec.id, "https://{CHECKOUT_SESSION_ID}.other.example/paid", c, 403, "")
			f.back(rec.id, "//other.example/{CHECKOUT_SESSION_ID}", c, 403, "")
			f.back("cs_bad/../../other", "/paid/{CHECKOUT_SESSION_ID}", c, 400, "")
			f.back(rec.id, "/unrelated", c, 403, "")
			w := f.hit(f.a, "/subscription/success?callbackURL=%2F&callbackURL=%2Fpaid", nil, c)
			if w.Code != 400 {
				t.Fatal("ambiguous return query accepted")
			}
			if f.getCheckout+f.getSub != 0 {
				t.Fatal("unproven checkout reached Stripe")
			}
			for _, tc := range []struct {
				mode string
				code int
			}{{"checkout-fail", 302}, {"open", 302}, {"unpaid", 302}, {"wrong-customer", 403}, {"wrong-price", 403}, {"sub-fail", 302}} {
				f.mode = tc.mode
				location := filled
				if tc.code != 302 {
					location = ""
				}
				f.back(rec.id, returnTemplate, c, tc.code, location)
				if f.state(owner.User.ID) != "incomplete" {
					t.Fatal("unconfirmed browser return activated an entitlement", tc.mode)
				}
			}
			f.mode = "trial"
			f.back(rec.id, returnTemplate, c, 302, filled)
			if f.state(owner.User.ID) != "trialing" || f.onEvent != 0 {
				t.Fatal("browser confirmation did not verify the subscription independently of webhooks")
			}
			reads := f.getCheckout + f.getSub
			f.back(rec.id, returnTemplate, c, 302, filled)
			f.back(rec.id, "", c, 302, returnOrigin+"/")
			f.notify(rec)
			if f.getCheckout+f.getSub != reads || f.onEvent != 1 {
				t.Fatal("replay or subsequent webhook repeated billing reconciliation")
			}
			f.back(rec.id, returnTemplate, f.a.SessionCookie(other.Token, true), 404, "")
			// The webhook can settle before the customer returns to a different replica.
			f.mode = ""
			early := f.start(other)
			f.notify(early)
			reads = f.getCheckout + f.getSub
			f.back(early.id, returnTemplate, f.b.SessionCookie(other.Token, true), 302, strings.ReplaceAll(returnTemplate, "{CHECKOUT_SESSION_ID}", early.id))
			if f.state(other.User.ID) != "active" || f.getCheckout+f.getSub != reads {
				t.Fatal("early webhook receipt was not reused")
			}
			paid := f.user("paid")
			purchase := f.start(paid)
			f.back(purchase.id, returnTemplate, f.b.SessionCookie(paid.Token, true), 302, strings.ReplaceAll(returnTemplate, "{CHECKOUT_SESSION_ID}", purchase.id))
			if f.state(paid.User.ID) != "active" {
				t.Fatal("verified paid checkout was not activated")
			}
			// Revocation during Stripe's GET must win before the return commits.
			revoke := f.user("revoke")
			rr := f.start(revoke)
			f.duringSubscriptionGet = func() {
				if err := f.store.DeleteSession(t.Context(), revoke.Token); err != nil {
					t.Fatal(err)
				}
			}
			f.back(rr.id, returnTemplate, f.a.SessionCookie(revoke.Token, true), 401, "")
			if f.state(revoke.User.ID) != "incomplete" {
				t.Fatal("revoked browser session committed a return")
			}
			racing := f.user("racing")
			raced := f.start(racing)
			f.duringSubscriptionGet = func() {
				f.mode = "trial"
				f.notify(raced)
				f.mode = ""
			}
			f.back(raced.id, returnTemplate, f.a.SessionCookie(racing.Token, true), 302, strings.ReplaceAll(returnTemplate, "{CHECKOUT_SESSION_ID}", raced.id))
			if f.state(racing.User.ID) != "trialing" {
				t.Fatal("browser return replaced the webhook snapshot from another replica")
			}
			// Old attempts must keep exactly the parameters used for their Stripe idempotency key.
			legacy := f.user("legacy")
			attempt, err := f.store.ReserveStripeCheckout(t.Context(), legacy.User.ID, legacy.Token, billing.CheckoutAttempt{Plan: "pro", Price: "price_pro", Interval: "month", SuccessURL: returnTemplate, CancelURL: returnOrigin + "/cancel"}, time.Now())
			if err != nil || attempt.ReturnURL != "" {
				t.Fatal("legacy pending reservation", err)
			}
			old := f.start(legacy)
			if old.callback != returnTemplate || old.meta["checkoutAttemptId"] != attempt.ID {
				t.Fatal("legacy retry changed its provider parameters")
			}
			_, err = f.store.db.ExecContext(t.Context(), f.store.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "id"=?`), f.store.date(time.Now().Add(-time.Second)), stripeRecordID("return", rec.id))
			if err != nil {
				t.Fatal(err)
			}
			f.back(rec.id, returnTemplate, c, 404, "")
		})
	}
}
