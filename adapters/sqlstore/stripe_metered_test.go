package sqlstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/client"
	browser "github.com/Stonewrit/stonewrit-auth/client/stripe"
	billing "github.com/Stonewrit/stonewrit-auth/plugins/stripe"
)

// This transport delegates customer and ownership metadata to the existing
// Checkout fixture. It records the original SDK form independently of the row.
type meteredProvider struct {
	price, interval, receiptUsage string
	form, key                     string
	reads, creates                int
	unavailable                   bool
}

func (p *meteredProvider) handle(f *returnFixture, r *http.Request) (*http.Response, error) {
	price := func(usage string) map[string]any {
		return map[string]any{"id": p.price, "active": true, "recurring": map[string]any{
			"usage_type": usage, "interval": p.interval, "interval_count": 1,
		}}
	}
	if r.Method == "GET" && r.URL.Path == "/v1/prices/"+p.price {
		p.reads++
		if p.unavailable {
			return stripeJSON(503, map[string]any{"error": map[string]string{"message": "fixture catalog unavailable"}}), nil
		}
		return stripeJSON(200, price("metered")), nil
	}
	if r.Method == "POST" && r.URL.Path == "/v1/checkout/sessions" {
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		if r.Form.Get("line_items[0][price]") != p.price || r.Form.Has("line_items[0][quantity]") || r.Form.Has("line_items[1][price]") {
			f.t.Fatalf("incorrect metered Checkout lines: %v", r.Form)
		}
		p.creates++
		key := r.Header.Get("Idempotency-Key")
		if key == "" || p.creates > 1 && (key != p.key || r.Form.Encode() != p.form) {
			f.t.Fatalf("retry changed metered Checkout key or form")
		}
		p.key, p.form = key, r.Form.Encode()
		first, err := f.provider(r)
		if p.creates == 1 && err == nil {
			first.Body.Close()
			return nil, errors.New("fixture disconnected after Stripe created Checkout")
		}
		return first, err
	}

	response, err := f.provider(r)
	if err != nil || response.StatusCode != 200 {
		return response, err
	}
	var obj map[string]any
	err = json.NewDecoder(response.Body).Decode(&obj)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	switch obj["object"] {
	case "checkout.session":
		obj["line_items"] = map[string]any{"data": []any{map[string]any{"price": price(p.receiptUsage)}}}
	case "subscription":
		obj["items"] = map[string]any{"data": []any{map[string]any{
			"price": price("metered"), "quantity": nil, "current_period_start": 1234, "current_period_end": 5678,
		}}}
	default:
		return nil, fmt.Errorf("unexpected provider object %v", obj["object"])
	}
	return stripeJSON(200, obj), nil
}

func meteredClient(t *testing.T, server *auth.Auth, token string) browser.Client {
	t.Helper()
	httpClient := &http.Client{Transport: localBillingTransport(func(r *http.Request) (*http.Response, error) {
		r.AddCookie(server.SessionCookie(token, true))
		out := httptest.NewRecorder()
		server.ServeHTTP(out, r)
		return out.Result(), nil
	})}
	c, err := client.New(returnOrigin+returnMount, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	return browser.Client{Auth: c}
}

func TestMeteredStripeCheckout(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		for _, interval := range []string{"month", "year"} {
			t.Run(dialect+"/"+interval, func(t *testing.T) {
				plan := billing.Plan{Name: "usage", PriceID: "price_month", AnnualPriceID: "price_year"}
				annual := interval == "year"
				remote := &meteredProvider{price: "price_" + interval, interval: interval, receiptUsage: "metered", unavailable: true}
				f := configuredReturnFixture(t, dialect, plan, remote.handle)
				owner, outsider := f.user("owner"), f.user("outsider")
				first := meteredClient(t, f.a, owner.Token)
				replica := meteredClient(t, f.b, owner.Token)
				input := browser.Checkout{Plan: "usage", Annual: annual, SuccessURL: returnTemplate, DisableRedirect: true}
				if annual {
					input.Seats = 7
				}
				if _, err := first.Upgrade(t.Context(), input); err == nil || remote.creates != 0 {
					t.Fatalf("catalog outage issued an unchecked Checkout: %v", err)
				}
				if _, err := f.store.PendingStripeCheckout(t.Context(), owner.User.ID); !errors.Is(err, auth.ErrNotFound) {
					t.Fatalf("catalog outage reserved an unknown billing mode: %v", err)
				}
				remote.unavailable = false
				if _, err := first.Upgrade(t.Context(), input); err == nil || remote.creates != 1 {
					t.Fatalf("first request did not reach the provider and lose the response: %v", err)
				}
				pending, err := f.store.PendingStripeCheckout(t.Context(), owner.User.ID)
				if err != nil || !pending.Metered || !pending.PriceVerified || pending.Quantity() != max(1, input.Seats) {
					t.Fatalf("incomplete reservation did not retain its billing mode: %+v, %v", pending, err)
				}
				page, err := replica.Upgrade(t.Context(), input)
				if err != nil || page.ID != "cs_owner" || page.Redirect || remote.reads != 2 || remote.creates != 2 {
					t.Fatalf("replica did not replay the original Checkout: %+v, %v", page, err)
				}
				cookie := f.a.SessionCookie(owner.Token, true)
				f.back(page.ID, returnTemplate, f.a.SessionCookie(outsider.Token, true), 404, "")
				remote.receiptUsage = "licensed"
				f.back(page.ID, returnTemplate, cookie, 403, "")
				if f.state(owner.User.ID) != "incomplete" {
					t.Fatal("mismatched receipt changed metered subscription state")
				}
				remote.receiptUsage = "metered"
				record := f.sessions[page.ID]
				if annual {
					f.notify(record)
				}
				f.back(page.ID, returnTemplate, cookie, 302, strings.ReplaceAll(returnTemplate, "{CHECKOUT_SESSION_ID}", page.ID))
				f.notify(record)
				f.notify(record)
				rows, err := first.List(t.Context())
				if err != nil || len(rows) != 1 {
					t.Fatalf("metered list after delivery: %v, %v", rows, err)
				}
				row := rows[0]
				if row.ReferenceID != owner.User.ID || row.Seats == nil || *row.Seats != 1 || row.PriceID != remote.price || row.Interval == nil || *row.Interval != interval || row.PeriodEnd == nil || row.PeriodEnd.Unix() != 5678 {
					t.Fatalf("metered subscription did not reconcile its owner, price, period and default quantity: %+v", row)
				}
				foreign, err := meteredClient(t, f.b, outsider.Token).List(t.Context())
				if err != nil || len(foreign) != 0 {
					t.Fatalf("unrelated account listed metered billing: %v, %v", foreign, err)
				}
			})
		}
	}
}
