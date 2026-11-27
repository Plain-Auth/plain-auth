package sqlstore

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	browser "github.com/Plain-Org/plain-auth/client/stripe"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
)

var fixtureLineItems = []billing.LineItem{{Price: "price_support", Quantity: 2}, {Price: "price_requests"}}

type lineItemProvider struct {
	supportInterval               string
	receiptSupport, activeSupport int64
	dropSupport                   bool
	key, form                     string
	creates                       int
}

func (p *lineItemProvider) price(id string) map[string]any {
	usage, interval := "licensed", "month"
	if id == "price_requests" {
		usage = "metered"
	}
	if id == "price_support" {
		interval = p.supportInterval
	}
	return map[string]any{"id": id, "active": true, "recurring": map[string]any{"interval": interval, "interval_count": 1, "usage_type": usage}}
}

func (p *lineItemProvider) handle(f *returnFixture, r *http.Request) (*http.Response, error) {
	if id, found := strings.CutPrefix(r.URL.Path, "/v1/prices/"); found {
		return stripeJSON(200, p.price(id)), nil
	}
	if r.Method == "POST" && r.URL.Path == "/v1/checkout/sessions" {
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		if r.Form.Get("line_items[0][price]") != "price_base" || r.Form.Get("line_items[0][quantity]") != "4" ||
			r.Form.Get("line_items[1][price]") != "price_support" || r.Form.Get("line_items[1][quantity]") != "2" ||
			r.Form.Get("line_items[2][price]") != "price_requests" || r.Form.Has("line_items[2][quantity]") || r.Form.Has("line_items[3][price]") {
			f.t.Fatalf("wrong line item Checkout form: %v", r.Form)
		}
		key := r.Header.Get("Idempotency-Key")
		if key == "" || p.creates > 0 && (key != p.key || p.form != r.Form.Encode()) {
			f.t.Fatal("a line item retry changed the idempotency key or the Checkout form")
		}
		p.creates++
		p.key, p.form = key, r.Form.Encode()
		result, err := f.provider(r)
		if err == nil && p.creates == 1 {
			result.Body.Close()
			return nil, errors.New("fixture lost the accepted Checkout response")
		}
		return result, err
	}
	if r.URL.Path == "/v1/checkout/sessions/cs_owner/line_items" {
		return stripeJSON(200, map[string]any{"object": "list", "has_more": false, "data": []any{
			map[string]any{"price": p.price("price_support"), "quantity": p.receiptSupport},
			map[string]any{"price": p.price("price_base"), "quantity": 4},
			map[string]any{"price": p.price("price_requests")},
		}}), nil
	}
	if r.URL.Path == "/v1/subscription_items" {
		data := []any{
			map[string]any{"id": "si_requests", "subscription": "sub_owner", "price": p.price("price_requests")},
			map[string]any{"id": "si_base", "subscription": "sub_owner", "price": p.price("price_base"), "quantity": 8, "current_period_start": 1234, "current_period_end": 5678},
		}
		if !p.dropSupport {
			data = append(data, map[string]any{"id": "si_support", "subscription": "sub_owner", "price": p.price("price_support"), "quantity": p.activeSupport})
		}
		return stripeJSON(200, map[string]any{"object": "list", "has_more": false, "data": data}), nil
	}
	resp, err := f.provider(r)
	if err != nil || resp.StatusCode != 200 {
		return resp, err
	}
	defer resp.Body.Close()
	var obj map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return nil, err
	}
	partial := map[string]any{"object": "list", "has_more": true, "data": []any{map[string]any{"price": p.price("price_requests")}}}
	switch obj["object"] {
	case "checkout.session":
		obj["line_items"] = partial
	case "subscription":
		obj["items"] = partial
	}
	return stripeJSON(200, obj), nil
}

// A plan's line items follow the base line in Checkout, a fixed quantity
// sent and a metered one without; a retry on another node sends the stored
// request; a receipt with another quantity binds nothing; and a missing
// item unmaps the subscription while a changed fixed quantity keeps it.
func TestStripeCheckoutLineItems(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			remote := &lineItemProvider{supportInterval: "year", receiptSupport: 2, activeSupport: 2}
			plan := billing.Plan{Name: "platform", PriceID: "price_base", LineItems: slices.Clone(fixtureLineItems)}
			f := configuredReturnFixture(t, dialect, plan, false, remote.handle)
			owner := f.user("owner")
			first := meteredClient(t, f.a, owner.Token)
			second := meteredClient(t, f.b, owner.Token)
			in := browser.Checkout{Plan: "platform", Seats: 4, SuccessURL: returnTemplate, DisableRedirect: true}
			// A fixed item at another interval is refused before any row.
			_, err := first.Upgrade(t.Context(), in)
			var api *auth.APIError
			if !errors.As(err, &api) || api.Code != "UNSUPPORTED_SUBSCRIPTION_ITEM" || remote.creates != 0 {
				t.Fatal("a yearly fixed item was accepted on a monthly base", err)
			}
			if _, err := f.store.PendingStripeCheckout(t.Context(), owner.User.ID); !errors.Is(err, auth.ErrNotFound) {
				t.Fatalf("a refused line item reserved billing: %v", err)
			}
			remote.supportInterval = "month"
			if _, err := first.Upgrade(t.Context(), in); err == nil || remote.creates != 1 {
				t.Fatalf("expected the lost provider response: %v", err)
			}
			a, err := f.store.PendingStripeCheckout(t.Context(), owner.User.ID)
			if err != nil || !a.PriceVerified || !slices.Equal(a.LineItems, fixtureLineItems) {
				t.Fatalf("the line items were not stored with the purchase: %+v, %v", a, err)
			}
			// The store reserves line items only after their prices were checked.
			other := f.user("other")
			unchecked := billing.CheckoutAttempt{Owner: other.User.ID, Plan: "platform", Interval: "month", Price: "price_base", Seats: 1, SuccessURL: a.SuccessURL, CancelURL: a.CancelURL, LineItems: slices.Clone(fixtureLineItems)}
			if _, err := f.store.ReserveStripeCheckout(t.Context(), other.User.ID, other.Token, unchecked, time.Now()); !errors.Is(err, billing.ErrCheckoutPriceCheck) {
				t.Fatal("line items were reserved without a price check", err)
			}
			page, err := second.Upgrade(t.Context(), in)
			if err != nil || page.ID != "cs_owner" || remote.creates != 2 {
				t.Fatalf("a retry on another node did not resend the stored request: %+v %v", page, err)
			}
			// A receipt with another fixed quantity binds nothing.
			remote.receiptSupport = 3
			if got := signedAddonUpdate(t, f, "customer.subscription.created", "evt_line_creation"); got != 500 || f.state(owner.User.ID) != "incomplete" {
				t.Fatalf("a receipt with another quantity bound the purchase: %d", got)
			}
			remote.receiptSupport = 2
			if got := signedAddonUpdate(t, f, "customer.subscription.created", "evt_line_creation"); got != 200 {
				t.Fatal("the corrected receipt did not bind the purchase", got)
			}
			f.notify(f.sessions[page.ID])
			rows, err := first.List(t.Context())
			if err != nil || len(rows) != 1 || rows[0].Plan != "platform" || rows[0].Seats == nil || *rows[0].Seats != 8 {
				t.Fatalf("the purchase did not bind its base seats: %+v %v", rows, err)
			}
			// A changed fixed quantity stays mapped; a missing item unmaps it.
			remote.activeSupport = 5
			if got := signedAddonUpdate(t, f, "customer.subscription.updated", "evt_line_quantity"); got != 200 || f.state(owner.User.ID) != "active" {
				t.Fatal("a changed fixed quantity lost the plan", got)
			}
			remote.activeSupport = 0
			if got := signedAddonUpdate(t, f, "customer.subscription.updated", "evt_line_zero"); got != 200 || f.state(owner.User.ID) != "unmapped" {
				t.Fatal("a fixed item without a quantity kept the plan", got)
			}
			remote.activeSupport = 5
			remote.dropSupport = true
			if got := signedAddonUpdate(t, f, "customer.subscription.updated", "evt_line_missing"); got != 200 || f.state(owner.User.ID) != "unmapped" {
				t.Fatal("a missing line item kept the plan", got)
			}
			remote.dropSupport = false
			if got := signedAddonUpdate(t, f, "customer.subscription.updated", "evt_line_restored"); got != 200 || f.state(owner.User.ID) != "active" {
				t.Fatal("a restored line item did not recover the plan", got)
			}
		})
	}
}
