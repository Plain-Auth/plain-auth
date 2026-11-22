package sqlstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	browser "github.com/Plain-Auth/plain-auth/client/stripe"
	billing "github.com/Plain-Auth/plain-auth/plugins/stripe"
	sdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

var fixtureAddons = []string{"price_storage", "price_requests"}

type addonProvider struct {
	interval, receiptPrice, activePrice      string
	key, form                                string
	reads, creates, checkoutLists, itemLists int
}

func (p *addonProvider) price(id string) map[string]any {
	usage, interval := "metered", "month"
	if id == "price_base" {
		usage = "licensed"
	}
	if id == "price_requests" {
		interval = p.interval
	}
	return map[string]any{"id": id, "active": true, "recurring": map[string]any{
		"interval": interval, "interval_count": 1, "usage_type": usage,
	}}
}

func (p *addonProvider) handle(f *returnFixture, r *http.Request) (*http.Response, error) {
	if id, found := strings.CutPrefix(r.URL.Path, "/v1/prices/"); found {
		p.reads++
		return stripeJSON(200, p.price(id)), nil
	}
	if r.Method == "POST" && r.URL.Path == "/v1/checkout/sessions" {
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		if r.Form.Get("line_items[0][price]") != "price_base" || r.Form.Get("line_items[0][quantity]") != "4" ||
			r.Form.Get("line_items[1][price]") != "price_storage" || r.Form.Get("line_items[2][price]") != "price_requests" ||
			r.Form.Has("line_items[1][quantity]") || r.Form.Has("line_items[2][quantity]") || r.Form.Has("line_items[3][price]") {
			f.t.Fatalf("wrong add-on Checkout form: %v", r.Form)
		}
		key := r.Header.Get("Idempotency-Key")
		if key == "" || p.creates > 0 && (key != p.key || p.form != r.Form.Encode()) {
			f.t.Fatal("add-on retry changed original idempotency key or Checkout form")
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
		p.checkoutLists++
		if r.URL.Query().Get("limit") != "20" {
			f.t.Fatalf("unbounded Checkout receipt lookup: %v", r.URL.Query())
		}
		return stripeJSON(200, map[string]any{"object": "list", "has_more": false, "data": []any{
			map[string]any{"price": p.price(p.receiptPrice)},
			map[string]any{"price": p.price("price_base"), "quantity": 4},
			map[string]any{"price": p.price("price_requests")},
		}}), nil
	}
	if r.URL.Path == "/v1/subscription_items" {
		p.itemLists++
		if r.URL.Query().Get("limit") != "20" || r.URL.Query().Get("subscription") != "sub_owner" {
			f.t.Fatalf("unbound subscription items lookup: %v", r.URL.Query())
		}
		return stripeJSON(200, map[string]any{"object": "list", "has_more": false, "data": []any{
			map[string]any{"id": "si_requests", "subscription": "sub_owner", "price": p.price("price_requests")},
			map[string]any{"id": "si_storage", "subscription": "sub_owner", "price": p.price(p.activePrice)},
			map[string]any{"id": "si_base", "subscription": "sub_owner", "price": p.price("price_base"), "quantity": 8, "current_period_start": 1234, "current_period_end": 5678},
		}}), nil
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

func signedAddonUpdate(t *testing.T, f *returnFixture, kind, id string) int {
	t.Helper()
	record := f.sessions["cs_owner"]
	snapshot := map[string]any{"object": "subscription", "id": record.remote, "status": "active", "customer": record.customer, "metadata": record.meta}
	payload, err := json.Marshal(map[string]any{"object": "event", "id": id, "type": kind, "api_version": sdk.APIVersion, "data": map[string]any{"object": snapshot}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, returnOrigin+returnMount+"/stripe/webhook", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Stripe-Signature", webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: payload, Secret: returnSecret}).Header)
	result := httptest.NewRecorder()
	f.b.ServeHTTP(result, r)
	return result.Code
}

func TestStripeMeteredAddons(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			remote := &addonProvider{interval: "year", receiptPrice: "price_storage", activePrice: "price_storage"}
			plan := billing.Plan{Name: "pro", PriceID: "price_base", MeteredPriceIDs: slices.Clone(fixtureAddons)}
			f := configuredReturnFixture(t, dialect, plan, false, remote.handle)
			owner, other := f.user("owner"), f.user("other")
			first := meteredClient(t, f.a, owner.Token)
			second := meteredClient(t, f.b, owner.Token)
			in := browser.Checkout{Plan: "pro", Seats: 4, SuccessURL: returnTemplate, DisableRedirect: true}
			if _, err := first.Upgrade(t.Context(), in); err == nil || remote.creates != 0 {
				t.Fatal("catalog accepted mismatched add-on interval")
			}
			if _, err := f.store.PendingStripeCheckout(t.Context(), owner.User.ID); !errors.Is(err, auth.ErrNotFound) {
				t.Fatalf("invalid add-on reserved billing: %v", err)
			}
			remote.interval = "month"
			if _, err := first.Upgrade(t.Context(), in); err == nil || remote.creates != 1 {
				t.Fatalf("expected ambiguous provider response: %v", err)
			}
			a, err := f.store.PendingStripeCheckout(t.Context(), owner.User.ID)
			if err != nil || !a.PriceVerified || !slices.Equal(a.MeteredPriceIDs, fixtureAddons) || a.Metered {
				t.Fatalf("original basket was not persisted: %+v, %v", a, err)
			}
			reconfigured := a
			reconfigured.MeteredPriceIDs = []string{"price_different"}
			stored, err := f.store.ReserveStripeCheckout(t.Context(), owner.User.ID, owner.Token, reconfigured, time.Now())
			if err != nil || !slices.Equal(stored.MeteredPriceIDs, fixtureAddons) {
				t.Fatalf("changed configuration rewrote the reserved add-ons: %+v, %v", stored, err)
			}
			page, err := second.Upgrade(t.Context(), in)
			if err != nil || page.ID != "cs_owner" || remote.reads != 6 || remote.creates != 2 {
				t.Fatalf("incorrect cross-node checkout retry: %+v %v", page, err)
			}
			f.back(page.ID, returnTemplate, f.b.SessionCookie(other.Token, true), 404, "")
			remote.receiptPrice = "price_unrelated"
			if got := signedAddonUpdate(t, f, "customer.subscription.created", "evt_creation"); got != 500 || f.state(owner.User.ID) != "incomplete" {
				t.Fatalf("substitution in original add-on receipt bound the purchase: %d", got)
			}
			remote.receiptPrice = "price_storage"
			if got := signedAddonUpdate(t, f, "customer.subscription.created", "evt_creation"); got != 200 {
				t.Fatal("corrected original receipt did not recover signed creation", got)
			}
			f.notify(f.sessions[page.ID])
			f.notify(f.sessions[page.ID])
			rows, err := first.List(t.Context())
			if err != nil || len(rows) != 1 || rows[0].ReferenceID != owner.User.ID || rows[0].PriceID != "price_base" || rows[0].Seats == nil || *rows[0].Seats != 8 || rows[0].PeriodEnd == nil || rows[0].PeriodEnd.Unix() != 5678 {
				t.Fatalf("verified add-ons did not bind exactly the current licensed base: %+v %v", rows, err)
			}
			_, err = second.Upgrade(t.Context(), in)
			var api *auth.APIError
			if !errors.As(err, &api) || api.Code != "UNSUPPORTED_SUBSCRIPTION_ITEM" {
				t.Fatalf("existing add-on purchase was offered an incomplete plan switch: %v", err)
			}
			remote.activePrice = "price_substituted"
			if got := signedAddonUpdate(t, f, "customer.subscription.updated", "evt_replaced"); got != 200 || f.state(owner.User.ID) != "unmapped" {
				t.Fatal("unrecognized replacement kept the old entitlement", got)
			}
			remote.activePrice = "price_storage"
			if got := signedAddonUpdate(t, f, "customer.subscription.updated", "evt_repaired"); got != 200 || f.state(owner.User.ID) != "active" {
				t.Fatal("restored add-on did not recover the base plan", got)
			}
			if rows, err := meteredClient(t, f.a, other.Token).List(t.Context()); err != nil || len(rows) != 0 || remote.checkoutLists == 0 || remote.itemLists == 0 {
				t.Fatalf("incorrect ownership or incomplete metadata lookup: %+v %v", rows, err)
			}
		})
	}
}

func TestOrganizationStripeMeteredAddons(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			remote := &addonProvider{interval: "month", receiptPrice: "price_storage", activePrice: "price_storage"}
			f := configuredReturnFixture(t, dialect, billing.Plan{Name: "pro", PriceID: "price_base", MeteredPriceIDs: slices.Clone(fixtureAddons)}, true, remote.handle)
			admin, peer := f.user("admin"), f.user("peer")
			manager := meteredClient(t, f.a, admin.Token)
			other := meteredClient(t, f.b, peer.Token)
			var group struct{ ID string }
			if err := manager.Auth.Do(ctx, "POST", "/organization/create", map[string]string{"name": "Metered group", "slug": "metered-group"}, &group); err != nil {
				t.Fatal(err)
			}
			// Give the organization a distinct Stripe customer from either user.
			if _, err := f.store.db.ExecContext(ctx, f.store.bind(`UPDATE "organization" SET "stripeCustomerId"=? WHERE "id"=?`), "cus_owner", group.ID); err != nil {
				t.Fatal(err)
			}
			in := browser.Checkout{Plan: "pro", ReferenceID: group.ID, CustomerType: "organization", Seats: 4, SuccessURL: returnTemplate, DisableRedirect: true}
			if _, err := other.Upgrade(ctx, in); err == nil || remote.reads != 0 || remote.creates != 0 {
				t.Fatal("nonmember reached the organization metered checkout", err)
			}
			if _, err := manager.Upgrade(ctx, in); err == nil || remote.creates != 1 {
				t.Fatal("missing ambiguous organization checkout", err)
			}
			ownerReplica := meteredClient(t, f.b, admin.Token)
			page, err := ownerReplica.Upgrade(ctx, in)
			if err != nil || page.ID != "cs_owner" {
				t.Fatalf("organization checkout retry: %+v %v", page, err)
			}
			rec := f.sessions[page.ID]
			if rec.meta["customerType"] != "organization" || rec.meta["organizationId"] != group.ID || rec.meta["userId"] != admin.User.ID {
				t.Fatalf("incorrect account metadata for metered add-ons: %+v", rec.meta)
			}
			f.notify(rec)
			if got := signedAddonUpdate(t, f, "customer.subscription.updated", "evt_group"); got != 200 {
				t.Fatalf("organization add-on renewal: %d", got)
			}
			rows, err := manager.ListOrganization(ctx, group.ID)
			if err != nil || len(rows) != 1 || rows[0].ReferenceID != group.ID || rows[0].Seats == nil || *rows[0].Seats != 8 {
				t.Fatalf("organization licensed quantity or ownership changed: %+v %v", rows, err)
			}
			if personal, err := manager.List(ctx); err != nil || len(personal) != 0 {
				t.Fatalf("organization purchase appeared on personal account: %+v %v", personal, err)
			}
			if _, err := other.ListOrganization(ctx, group.ID); err == nil {
				t.Fatal("nonmember read the organization's metered subscription")
			}
		})
	}
}
