package stripe

import (
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	sdk "github.com/stripe/stripe-go/v87"
)

// PlanChangeItem is one subscription item, or one item update sent to
// Stripe. A nil Quantity sends none, as for a metered price.
type PlanChangeItem struct {
	ID       string `json:"id,omitempty"`
	Price    string `json:"price,omitempty"`
	Quantity *int64 `json:"quantity,omitempty"`
	Deleted  bool   `json:"deleted,omitempty"`
}

// PlanChange is a direct subscription update recorded before it is sent to
// Stripe. ID is the idempotency key every server retrying it shares.
type PlanChange struct {
	ID, Owner, Customer, LocalID, Subscription string
	// CurrentPlan, CurrentInterval and CurrentSeats are the local row's plan
	// when the change was computed, and From the subscription's items,
	// sorted by ID.
	CurrentPlan, CurrentInterval string
	CurrentSeats                 int64
	From                         []PlanChangeItem
	// Plan, Interval and Quantity name the target.
	Plan, Interval string
	Quantity       int64
	// Items and Proration are the exact update sent under ID, so a retry
	// carries the same parameters even after the plans changed.
	Items     []PlanChangeItem
	Proration string
	// Created bounds the idempotency key; Started is the latest send.
	Created, Started int64
}

// Targets reports whether the change names the same subscription and target.
func (p PlanChange) Targets(o PlanChange) bool {
	return p.Subscription == o.Subscription && p.Plan == o.Plan && p.Interval == o.Interval && p.Quantity == o.Quantity
}

// SameRequest reports whether the change starts from the same items and
// names the same target, so a retry may reuse its idempotency key.
func (p PlanChange) SameRequest(o PlanChange) bool {
	return p.Targets(o) && p.Owner == o.Owner && p.Customer == o.Customer && p.LocalID == o.LocalID && slices.EqualFunc(p.From, o.From, func(a, b PlanChangeItem) bool {
		return a.ID == b.ID && a.Price == b.Price && a.Deleted == b.Deleted && (a.Quantity == nil) == (b.Quantity == nil) && (a.Quantity == nil || *a.Quantity == *b.Quantity)
	})
}

const (
	// PlanChangeHold is how long a stored change blocks other changes and
	// new schedules after its latest send.
	PlanChangeHold = 30 * time.Minute
	// PlanChangeReuse bounds the age of a reused idempotency key: Stripe
	// keeps idempotent results for 24 hours.
	PlanChangeReuse = 23 * time.Hour
	planChangeSend  = 10 * time.Minute
)

// PlanChangeStore serializes direct plan changes per subscription under the
// owner lock, rechecking the session.
type PlanChangeStore interface {
	// ReserveStripePlanChange returns the stored change when SameRequest
	// holds and it is younger than PlanChangeReuse, refreshing Started. It
	// returns ErrPendingSchedule while a different change was sent within
	// PlanChangeHold or a scheduled change for the subscription has not
	// reached its end, and otherwise stores want under a new ID with
	// Created and Started set to now.
	ReserveStripePlanChange(ctx context.Context, token string, want PlanChange, now time.Time) (PlanChange, error)
	// ReleaseStripePlanChange removes the stored change for which Targets
	// holds, and reports whether one did.
	ReleaseStripePlanChange(ctx context.Context, token string, target PlanChange, now time.Time) (bool, error)
}

var errPlanChangeStorage = billingError(409, "PLAN_CHANGE_UNAVAILABLE", "Direct plan changes require plan change storage")

// basket is a subscription's items matched to one configured plan, as the
// webhook matches them.
type basket struct {
	plan    subscriptionPrice
	seats   int64
	metered bool
	base    *sdk.SubscriptionItem
	extras  []*sdk.SubscriptionItem
	order   []*sdk.SubscriptionItem
}

// currentBasket requires the subscription to be exactly a configured plan:
// its base plus the plan's line items and add-ons. Membership plans keep
// their own flow.
func (s *subscriptions) currentBasket(sub *sdk.Subscription, organization bool) (basket, bool) {
	change := s.subscriptionChange(sub, false, organization)
	if change.Plan == "" || change.ManagedSeatPrice != "" || sub.Items == nil || sub.Items.HasMore {
		return basket{}, false
	}
	b := basket{plan: subscriptionPrice{change.Plan, change.Interval}, seats: change.Seats, order: sub.Items.Data}
	for _, item := range sub.Items.Data {
		if item == nil || item.ID == "" || item.Price == nil {
			return basket{}, false
		}
		if price, ok := s.priceOf(item.Price); ok && price == b.plan && b.base == nil {
			b.base = item
			continue
		}
		b.extras = append(b.extras, item)
	}
	if b.base == nil || len(b.extras) != len(s.plans[change.Plan].extras()) {
		return basket{}, false
	}
	b.metered = recurringAtInterval(b.base.Price, b.plan.interval, sdk.PriceRecurringUsageTypeMetered)
	if !b.metered && (b.base.Quantity < 1 || b.base.Quantity > math.MaxInt32 || !licensedAtInterval(b.base.Price, b.plan.interval)) {
		return basket{}, false
	}
	return b, true
}

// items lists the basket's items sorted by ID, with quantities for
// licensed prices.
func (b basket) items() []PlanChangeItem {
	out := make([]PlanChangeItem, 0, len(b.order))
	for _, item := range b.order {
		v := PlanChangeItem{ID: item.ID, Price: item.Price.ID}
		if !recurringAtInterval(item.Price, b.plan.interval, sdk.PriceRecurringUsageTypeMetered) {
			v.Quantity = sdk.Int64(item.Quantity)
		}
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b PlanChangeItem) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// changeTo is the item update from the basket to the target, in Stripe's
// item order and then new items in plan order. The base takes the target
// price and quantity; an item kept at its price and configured quantity
// gets no entry. Another runtime ignores quantities when it compares items
// and sends new ones without them, so Stripe uses one; here a kept fixed
// item follows its configured quantity and a new one carries it, so the
// purchased quantity follows configuration.
func (b basket) changeTo(t CheckoutAttempt, quantity int64) []PlanChangeItem {
	want := t.extras()
	kept := make([]bool, len(want))
	var out []PlanChangeItem
	for _, item := range b.order {
		if item == b.base {
			v := PlanChangeItem{ID: item.ID, Price: t.Price}
			if !t.Metered {
				v.Quantity = sdk.Int64(quantity)
			}
			out = append(out, v)
			continue
		}
		at := slices.IndexFunc(want, func(l LineItem) bool { return l.Price == item.Price.ID })
		if at < 0 || kept[at] {
			out = append(out, PlanChangeItem{ID: item.ID, Deleted: true})
			continue
		}
		kept[at] = true
		if want[at].Quantity > 0 && item.Quantity != want[at].Quantity {
			out = append(out, PlanChangeItem{ID: item.ID, Quantity: sdk.Int64(want[at].Quantity)})
		}
	}
	for i, l := range want {
		if kept[i] {
			continue
		}
		v := PlanChangeItem{Price: l.Price}
		if l.Quantity > 0 {
			v.Quantity = sdk.Int64(l.Quantity)
		}
		out = append(out, v)
	}
	return out
}

// updatePlanItems changes a subscription's items directly. Another runtime
// opens a portal confirmation, which Stripe refuses for a subscription with
// several items, and writes the plan and seats itself. Here the change is
// reserved with a durable idempotency key, so a retry never updates or
// prorates twice, and the row is synchronized from Stripe afterwards.
func (s *subscriptions) updatePlanItems(c auth.EndpointContext, selection billingSelection, local Subscription, sub *sdk.Subscription, b basket, to Plan, t CheckoutAttempt, quantity int64, returnURL string) (any, error) {
	store, ok := c.Store().(PlanChangeStore)
	if !ok {
		return nil, errPlanChangeStorage
	}
	ctx := c.Request.Context()
	token := selection.session.Session.Token
	want := PlanChange{Owner: selection.reference, Customer: sub.Customer.ID, LocalID: local.ID, Subscription: sub.ID,
		CurrentPlan: b.plan.plan, CurrentInterval: b.plan.interval, CurrentSeats: b.seats, From: b.items(),
		Plan: to.Name, Interval: t.Interval, Quantity: quantity, Items: b.changeTo(t, quantity), Proration: to.ProrationBehavior}
	change, err := store.ReserveStripePlanChange(ctx, token, want, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	params := &sdk.SubscriptionUpdateParams{ProrationBehavior: sdk.String(change.Proration)}
	for _, item := range change.Items {
		p := &sdk.SubscriptionUpdateItemParams{}
		if item.ID != "" {
			p.ID = sdk.String(item.ID)
		}
		if item.Price != "" {
			p.Price = sdk.String(item.Price)
		}
		if item.Quantity != nil {
			p.Quantity = sdk.Int64(*item.Quantity)
		}
		if item.Deleted {
			p.Deleted = sdk.Bool(true)
		}
		params.Items = append(params.Items, p)
	}
	params.SetIdempotencyKey("plainauth-plan-change-" + change.ID)
	send, cancel := context.WithDeadline(ctx, time.Unix(change.Started, 0).Add(planChangeSend))
	_, err = s.client.V1Subscriptions.Update(send, sub.ID, params)
	cancel()
	if err != nil {
		// Stripe refused the update, so nothing changed and another target
		// may proceed at once. Any other failure may have applied it: the
		// reservation keeps the key for a retry.
		var api *sdk.Error
		if errors.As(err, &api) && (api.HTTPStatusCode == 400 || api.HTTPStatusCode == 402 || api.HTTPStatusCode == 404) {
			if _, err := store.ReleaseStripePlanChange(ctx, token, change, time.Now().UTC()); err != nil {
				return nil, err
			}
			return nil, providerManagementError(err)
		}
		return nil, billingError(502, "STRIPE_SUBSCRIPTION_UNAVAILABLE", "Could not contact the billing provider")
	}
	current, err := s.currentManaged(c, selection, local)
	if err != nil {
		return nil, err
	}
	if after, ok := s.currentBasket(current, selection.organization); !ok || after.plan != (subscriptionPrice{to.Name, t.Interval}) {
		return nil, ErrCheckoutReconcile
	}
	if _, err := store.ReleaseStripePlanChange(ctx, token, change, time.Now().UTC()); err != nil {
		return nil, err
	}
	disable, _ := c.Body["disableRedirect"].(bool)
	return map[string]any{"url": returnURL, "redirect": !disable}, nil
}
