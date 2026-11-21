package stripe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	sdk "github.com/stripe/stripe-go/v87"
)

// Plan supplies Stripe recurring price IDs. A checkout always uses one seat.
type Plan struct{ Name, PriceID, AnnualPriceID string }
type SubscriptionOptions struct {
	Client *sdk.Client
	Plans  []Plan
}

type Subscription struct {
	ID                string     `json:"id"`
	Plan              string     `json:"plan"`
	ReferenceID       string     `json:"referenceId"`
	CustomerID        *string    `json:"stripeCustomerId,omitempty"`
	SubscriptionID    *string    `json:"stripeSubscriptionId,omitempty"`
	Status            string     `json:"status"`
	PeriodStart       *time.Time `json:"periodStart,omitempty"`
	PeriodEnd         *time.Time `json:"periodEnd,omitempty"`
	TrialStart        *time.Time `json:"trialStart,omitempty"`
	TrialEnd          *time.Time `json:"trialEnd,omitempty"`
	CancelAtPeriodEnd *bool      `json:"cancelAtPeriodEnd,omitempty"`
	CancelAt          *time.Time `json:"cancelAt,omitempty"`
	CanceledAt        *time.Time `json:"canceledAt,omitempty"`
	EndedAt           *time.Time `json:"endedAt,omitempty"`
	Seats             *int64     `json:"seats,omitempty"`
	Interval          *string    `json:"billingInterval,omitempty"`
	ScheduleID        *string    `json:"stripeScheduleId,omitempty"`
	PriceID           string     `json:"priceId,omitempty"`
}

// CheckoutAttempt is a durable reservation; the same attempt always sends
// identical Stripe parameters, including callbacks and expiry.
type CheckoutAttempt struct {
	ID, Owner, LocalSubscription, Customer, Plan, Interval, Price, SuccessURL, CancelURL, CheckoutID, CheckoutURL string
	Expires                                                                                                       int64
}

type SubscriptionStore interface {
	CheckSubscriptionSchema(context.Context) error
	ReserveStripeCheckout(ctx context.Context, userID, sessionToken string, requested CheckoutAttempt, now time.Time) (CheckoutAttempt, error)
	BindStripeCheckoutCustomer(ctx context.Context, attempt CheckoutAttempt, sessionToken, customer string, now time.Time) error
	SaveStripeCheckoutResult(ctx context.Context, attempt CheckoutAttempt, sessionToken, checkoutID, checkoutURL string, now time.Time) error
	FindStripeCheckout(ctx context.Context, owner, attemptID string) (CheckoutAttempt, error)
	ApplyStripeCheckout(ctx context.Context, attempt CheckoutAttempt, checkoutID, remoteID, status string, start, end, trialStart, trialEnd int64) error
	ListStripeSubscriptions(ctx context.Context, userID, sessionToken string, now time.Time) ([]Subscription, error)
}

func billingError(status int, code, message string) *auth.APIError {
	return &auth.APIError{Status: status, Code: code, Message: message}
}

var (
	ErrPendingCheckout      = billingError(409, "CHECKOUT_ALREADY_PENDING", "A different checkout is already pending")
	ErrExistingSubscription = billingError(409, "SUBSCRIPTION_ALREADY_EXISTS", "A subscription already exists")
	ErrCheckoutReconcile    = billingError(409, "CHECKOUT_RECONCILIATION_REQUIRED", "Waiting for checkout reconciliation")
	ErrCheckoutSession      = billingError(401, "UNAUTHORIZED", "A current session is required")
)

type subscriptions struct {
	client *sdk.Client
	plans  map[string]Plan
}

func configureSubscriptions(o *SubscriptionOptions) (*subscriptions, error) {
	if o == nil {
		return nil, nil
	}
	if o.Client == nil || len(o.Plans) == 0 {
		return nil, errors.New("stripe: subscriptions require a client and plans")
	}
	s := &subscriptions{client: o.Client, plans: map[string]Plan{}}
	for _, p := range o.Plans {
		p.Name = strings.ToLower(strings.TrimSpace(p.Name))
		if p.Name == "" || !strings.HasPrefix(p.PriceID, "price_") || len(p.PriceID) == 6 || (p.AnnualPriceID != "" && (!strings.HasPrefix(p.AnnualPriceID, "price_") || len(p.AnnualPriceID) == 6)) || s.plans[p.Name].Name != "" {
			return nil, errors.New("stripe: invalid or duplicate subscription plan")
		}
		s.plans[p.Name] = p
	}
	return s, nil
}
func billingOwner(c auth.EndpointContext, reference, kind string) (*auth.SessionResult, error) {
	ss, err := c.Auth.GetSession(c.Request.Context(), c.Request.Header)
	if err != nil {
		return nil, err
	}
	if ss == nil {
		return nil, ErrCheckoutSession
	}
	if err := ss.Session.RequireOwner(); err != nil {
		return nil, err
	}
	if (reference != "" && reference != ss.User.ID) || (kind != "" && kind != "user") {
		return nil, billingError(403, "UNAUTHORIZED", "This billing account is unavailable")
	}
	return ss, nil
}
func (s *subscriptions) list(c auth.EndpointContext) (any, error) {
	q := c.Request.URL.Query()
	ss, err := billingOwner(c, q.Get("referenceId"), q.Get("customerType"))
	if err != nil {
		return nil, err
	}
	rows, err := c.Store().(SubscriptionStore).ListStripeSubscriptions(c.Request.Context(), ss.User.ID, ss.Session.Token, time.Now())
	if err != nil {
		return nil, err
	}
	for i := range rows {
		p := s.plans[strings.ToLower(rows[i].Plan)]
		rows[i].PriceID = p.PriceID
		if rows[i].Interval != nil && *rows[i].Interval == "year" && p.AnnualPriceID != "" {
			rows[i].PriceID = p.AnnualPriceID
		}
	}
	return rows, nil
}
func (s *subscriptions) checkout(c auth.EndpointContext) (any, error) {
	// Request-controlled values can select a plan name, never a Stripe customer,
	// price, account or subscription metadata object.
	for key, value := range c.Body {
		switch key {
		case "plan", "successUrl", "cancelUrl", "referenceId", "customerType":
			if _, ok := value.(string); !ok {
				return nil, billingError(400, "VALIDATION_ERROR", "Invalid "+key)
			}
		case "annual", "disableRedirect":
			if _, ok := value.(bool); !ok {
				return nil, billingError(400, "VALIDATION_ERROR", "Invalid "+key)
			}
		default:
			return nil, billingError(400, "UNSUPPORTED_CHECKOUT_OPTION", "Unsupported checkout option")
		}
	}
	reference, _ := c.Body["referenceId"].(string)
	kind, _ := c.Body["customerType"].(string)
	ss, err := billingOwner(c, reference, kind)
	if err != nil {
		return nil, err
	}
	name, _ := c.Body["plan"].(string)
	p, ok := s.plans[strings.ToLower(name)]
	if !ok {
		return nil, billingError(400, "PLAN_NOT_FOUND", "Plan not found")
	}
	price, interval := p.PriceID, "month"
	if annual, _ := c.Body["annual"].(bool); annual {
		price, interval = p.AnnualPriceID, "year"
		if price == "" {
			return nil, billingError(400, "PLAN_NOT_FOUND", "Annual price is unavailable")
		}
	}
	success, _ := c.Body["successUrl"].(string)
	success, err = c.Auth.CallbackURL(success)
	if err != nil {
		return nil, err
	}
	cancel, _ := c.Body["cancelUrl"].(string)
	cancel, err = c.Auth.CallbackURL(cancel)
	if err != nil {
		return nil, err
	}
	ctx := c.Request.Context()
	store := c.Store().(SubscriptionStore)
	want := CheckoutAttempt{Owner: ss.User.ID, Plan: p.Name, Interval: interval, Price: price, SuccessURL: success, CancelURL: cancel}
	a, err := store.ReserveStripeCheckout(ctx, ss.User.ID, ss.Session.Token, want, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if a.Customer == "" {
		params := &sdk.CustomerCreateParams{Metadata: map[string]string{"userId": ss.User.ID, "customerType": "user"}}
		sum := sha256.Sum256([]byte("customer:" + ss.User.ID))
		params.SetIdempotencyKey("auth-customer-" + hex.EncodeToString(sum[:]))
		customer, err := s.client.V1Customers.Create(ctx, params)
		if err != nil || customer == nil || customer.ID == "" || customer.Metadata["userId"] != a.Owner || customer.Metadata["customerType"] != "user" {
			return nil, billingError(502, "CUSTOMER_CREATION_FAILED", "Stripe customer creation failed")
		}
		if err := store.BindStripeCheckoutCustomer(ctx, a, ss.Session.Token, customer.ID, time.Now()); err != nil {
			return nil, err
		}
		a.Customer = customer.ID
	}
	if a.CheckoutID == "" {
		meta := map[string]string{"userId": a.Owner, "referenceId": a.Owner, "subscriptionId": a.LocalSubscription, "checkoutAttemptId": a.ID}
		params := &sdk.CheckoutSessionCreateParams{
			Mode:              sdk.String("subscription"),
			Customer:          sdk.String(a.Customer),
			ClientReferenceID: sdk.String(a.Owner),
			SuccessURL:        sdk.String(a.SuccessURL),
			CancelURL:         sdk.String(a.CancelURL),
			ExpiresAt:         sdk.Int64(a.Expires),
			LineItems:         []*sdk.CheckoutSessionCreateLineItemParams{{Price: sdk.String(a.Price), Quantity: sdk.Int64(1)}},
			Metadata:          meta,
			SubscriptionData:  &sdk.CheckoutSessionCreateSubscriptionDataParams{Metadata: meta},
		}
		params.SetIdempotencyKey("auth-checkout-" + a.ID)
		checkout, err := s.client.V1CheckoutSessions.Create(ctx, params)
		if err != nil || checkout == nil || checkout.ID == "" || checkout.URL == "" {
			return nil, billingError(502, "CHECKOUT_CREATION_FAILED", "Stripe checkout creation failed")
		}
		if err := store.SaveStripeCheckoutResult(ctx, a, ss.Session.Token, checkout.ID, checkout.URL, time.Now()); err != nil {
			return nil, err
		}
		a.CheckoutID, a.CheckoutURL = checkout.ID, checkout.URL
	}
	disable, _ := c.Body["disableRedirect"].(bool)
	return map[string]any{"id": a.CheckoutID, "url": a.CheckoutURL, "redirect": !disable}, nil
}

func (s *subscriptions) handleCheckoutEvent(c auth.EndpointContext, event sdk.Event) error {
	if event.Type != "checkout.session.completed" && event.Type != "checkout.session.expired" {
		return nil
	}
	if event.Data == nil {
		return errors.New("stripe: missing event data")
	}
	var checkout sdk.CheckoutSession
	if err := json.Unmarshal(event.Data.Raw, &checkout); err != nil {
		return err
	}
	if checkout.Mode != "subscription" || checkout.Metadata["checkoutAttemptId"] == "" {
		return nil
	}
	ctx := c.Request.Context()
	store := c.Store().(SubscriptionStore)
	a, err := store.FindStripeCheckout(ctx, checkout.Metadata["userId"], checkout.Metadata["checkoutAttemptId"])
	if errors.Is(err, auth.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if checkout.ID == "" || checkout.Customer == nil || checkout.Customer.ID != a.Customer || checkout.ClientReferenceID != a.Owner || checkout.Metadata["referenceId"] != a.Owner || checkout.Metadata["subscriptionId"] != a.LocalSubscription || (a.CheckoutID != "" && a.CheckoutID != checkout.ID) {
		return errors.New("stripe: checkout ownership mismatch")
	}
	if event.Type == "checkout.session.expired" {
		return store.ApplyStripeCheckout(ctx, a, checkout.ID, "", "incomplete_expired", 0, 0, 0, 0)
	}
	if checkout.Subscription == nil || checkout.Subscription.ID == "" {
		return errors.New("stripe: checkout missing subscription")
	}
	sub, err := s.client.V1Subscriptions.Retrieve(ctx, checkout.Subscription.ID, &sdk.SubscriptionRetrieveParams{})
	if err != nil {
		return err
	}
	if sub == nil || sub.ID != checkout.Subscription.ID || sub.Customer == nil || sub.Customer.ID != a.Customer || sub.Metadata["subscriptionId"] != a.LocalSubscription || sub.Metadata["checkoutAttemptId"] != a.ID || sub.Metadata["referenceId"] != a.Owner || sub.Metadata["userId"] != a.Owner || sub.Items == nil || len(sub.Items.Data) != 1 {
		return errors.New("stripe: subscription ownership mismatch")
	}
	item := sub.Items.Data[0]
	if item == nil || item.Price == nil || item.Price.ID != a.Price || item.Quantity != 1 {
		return errors.New("stripe: subscription price mismatch")
	}
	return store.ApplyStripeCheckout(ctx, a, checkout.ID, sub.ID, string(sub.Status), item.CurrentPeriodStart, item.CurrentPeriodEnd, sub.TrialStart, sub.TrialEnd)
}
