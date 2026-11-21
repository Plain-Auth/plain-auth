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
	// RequireEmailVerification restricts starting Checkout to a verified owner.
	RequireEmailVerification bool
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
	// ReturnURL holds the provider success URL issued for this reservation.
	// Older reservations use their stored SuccessURL directly.
	ReturnURL                                                                                                     string
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
	ErrCheckoutSession      = billingError(401, "UNAUTHORIZED", "Unauthorized")
)

type subscriptionPrice struct{ plan, interval string }

type subscriptions struct {
	prices                   map[string]subscriptionPrice
	client                   *sdk.Client
	plans                    map[string]Plan
	requireEmailVerification bool
}

func configureSubscriptions(o *SubscriptionOptions) (*subscriptions, error) {
	if o == nil {
		return nil, nil
	}
	if o.Client == nil || len(o.Plans) == 0 {
		return nil, errors.New("stripe: subscriptions require a client and plans")
	}
	s := &subscriptions{client: o.Client, plans: map[string]Plan{}, requireEmailVerification: o.RequireEmailVerification}
	s.prices = make(map[string]subscriptionPrice)
	for _, p := range o.Plans {
		p.Name = strings.ToLower(strings.TrimSpace(p.Name))
		if p.Name == "" || !strings.HasPrefix(p.PriceID, "price_") || len(p.PriceID) == 6 || (p.AnnualPriceID != "" && (!strings.HasPrefix(p.AnnualPriceID, "price_") || len(p.AnnualPriceID) == 6)) || s.plans[p.Name].Name != "" {
			return nil, errors.New("stripe: invalid or duplicate subscription plan")
		}
		s.plans[p.Name] = p
		for interval, price := range map[string]string{"month": p.PriceID, "year": p.AnnualPriceID} {
			if price == "" {
				continue
			}
			if _, exists := s.prices[price]; exists {
				return nil, errors.New("stripe: a recurring price must identify a single subscription plan and interval")
			}
			s.prices[price] = subscriptionPrice{p.Name, interval}
		}
	}
	return s, nil
}
func (s *subscriptions) list(c auth.EndpointContext) (any, error) {
	ss, err := billingOwner(c, listFields)
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
	ss, err := billingOwner(c, checkoutFields)
	if err != nil {
		return nil, err
	}
	for key := range c.Body {
		switch key {
		case "plan", "successUrl", "cancelUrl", "returnUrl", "referenceId", "subscriptionId", "customerType", "annual", "disableRedirect", "scheduleAtPeriodEnd":
		default:
			return nil, billingError(400, "UNSUPPORTED_CHECKOUT_OPTION", "Unsupported checkout option")
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
	rawReturn, _ := c.Body["returnUrl"].(string)
	returnURL, err := c.Auth.CallbackURL(rawReturn)
	if err != nil {
		return nil, err
	}
	name, _ := c.Body["plan"].(string)
	if s.requireEmailVerification && !ss.User.EmailVerified {
		return nil, billingError(400, "EMAIL_VERIFICATION_REQUIRED", "Email verification is required before you can subscribe to a plan")
	}
	p, ok := s.plans[strings.ToLower(name)]
	if !ok {
		return nil, billingError(400, "SUBSCRIPTION_PLAN_NOT_FOUND", "Subscription plan not found")
	}
	explicit, _ := c.Body["subscriptionId"].(string)
	var selected Subscription
	if explicit != "" {
		selected, err = managedSubscription(c, ss)
		if err != nil {
			return nil, err
		}
	}
	price, interval := p.PriceID, "month"
	if annual, _ := c.Body["annual"].(bool); annual {
		price, interval = p.AnnualPriceID, "year"
		if price == "" {
			return nil, billingError(400, "", "Price ID not found for the selected plan")
		}
	}
	if explicit != "" {
		return s.changePlan(c, ss, selected, price, returnURL)
	}
	ctx := c.Request.Context()
	store := c.Store().(SubscriptionStore)
	want := CheckoutAttempt{Owner: ss.User.ID, Plan: p.Name, Interval: interval, Price: price, SuccessURL: success, CancelURL: cancel}
	if _, ok := store.(CheckoutReturnStore); ok {
		want.ReturnURL, err = hostedReturnURL(c.Auth, success)
		if err != nil {
			return nil, err
		}
	}
	a, err := store.ReserveStripeCheckout(ctx, ss.User.ID, ss.Session.Token, want, time.Now().UTC())
	if errors.Is(err, ErrExistingSubscription) {
		// With multiple subscriptions the customer must name the one to change.
		rows, err := store.ListStripeSubscriptions(ctx, ss.User.ID, ss.Session.Token, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		if len(rows) != 1 || rows[0].SubscriptionID == nil {
			return nil, ErrExistingSubscription
		}
		return s.changePlan(c, ss, rows[0], price, returnURL)
	}
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
		providerSuccess := a.SuccessURL
		if a.ReturnURL != "" {
			providerSuccess = a.ReturnURL
		}
		params := &sdk.CheckoutSessionCreateParams{
			Mode:              sdk.String("subscription"),
			Customer:          sdk.String(a.Customer),
			ClientReferenceID: sdk.String(a.Owner),
			SuccessURL:        sdk.String(providerSuccess),
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
	if !checkoutMatches(a, &checkout) {
		return errors.New("stripe: checkout ownership mismatch")
	}
	if event.Type == "checkout.session.expired" {
		return store.ApplyStripeCheckout(ctx, a, checkout.ID, "", "incomplete_expired", 0, 0, 0, 0)
	}
	if checkout.Subscription == nil || checkout.Subscription.ID == "" {
		return errors.New("stripe: checkout missing subscription")
	}
	if lifecycle, ok := store.(SubscriptionLifecycleStore); ok {
		settled, err := lifecycle.SettleReconciledCheckout(ctx, a, checkout.ID, checkout.Subscription.ID)
		if err != nil || settled {
			return err
		}
	}
	receipt, err := s.checkoutReceipt(ctx, a, checkout.Subscription.ID, checkout.Livemode)
	if err != nil {
		return err
	}
	return store.ApplyStripeCheckout(ctx, a, checkout.ID, receipt.RemoteID, receipt.Status, receipt.PeriodStart, receipt.PeriodEnd, receipt.TrialStart, receipt.TrialEnd)
}
