package stripe

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	sdk "github.com/stripe/stripe-go/v87"
)

const sessionIDTemplate = "{CHECKOUT_SESSION_ID}"

// CheckoutReturn is an authenticated owner's pending checkout or recent settled receipt.
type CheckoutReturn struct {
	Attempt             CheckoutAttempt
	BoundSubscriptionID string
	Settled             bool
}

// CheckoutReceipt is the state read from the provider subscription for this checkout.
type CheckoutReceipt struct {
	RemoteID, Status                             string
	PeriodStart, PeriodEnd, TrialStart, TrialEnd int64
}

// CheckoutReturnStore enables browser confirmation of a hosted Checkout Session.
// Both methods must check an active owner session, the stored checkout and its customer.
type CheckoutReturnStore interface {
	FindStripeCheckoutReturn(ctx context.Context, owner, sessionToken, checkoutID string, now time.Time) (CheckoutReturn, error)
	ApplyStripeCheckoutReturn(ctx context.Context, a CheckoutAttempt, sessionToken, checkoutID string, receipt CheckoutReceipt, now time.Time) error
}

func hostedReturnURL(a *auth.Auth, callback string) (string, error) {
	target, err := a.CallbackURL(strings.TrimRight(a.BasePath(), "/") + "/subscription/success")
	if err != nil {
		return "", err
	}
	return target + "?callbackURL=" + url.QueryEscape(callback) + "&checkoutSessionId=" + sessionIDTemplate, nil
}

func validCheckoutID(id string) bool {
	if !strings.HasPrefix(id, "cs_") || len(id) < 4 || len(id) > 255 {
		return false
	}
	for _, ch := range id[3:] {
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_') {
			return false
		}
	}
	return true
}

func (s *subscriptions) checkoutSuccess(c auth.EndpointContext) (any, error) {
	q, err := url.ParseQuery(c.Request.URL.RawQuery)
	if err != nil || len(q["callbackURL"]) > 1 || len(q["checkoutSessionId"]) > 1 || len(q["organizationId"]) > 1 {
		return nil, billingError(400, "VALIDATION_ERROR", "Invalid checkout return query")
	}
	callback, err := c.Auth.CallbackURL(q.Get("callbackURL"))
	if err != nil {
		return nil, err
	}
	id := q.Get("checkoutSessionId")
	if id == "" {
		return c.Redirect(callback)
	}
	if !validCheckoutID(id) {
		return nil, billingError(400, "VALIDATION_ERROR", "Invalid checkout session ID")
	}
	filled, err := c.Auth.CallbackURL(strings.ReplaceAll(callback, sessionIDTemplate, id))
	if err != nil {
		return nil, err
	}

	ctx := c.Request.Context()
	session, err := c.Auth.GetSession(ctx, c.Request.Header)
	if err != nil {
		return nil, err
	}
	if session == nil || (session.User.IsAnonymous != nil && *session.User.IsAnonymous) {
		return c.Redirect(callback)
	}
	if err := session.Session.RequireOwner(); err != nil {
		return nil, err
	}
	store, ok := c.Store().(CheckoutReturnStore)
	if !ok {
		return nil, billingError(400, "CHECKOUT_RETURN_UNAVAILABLE", "Checkout return confirmation is unavailable")
	}
	reference := session.User.ID
	if id := q.Get("organizationId"); id != "" {
		if s.organization == nil || s.organization.AuthorizeReference == nil {
			return nil, ErrOrganizationBillingAccess
		}
		c = withOrganization(c, OrganizationScope{ID: id, Actor: session.User.ID, Session: session.Session.ID, Action: "upgrade-subscription", Authorize: s.organization.AuthorizeReference})
		ctx = c.Request.Context()
		reference = id
	}
	returned, err := store.FindStripeCheckoutReturn(ctx, reference, session.Session.Token, id, time.Now())
	if errors.Is(err, auth.ErrNotFound) {
		return nil, billingError(404, "CHECKOUT_SESSION_NOT_FOUND", "Checkout session not found")
	}
	if err != nil {
		return nil, err
	}
	a := returned.Attempt
	if (q.Get("callbackURL") != "" && callback != a.SuccessURL) || a.CheckoutID != id || a.Owner != reference {
		return nil, billingError(403, "INVALID_CHECKOUT_RETURN", "Invalid checkout return")
	}
	if returned.Settled {
		return c.Redirect(filled)
	}
	params := &sdk.CheckoutSessionRetrieveParams{}
	if a.Seats > 0 {
		params.AddExpand("line_items")
	}
	checkout, err := s.client.V1CheckoutSessions.Retrieve(ctx, id, params)
	if err != nil {
		return c.Redirect(filled)
	}
	if checkout == nil || checkout.Mode != sdk.CheckoutSessionModeSubscription || !checkoutMatches(a, checkout) {
		return nil, billingError(403, "INVALID_CHECKOUT_RETURN", "Invalid checkout return")
	}
	if checkout.Status != sdk.CheckoutSessionStatusComplete || (checkout.PaymentStatus != sdk.CheckoutSessionPaymentStatusPaid && checkout.PaymentStatus != sdk.CheckoutSessionPaymentStatusNoPaymentRequired) || checkout.Subscription == nil || checkout.Subscription.ID == "" {
		return c.Redirect(filled)
	}
	receipt := CheckoutReceipt{RemoteID: checkout.Subscription.ID}
	if returned.BoundSubscriptionID == "" {
		receipt, err = s.checkoutReceipt(c, a, checkout, session.Session.Token)
		if err != nil {
			if errors.Is(err, ErrCheckoutReconcile) {
				return nil, billingError(403, "INVALID_CHECKOUT_RETURN", "Invalid checkout return")
			}
			var authError *auth.APIError
			if errors.As(err, &authError) {
				return nil, err
			}
			return c.Redirect(filled)
		}
	} else if returned.BoundSubscriptionID != receipt.RemoteID {
		return nil, billingError(403, "INVALID_CHECKOUT_RETURN", "Invalid checkout return")
	}
	if err := store.ApplyStripeCheckoutReturn(ctx, a, session.Session.Token, id, receipt, time.Now()); err != nil {
		return nil, err
	}
	return c.Redirect(filled)
}

func checkoutMatches(a CheckoutAttempt, c *sdk.CheckoutSession) bool {
	return c.Object == "checkout.session" && c.ID != "" && c.Customer != nil && c.Customer.ID == a.Customer && c.ClientReferenceID == a.Owner &&
		checkoutMetadataMatches(a, c.Metadata) && (a.CheckoutID == "" || a.CheckoutID == c.ID)
}

func checkoutMetadataMatches(a CheckoutAttempt, meta map[string]string) bool {
	if a.OrganizationID != "" && (meta["customerType"] != "organization" || meta["organizationId"] != a.OrganizationID) {
		return false
	}
	if a.OrganizationID == "" && (meta["organizationId"] != "" || meta["customerType"] != "" && meta["customerType"] != "user") {
		return false
	}
	return meta["userId"] == a.creator() && meta["referenceId"] == a.Owner && meta["subscriptionId"] == a.LocalSubscription && meta["checkoutAttemptId"] == a.ID
}

func (s *subscriptions) checkoutReceipt(c auth.EndpointContext, a CheckoutAttempt, checkout *sdk.CheckoutSession, token string) (CheckoutReceipt, error) {
	ctx := c.Request.Context()
	remote, live := checkout.Subscription.ID, checkout.Livemode
	lifecycle, supportsLifecycle := c.Store().(SubscriptionLifecycleStore)
	if (a.Metered || len(a.MeteredPriceIDs) > 0) && !supportsLifecycle {
		return CheckoutReceipt{}, ErrCheckoutReconcile
	}
	if supportsLifecycle && a.Seats > 0 {
		purchase, err := s.checkoutPurchase(ctx, a, checkout.ID, remote, live, checkout)
		if err != nil {
			return CheckoutReceipt{}, err
		}
		key := SubscriptionIdentity{RemoteID: remote, CustomerID: a.Customer, SessionToken: token, Purchase: purchase}
		current, err := s.reconcile(ctx, lifecycle, key, nil, false)
		if errors.Is(err, errCheckoutAlreadyBound) {
			return CheckoutReceipt{RemoteID: remote}, nil
		}
		if err != nil {
			return CheckoutReceipt{}, err
		}
		if current == nil {
			return CheckoutReceipt{}, ErrCheckoutReconcile
		}
		return CheckoutReceipt{RemoteID: remote, Status: string(current.Status)}, nil
	}
	sub, err := s.client.V1Subscriptions.Retrieve(ctx, remote, nil)
	if err != nil {
		return CheckoutReceipt{}, err
	}
	if sub == nil || sub.Object != "subscription" || sub.ID != remote || sub.Livemode != live || sub.Customer == nil || sub.Customer.ID != a.Customer || sub.Status == "" || !checkoutMetadataMatches(a, sub.Metadata) || sub.Items == nil || len(sub.Items.Data) != 1 || sub.Items.HasMore {
		return CheckoutReceipt{}, ErrCheckoutReconcile
	}
	item := sub.Items.Data[0]
	if item == nil || item.Price == nil || item.Price.ID != a.Price || item.Quantity != a.Quantity() || a.Quantity() > 1 && !s.licensedPrice(item.Price) {
		return CheckoutReceipt{}, ErrCheckoutReconcile
	}
	return CheckoutReceipt{RemoteID: sub.ID, Status: string(sub.Status), PeriodStart: item.CurrentPeriodStart, PeriodEnd: item.CurrentPeriodEnd, TrialStart: sub.TrialStart, TrialEnd: sub.TrialEnd}, nil
}

func (s *subscriptions) successEndpoint() auth.Endpoint {
	return auth.Endpoint{Method: http.MethodGet, Path: "/subscription/success", Handler: s.checkoutSuccess}
}
