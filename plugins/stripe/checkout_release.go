package stripe

import (
	"context"
	"errors"
	"net/http"

	auth "github.com/Plain-Org/plain-auth"
	sdk "github.com/stripe/stripe-go/v87"
)

// CheckoutReleaseStore discards a reservation whose Checkout Session Stripe
// refused to create, with its never-sent local subscription row. It runs
// with an ID-only scope and no session token, so it calls no host code. A
// missing or different reservation is ignored; one with a known Checkout
// Session or another local row answers ErrCheckoutReconcile.
type CheckoutReleaseStore interface {
	ReleaseStripeCheckout(ctx context.Context, attempt CheckoutAttempt) error
}

// refusedByStripe reports a definitive refusal: Stripe answered 400, 401,
// 403 or 404 other than an idempotency conflict, so the same request would
// be refused again. Network failures, conflicts, rate limits and server
// errors keep the reservation for a retry.
func refusedByStripe(err error) bool {
	var api *sdk.Error
	if !errors.As(err, &api) || api.Type == sdk.ErrorTypeIdempotency {
		return false
	}
	switch api.HTTPStatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	}
	return false
}

// releaseContext scopes a release to the purchase's organization by ID
// alone, so the store asks no policy and needs no session.
func releaseContext(ctx context.Context, a CheckoutAttempt) context.Context {
	if a.OrganizationID == "" {
		return ctx
	}
	return context.WithValue(ctx, organizationScopeKey{}, OrganizationScope{ID: a.OrganizationID})
}

// logStripeError logs a Stripe failure with its status, type, code,
// parameter and request ID, which locate it in Stripe's dashboard, but not
// Stripe's message.
func logStripeError(c auth.EndpointContext, message string, err error) {
	var api *sdk.Error
	if !errors.As(err, &api) {
		c.Auth.Logger().ErrorContext(c.Request.Context(), message, "error", err)
		return
	}
	c.Auth.Logger().ErrorContext(c.Request.Context(), message, "status", api.HTTPStatusCode, "type", string(api.Type), "code", string(api.Code), "param", api.Param, "request", api.RequestID)
}
