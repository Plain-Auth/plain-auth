package stripe

import (
	"context"
	"errors"
	"net/http"

	auth "github.com/Stonewrit/stonewrit-auth"
	sdk "github.com/stripe/stripe-go/v87"
)

// CustomerStore resolves a billing customer using the authenticated local user.
type CustomerStore interface {
	StripeCustomer(context.Context, string) (string, error)
}

type PortalOptions struct {
	Client    *sdk.Client
	Customers CustomerStore
}

func portalEndpoint(opts PortalOptions) auth.Endpoint {
	return auth.Endpoint{Method: http.MethodPost, Path: "/subscription/billing-portal", Handler: func(c auth.EndpointContext) (any, error) {
		ctx := c.Request.Context()
		session, err := billingOwner(c, portalFields)
		if err != nil {
			return nil, err
		}
		raw, _ := c.Body["returnUrl"].(string)
		callback, err := c.Auth.CallbackURL(raw)
		if err != nil {
			return nil, err
		}
		if opts.Client == nil || opts.Customers == nil {
			return nil, errors.New("stripe: billing portal requires a client and customer store")
		}
		customer, err := opts.Customers.StripeCustomer(ctx, session.User.ID)
		if errors.Is(err, auth.ErrNotFound) || (err == nil && customer == "") {
			return nil, billingError(404, "CUSTOMER_NOT_FOUND", "Stripe customer not found for this user")
		}
		if err != nil {
			return nil, err
		}
		params := &sdk.BillingPortalSessionCreateParams{Customer: sdk.String(customer), ReturnURL: sdk.String(callback)}
		if locale, ok := c.Body["locale"].(string); ok {
			params.Locale = sdk.String(locale)
		}
		res, err := opts.Client.V1BillingPortalSessions.Create(ctx, params)
		if err != nil {
			return nil, billingError(500, "UNABLE_TO_CREATE_BILLING_PORTAL", "Unable to create billing portal session")
		}
		disable, _ := c.Body["disableRedirect"].(bool)
		return map[string]any{"url": res.URL, "redirect": !disable}, nil
	}}
}
