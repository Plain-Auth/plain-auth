package stripe

import (
	"context"
	"errors"
	"net/http"
	"time"

	auth "github.com/Plain-Org/plain-auth"
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

func portalEndpoint(opts PortalOptions, organization *OrganizationOptions) auth.Endpoint {
	return auth.Endpoint{Method: http.MethodPost, Path: "/subscription/billing-portal", Handler: func(c auth.EndpointContext) (any, error) {
		selection, err := selectBilling(&c, portalFields, "billing-portal", organization)
		ctx := c.Request.Context()
		if err != nil {
			return nil, err
		}
		raw, _ := c.Body["returnUrl"].(string)
		callback, err := c.Auth.CallbackURL(raw)
		if err != nil {
			return nil, err
		}
		if opts.Client == nil || (!selection.organization && opts.Customers == nil) {
			return nil, errors.New("stripe: billing portal requires a client and customer store")
		}
		customer := selection.account.Customer
		if !selection.organization {
			customer, err = opts.Customers.StripeCustomer(ctx, selection.reference)
		}
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
		if selection.organization {
			account, err := c.Store().(OrganizationBillingStore).StripeOrganizationAccount(ctx, selection.session.Session.Token, time.Now())
			if err != nil {
				return nil, err
			}
			if account.Customer != customer || res == nil || res.Customer != customer || res.URL == "" {
				return nil, ErrCheckoutReconcile
			}
		}
		disable, _ := c.Body["disableRedirect"].(bool)
		return map[string]any{"url": res.URL, "redirect": !disable}, nil
	}}
}
