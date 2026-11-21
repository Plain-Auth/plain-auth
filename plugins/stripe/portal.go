package stripe

import (
	"context"
	"errors"
	"net/http"

	auth "github.com/nabuhadba/go-better-auth"
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
		session, err := c.Auth.GetSession(ctx, c.Request.Header)
		if err != nil {
			return nil, err
		}
		if session == nil {
			return nil, &auth.APIError{Status: 401, Code: "UNAUTHORIZED", Message: "Unauthorized"}
		}
		for k := range c.Body {
			switch k {
			case "referenceId", "customerType", "returnUrl", "locale":
				if _, ok := c.Body[k].(string); !ok {
					return nil, &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "Expected a string for " + k}
				}
			case "disableRedirect":
				if _, ok := c.Body[k].(bool); !ok {
					return nil, &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "Expected a boolean for disableRedirect"}
				}
			}
		}
		reference, _ := c.Body["referenceId"].(string)
		kind, _ := c.Body["customerType"].(string)
		if (reference != "" && reference != session.User.ID) || (kind != "" && kind != "user") {
			return nil, &auth.APIError{Status: 403, Code: "UNAUTHORIZED", Message: "This billing account is unavailable"}
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
			return nil, &auth.APIError{Status: 404, Code: "CUSTOMER_NOT_FOUND", Message: "Customer not found"}
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
			return nil, &auth.APIError{Status: 500, Code: "UNABLE_TO_CREATE_BILLING_PORTAL", Message: "Unable to create billing portal"}
		}
		disable, _ := c.Body["disableRedirect"].(bool)
		return map[string]any{"url": res.URL, "redirect": !disable}, nil
	}}
}
