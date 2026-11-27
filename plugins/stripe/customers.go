package stripe

import (
	"errors"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	sdk "github.com/stripe/stripe-go/v87"
)

// ErrCustomerInUse refuses binding a Stripe customer another account
// already holds; it answers as ErrCheckoutReconcile does.
var ErrCustomerInUse error = customerInUse{}

type customerInUse struct{}

func (customerInUse) Error() string { return ErrCheckoutReconcile.Error() }
func (customerInUse) Unwrap() error { return ErrCheckoutReconcile }

// checkoutCustomer links a Stripe customer to a new purchase and returns its
// ID. An organization's is found by its metadata or created under its name.
// A person with a verified email reuses the customer Stripe finds for that
// email when no other user owns it, as another runtime does; otherwise a
// customer is created with the user's email, name and metadata. A failure
// to find or create one answers ErrCustomerCreation.
func (s *subscriptions) checkoutCustomer(c auth.EndpointContext, selection billingSelection, store SubscriptionStore, a CheckoutAttempt, ss *auth.SessionResult) (string, error) {
	ctx := c.Request.Context()
	token := ss.Session.Token
	if selection.organization {
		customer, err := s.findOrganizationCustomer(ctx, a.OrganizationID)
		if errors.Is(err, ErrCheckoutReconcile) {
			return "", err
		}
		if err != nil {
			c.Auth.Logger().ErrorContext(ctx, "Stripe customer lookup failed", "error", err)
			return "", ErrCustomerCreation
		}
		if _, err = c.Store().(OrganizationBillingStore).StripeOrganizationAccount(ctx, token, time.Now()); err != nil {
			return "", err
		}
		if customer == nil {
			params := &sdk.CustomerCreateParams{Name: sdk.String(a.OrganizationName), Metadata: map[string]string{"organizationId": a.OrganizationID, "customerType": "organization"}}
			customer = s.createCustomer(c, params)
		}
		if customer == nil || customer.ID == "" || customer.Metadata["customerType"] != "organization" || customer.Metadata["organizationId"] != a.OrganizationID {
			return "", ErrCustomerCreation
		}
		return customer.ID, store.BindStripeCheckoutCustomer(ctx, a, token, customer.ID, time.Now())
	}
	// An unverified email is not looked up, so a lookup outage cannot block
	// the purchase, where another runtime looks it up and discards the match.
	if ss.User.EmailVerified {
		match, err := s.findUserCustomer(c, ss.User.Email)
		if err != nil {
			c.Auth.Logger().ErrorContext(ctx, "Stripe customer lookup failed", "error", err)
			return "", ErrCustomerCreation
		}
		if match != nil && (match.Metadata["userId"] == "" || match.Metadata["userId"] == ss.User.ID) {
			// A customer another account holds is not shared, since each
			// account binds its own customer: a new one is created.
			err := store.BindStripeCheckoutCustomer(ctx, a, token, match.ID, time.Now())
			if !errors.Is(err, ErrCustomerInUse) {
				return match.ID, err
			}
		}
	}
	params := &sdk.CustomerCreateParams{Email: sdk.String(ss.User.Email), Metadata: map[string]string{"userId": ss.User.ID, "customerType": "user"}}
	if ss.User.Name != "" {
		params.Name = sdk.String(ss.User.Name)
	}
	customer := s.createCustomer(c, params)
	if customer == nil || customer.ID == "" || customer.Metadata["customerType"] != "user" || customer.Metadata["userId"] != a.Owner {
		return "", ErrCustomerCreation
	}
	return customer.ID, store.BindStripeCheckoutCustomer(ctx, a, token, customer.ID, time.Now())
}

// createCustomer creates a Stripe customer, logging a failure and returning
// nil. It sends no idempotency key of its own, as another runtime sends
// none: Stripe replays a key's first answer, an error included, for a day,
// so a fixed key would refuse every retry after a failure. The search that
// precedes it finds a customer an earlier lost response created.
func (s *subscriptions) createCustomer(c auth.EndpointContext, params *sdk.CustomerCreateParams) *sdk.Customer {
	customer, err := s.client.V1Customers.Create(c.Request.Context(), params)
	if err != nil {
		c.Auth.Logger().ErrorContext(c.Request.Context(), "Stripe customer creation failed", "error", err)
		return nil
	}
	return customer
}

// findUserCustomer finds the first customer Stripe has for an email that is
// not an organization's, through search, or a list by email when search is
// unavailable, as another runtime does.
func (s *subscriptions) findUserCustomer(c auth.EndpointContext, email string) (*sdk.Customer, error) {
	ctx := c.Request.Context()
	query := `email:"` + stripeSearchValue(email) + `" AND -metadata["customerType"]:"organization"`
	var searchErr error
	for customer, err := range s.client.V1Customers.Search(ctx, &sdk.CustomerSearchParams{SearchParams: sdk.SearchParams{Query: query, Limit: sdk.Int64(1)}}).All(ctx) {
		if err != nil {
			searchErr = err
			break
		}
		return customer, nil
	}
	if searchErr == nil || ctx.Err() != nil {
		return nil, searchErr
	}
	c.Auth.Logger().WarnContext(ctx, "Stripe customers.search failed, falling back to customers.list", "error", searchErr)
	for customer, err := range s.client.V1Customers.List(ctx, &sdk.CustomerListParams{Email: sdk.String(email), ListParams: sdk.ListParams{Limit: sdk.Int64(100)}}).All(ctx) {
		if err != nil {
			return nil, err
		}
		if customer != nil && !customer.Deleted && customer.Metadata["customerType"] != "organization" {
			return customer, nil
		}
	}
	return nil, nil
}

// stripeSearchValue escapes a value for a double-quoted Stripe search
// string: backslashes before quotes.
func stripeSearchValue(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v)
}
