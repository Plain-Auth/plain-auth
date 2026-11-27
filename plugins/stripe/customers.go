package stripe

import (
	"context"
	"errors"
	"log/slog"
	"maps"
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

// CustomerBoundError refuses binding a customer to a purchase a concurrent
// identical request already bound to Customer; it answers as
// ErrCheckoutReconcile does.
type CustomerBoundError struct{ Customer string }

func (CustomerBoundError) Error() string { return ErrCheckoutReconcile.Error() }
func (CustomerBoundError) Unwrap() error { return ErrCheckoutReconcile }

// bindCustomer links a customer to the purchase. When a concurrent
// identical request bound another first, the purchase continues with that
// one. A customer this request created but could not bind, because another
// was bound first or the purchase was released or replaced meanwhile, is
// deleted.
func (s *subscriptions) bindCustomer(ctx context.Context, log *slog.Logger, store SubscriptionStore, a CheckoutAttempt, token, customer string, created bool) (string, error) {
	err := store.BindStripeCheckoutCustomer(ctx, a, token, customer, time.Now())
	if err == nil {
		return customer, nil
	}
	if created && errors.Is(err, ErrCheckoutReconcile) {
		s.deleteCustomer(ctx, log, customer)
	}
	var bound CustomerBoundError
	if errors.As(err, &bound) {
		return bound.Customer, nil
	}
	return customer, err
}

func (s *subscriptions) deleteCustomer(ctx context.Context, log *slog.Logger, customer string) {
	if _, err := s.client.V1Customers.Delete(ctx, customer, nil); err != nil {
		log.WarnContext(ctx, "Stripe customer from a concurrent purchase was not deleted", append([]any{"customer", customer}, stripeErrorAttrs(err)...)...)
	}
}

// checkoutCustomer links a Stripe customer to a new purchase and returns its
// ID. An organization's is found by its metadata or created under its
// current name. A person with a verified email reuses the customer Stripe
// finds for that email when no other user owns it, as another runtime does;
// otherwise a customer is created with the user's email, name and metadata.
// A failure to find or create one answers ErrCustomerCreation. The work runs
// on its own bounded context, so a client that disconnects cannot strand a
// customer Stripe created between its creation and its binding.
func (s *subscriptions) checkoutCustomer(c auth.EndpointContext, selection billingSelection, store SubscriptionStore, a CheckoutAttempt, ss *auth.SessionResult) (string, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), customerCallTimeout)
	defer cancel()
	log := c.Auth.Logger()
	token := ss.Session.Token
	if selection.organization {
		customer, err := s.findOrganizationCustomer(ctx, a.OrganizationID)
		if errors.Is(err, ErrCheckoutReconcile) {
			return "", err
		}
		if err != nil {
			log.ErrorContext(ctx, "Stripe customer lookup failed", stripeErrorAttrs(err)...)
			return "", ErrCustomerCreation
		}
		account, err := c.Store().(OrganizationBillingStore).StripeOrganizationAccount(ctx, token, time.Now())
		if err != nil {
			return "", err
		}
		// The current name, not the one the reservation recorded, names the
		// customer: a rename while it had no customer reached no customer.
		in := NewOrganizationCustomer{OrganizationID: a.OrganizationID, Name: account.Name, User: ss.User, Request: c.RequestMetadata()}
		created := customer == nil
		if created {
			if customer, err = s.createOrganizationCustomer(ctx, log, in); err != nil {
				return "", err
			}
		}
		if customer == nil || customer.ID == "" || customer.Metadata["customerType"] != "organization" || customer.Metadata["organizationId"] != a.OrganizationID {
			return "", ErrCustomerCreation
		}
		id, err := s.bindCustomer(ctx, log, store, a, token, customer.ID, created)
		if created && err != nil && !errors.Is(err, ErrCheckoutReconcile) {
			// The binding failed without saying whether it was stored.
			s.settleOrganizationCustomer(ctx, log, c.Store(), in, customer)
			return "", err
		}
		// Only the request that bound the customer it created reports it,
		// so a concurrent identical purchase never reports it twice.
		if err != nil || !created || id != customer.ID {
			return id, err
		}
		if !s.reportOrganizationCustomer(ctx, log, in, customer) {
			return "", ErrCustomerCreation
		}
		return id, nil
	}
	// An unverified email is not looked up, so a lookup outage cannot block
	// the purchase, where another runtime looks it up and discards the match.
	if ss.User.EmailVerified {
		match, err := findUserCustomer(ctx, s.client, log, ss.User.Email)
		if err != nil {
			log.ErrorContext(ctx, "Stripe customer lookup failed", stripeErrorAttrs(err)...)
			return "", ErrCustomerCreation
		}
		if match != nil && (match.Metadata["userId"] == "" || match.Metadata["userId"] == ss.User.ID) {
			// A customer another account holds is not shared, since each
			// account binds its own customer: a new one is created.
			id, err := s.bindCustomer(ctx, log, store, a, token, match.ID, false)
			if !errors.Is(err, ErrCustomerInUse) {
				return id, err
			}
		}
	}
	params := &sdk.CustomerCreateParams{Email: sdk.String(ss.User.Email), Metadata: map[string]string{"userId": ss.User.ID, "customerType": "user"}}
	if ss.User.Name != "" {
		params.Name = sdk.String(ss.User.Name)
	}
	customer := s.createCustomer(ctx, log, params)
	if customer == nil || customer.ID == "" || customer.Metadata["customerType"] != "user" || customer.Metadata["userId"] != a.Owner {
		return "", ErrCustomerCreation
	}
	return s.bindCustomer(ctx, log, store, a, token, customer.ID, true)
}

// reportOrganizationCustomer calls OnCustomerCreate for a customer this
// request created and stored, and reports whether it succeeded.
func (s *subscriptions) reportOrganizationCustomer(ctx context.Context, log *slog.Logger, in NewOrganizationCustomer, customer *sdk.Customer) bool {
	if s.organization == nil || s.organization.OnCustomerCreate == nil {
		return true
	}
	if err := s.organization.OnCustomerCreate(ctx, OrganizationCustomerCreated{NewOrganizationCustomer: in, Customer: customer}); err != nil {
		log.ErrorContext(ctx, "Stripe organization OnCustomerCreate failed", "organization_id", in.OrganizationID, "customer_id", customer.ID)
		return false
	}
	return true
}

// settleOrganizationCustomer reads which customer the organization holds
// after a binding failed without a verdict. The created customer is
// reported when it was stored after all, and deleted otherwise, so a later
// purchase cannot adopt it unreported. A failed read leaves it alone.
func (s *subscriptions) settleOrganizationCustomer(ctx context.Context, log *slog.Logger, store auth.Store, in NewOrganizationCustomer, customer *sdk.Customer) {
	reader, ok := store.(OrganizationBillingReader)
	if !ok {
		return
	}
	state, err := reader.StripeOrganizationBilling(ctx, in.OrganizationID)
	switch {
	case err != nil:
		log.ErrorContext(ctx, "Stripe organization customer not settled", "organization_id", in.OrganizationID, "customer_id", customer.ID)
	case state.Customer == customer.ID:
		s.reportOrganizationCustomer(ctx, log, in, customer)
	default:
		s.deleteCustomer(ctx, log, customer.ID)
	}
}

// createOrganizationCustomer creates an organization's customer under its
// name and metadata, over the host's CustomerCreateParams, as another
// runtime merges them. A failed or refused callback creates nothing.
func (s *subscriptions) createOrganizationCustomer(ctx context.Context, log *slog.Logger, in NewOrganizationCustomer) (*sdk.Customer, error) {
	params := &sdk.CustomerCreateParams{Name: sdk.String(in.Name), Metadata: map[string]string{"organizationId": in.OrganizationID, "customerType": "organization"}}
	if s.organization != nil && s.organization.CustomerCreateParams != nil {
		host, err := s.organization.CustomerCreateParams(ctx, in)
		if err == nil {
			params, err = mergeCustomerParams(params, host)
		}
		if err != nil {
			log.ErrorContext(ctx, "Stripe organization CustomerCreateParams failed", "organization_id", in.OrganizationID)
			return nil, ErrCustomerCreation
		}
	}
	return s.createCustomer(ctx, log, params), nil
}

// errCustomerOptions refuses host customer parameters with request
// options: a connected account's customer could not be used by this
// account's Checkout.
var errCustomerOptions = errors.New("stripe: customer parameters name request options")

// mergeCustomerParams lays the plugin's own customer fields over a host's
// parameters, as another runtime merges them: own's email and name, when
// set, and metadata keys win. The host's value is not changed.
func mergeCustomerParams(own, host *sdk.CustomerCreateParams) (*sdk.CustomerCreateParams, error) {
	if host == nil {
		return own, nil
	}
	if host.StripeAccount != nil || host.StripeContext != nil || host.Headers != nil || host.Extra != nil {
		return nil, errCustomerOptions
	}
	params := *host
	meta := maps.Clone(host.Params.Metadata)
	if meta == nil {
		meta = map[string]string{}
	}
	maps.Copy(meta, host.Metadata)
	maps.Copy(meta, own.Metadata)
	params.Params = sdk.Params{}
	params.UnsetFields = nil
	params.Metadata = meta
	if own.Email != nil {
		params.Email = own.Email
	}
	if own.Name != nil {
		params.Name = own.Name
	}
	return &params, nil
}

// createCustomer creates a Stripe customer, logging a failure and returning
// nil. It sends no idempotency key of its own, as another runtime sends
// none: Stripe replays a key's first answer, an error included, for a day,
// so a fixed key would refuse every retry after a failure. Concurrent
// identical requests settle on the first customer bound; a response lost
// after Stripe created a customer can leave it unbound, which a later
// search for a verified email finds once Stripe indexes it.
func (s *subscriptions) createCustomer(ctx context.Context, log *slog.Logger, params *sdk.CustomerCreateParams) *sdk.Customer {
	customer, err := s.client.V1Customers.Create(ctx, params)
	if err != nil {
		log.ErrorContext(ctx, "Stripe customer creation failed", stripeErrorAttrs(err)...)
		return nil
	}
	return customer
}

// findUserCustomer finds the first customer Stripe has for an email that is
// not an organization's, through search, or a list by email when search is
// unavailable, as another runtime does.
func findUserCustomer(ctx context.Context, client *sdk.Client, log *slog.Logger, email string) (*sdk.Customer, error) {
	query := `email:"` + stripeSearchValue(email) + `" AND -metadata["customerType"]:"organization"`
	var searchErr error
	for customer, err := range client.V1Customers.Search(ctx, &sdk.CustomerSearchParams{SearchParams: sdk.SearchParams{Query: query, Limit: sdk.Int64(1)}}).All(ctx) {
		if err != nil {
			searchErr = err
			break
		}
		return customer, nil
	}
	if searchErr == nil || ctx.Err() != nil {
		return nil, searchErr
	}
	log.WarnContext(ctx, "Stripe customers.search failed, falling back to customers.list", stripeErrorAttrs(searchErr)...)
	for customer, err := range client.V1Customers.List(ctx, &sdk.CustomerListParams{Email: sdk.String(email), ListParams: sdk.ListParams{Limit: sdk.Int64(100)}}).All(ctx) {
		if err != nil {
			return nil, err
		}
		if customer != nil && !customer.Deleted && customer.Metadata["customerType"] != "organization" {
			return customer, nil
		}
	}
	return nil, nil
}

// stripeErrorAttrs describes a failed Stripe call for a log line by its
// Stripe status, type, code and request ID, or by a timeout or transport
// failure. It leaves out error text, which can carry the request URL and,
// for a lookup, the email it searched for.
func stripeErrorAttrs(err error) []any {
	var api *sdk.Error
	switch {
	case errors.As(err, &api):
		return []any{"status", api.HTTPStatusCode, "type", string(api.Type), "code", string(api.Code), "param", api.Param, "request", api.RequestID}
	case errors.Is(err, context.DeadlineExceeded):
		return []any{"reason", "timeout"}
	case errors.Is(err, context.Canceled):
		return []any{"reason", "canceled"}
	case err == nil:
		// Stripe answered without the object asked for.
		return []any{"reason", "invalid_response"}
	}
	return []any{"reason", "transport"}
}

// stripeSearchValue escapes a value for a double-quoted Stripe search
// string: backslashes before quotes.
func stripeSearchValue(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v)
}
