package stripe

import (
	"context"
	"encoding/json"
	sdk "github.com/stripe/stripe-go/v87"
	"net/http"
	"strconv"
	"time"

	"github.com/Stonewrit/stonewrit-auth"
)

// ReferenceAuthorization contains the membership read under the database lock.
// Role can contain multiple comma-separated organization roles.
type ReferenceAuthorization struct {
	UserID, OrganizationID, SessionID, Role, Action string
}

type OrganizationOptions struct {
	// AuthorizeReference is called for every organization operation and before
	// committing its effects. Use a local, side-effect-free permission check.
	AuthorizeReference func(ReferenceAuthorization) bool
}

type OrganizationAccount struct{ Name, Customer string }

// OrganizationScope is attached by the plugin after selecting an organization.
// A verified webhook has no acting user or session.
type OrganizationScope struct {
	ID, Actor, Session, Action string
	Active                     bool
	Authorize                  func(ReferenceAuthorization) bool
}
type organizationScopeKey struct{}

func OrganizationFromContext(ctx context.Context) (OrganizationScope, bool) {
	v, ok := ctx.Value(organizationScopeKey{}).(OrganizationScope)
	return v, ok
}
func withOrganization(c stonewrit.EndpointContext, v OrganizationScope) stonewrit.EndpointContext {
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), organizationScopeKey{}, v))
	return c
}

type OrganizationBillingStore interface {
	CheckStripeOrganizationSchema(context.Context) error
	StripeOrganizationAccount(ctx context.Context, token string, now time.Time) (OrganizationAccount, error)
	StripeCustomerOrganization(ctx context.Context, customer string) (string, error)
}

var ErrOrganizationBillingAccess = billingError(401, "UNAUTHORIZED", "Unauthorized access")
var errOrganizationReference = billingError(400, "ORGANIZATION_REFERENCE_ID_REQUIRED", "Reference ID is required. Provide referenceId or set activeOrganizationId in session")

type billingSelection struct {
	session      *stonewrit.SessionResult
	reference    string
	organization bool
	account      OrganizationAccount
}

func selectBilling(c *stonewrit.EndpointContext, fields []billingField, action string, options *OrganizationOptions) (billingSelection, error) {
	user, err := billingSession(*c, fields, options != nil)
	if err != nil {
		return billingSelection{}, err
	}
	kind, _ := c.Body["customerType"].(string)
	id, _ := c.Body["referenceId"].(string)
	if c.Request.Method == http.MethodGet {
		kind = c.Request.URL.Query().Get("customerType")
		id = c.Request.URL.Query().Get("referenceId")
	}
	if kind != "organization" {
		return billingSelection{session: user, reference: user.User.ID}, nil
	}
	if options.AuthorizeReference == nil {
		return billingSelection{}, billingError(400, "AUTHORIZE_REFERENCE_REQUIRED", "Organization subscriptions require authorizeReference callback to be configured")
	}
	active := id == ""
	if active && user.Session.ActiveOrganizationID != nil {
		id = *user.Session.ActiveOrganizationID
	}
	if id == "" {
		return billingSelection{}, errOrganizationReference
	}
	scope := OrganizationScope{ID: id, Actor: user.User.ID, Session: user.Session.ID, Action: action, Active: active, Authorize: options.AuthorizeReference}
	*c = withOrganization(*c, scope)
	store, ok := c.Store().(OrganizationBillingStore)
	if !ok {
		return billingSelection{}, ErrOrganizationBillingAccess
	}
	account, err := store.StripeOrganizationAccount(c.Request.Context(), user.Session.Token, time.Now())
	return billingSelection{session: user, reference: id, organization: true, account: account}, err
}

func (s *subscriptions) organizationEvent(c stonewrit.EndpointContext, event sdk.Event) (stonewrit.EndpointContext, error) {
	switch event.Type {
	case sdk.EventTypeCheckoutSessionCompleted, sdk.EventTypeCheckoutSessionExpired, sdk.EventTypeCustomerSubscriptionCreated, sdk.EventTypeCustomerSubscriptionUpdated, sdk.EventTypeCustomerSubscriptionDeleted:
	default:
		return c, nil
	}
	if event.Data == nil {
		return c, nil
	}
	var object struct {
		Customer *sdk.Customer `json:"customer"`
	}
	if err := json.Unmarshal(event.Data.Raw, &object); err != nil {
		return c, err
	}
	if object.Customer == nil {
		return c, nil
	}
	id, err := c.Store().(OrganizationBillingStore).StripeCustomerOrganization(c.Request.Context(), object.Customer.ID)
	if err != nil || id == "" {
		return c, err
	}
	return withOrganization(c, OrganizationScope{ID: id}), nil
}

func (s *subscriptions) findOrganizationCustomer(ctx context.Context, id string) (*sdk.Customer, error) {
	var found *sdk.Customer
	collect := func(rows sdk.Seq2[*sdk.Customer, error]) error {
		for customer, err := range rows {
			if err != nil {
				return err
			}
			if customer == nil || customer.Deleted || customer.ID == "" || customer.Metadata["organizationId"] != id || customer.Metadata["customerType"] != "organization" {
				continue
			}
			if found != nil && found.ID != customer.ID {
				return ErrCheckoutReconcile
			}
			found = customer
		}
		return nil
	}
	query := `metadata["organizationId"]:` + strconv.Quote(id) + ` AND metadata["customerType"]:"organization"`
	err := collect(s.client.V1Customers.Search(ctx, &sdk.CustomerSearchParams{SearchParams: sdk.SearchParams{Query: query, Limit: sdk.Int64(2)}}).All(ctx))
	if err != nil && err != ErrCheckoutReconcile && ctx.Err() == nil {
		found = nil
		err = collect(s.client.V1Customers.List(ctx, &sdk.CustomerListParams{ListParams: sdk.ListParams{Limit: sdk.Int64(100)}}).All(ctx))
	}
	if err != nil && err != ErrCheckoutReconcile {
		return nil, billingError(502, "CUSTOMER_LOOKUP_FAILED", "Stripe customer lookup failed")
	}
	return found, err
}
