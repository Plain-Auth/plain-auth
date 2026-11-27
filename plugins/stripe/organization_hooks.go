package stripe

import (
	"context"
	"errors"
	"log/slog"

	"github.com/Plain-Org/plain-auth/plugins/organization"
	sdk "github.com/stripe/stripe-go/v87"
)

// ErrOrganizationHasActiveSubscription refuses deleting an organization
// whose Stripe customer still has a subscription that bills.
var ErrOrganizationHasActiveSubscription = billingError(400, "ORGANIZATION_HAS_ACTIVE_SUBSCRIPTION", "Cannot delete organization with active subscription")

// OrganizationBilling is an organization's stored Stripe state.
type OrganizationBilling struct {
	// Customer is the organization's stripeCustomerId; empty when it has none.
	Customer string
	// PendingCheckout reports a purchase that is reserved and not settled.
	PendingCheckout bool
}

// OrganizationBillingReader reads an organization's stored Stripe state.
type OrganizationBillingReader interface {
	StripeOrganizationBilling(ctx context.Context, organizationID string) (OrganizationBilling, error)
}

// OrganizationHooks keeps an organization's Stripe customer in step with the
// organization plugin, as another runtime does by wrapping that plugin's
// hooks. Assign its methods to organization.Options, after your own hooks.
type OrganizationHooks struct {
	Client *sdk.Client
	Store  OrganizationBillingReader
	// Logger receives the hooks' log lines; nil uses slog.Default(). Pass
	// the logger set in plainauth.Options.Logger.
	Logger *slog.Logger
}

var errOrganizationHooks = errors.New("stripe: organization hooks need a client and a store")

func (h OrganizationHooks) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// AfterUpdateOrganization renames the organization's Stripe customer when
// its name changed. A failure is logged and never fails the update, as in
// another runtime.
func (h OrganizationHooks) AfterUpdateOrganization(ctx context.Context, u organization.AfterProfileUpdate) error {
	if h.Client == nil || h.Store == nil {
		return errOrganizationHooks
	}
	if u.Organization == nil {
		return nil
	}
	log, id := h.logger(), u.Organization.ID
	state, err := h.Store.StripeOrganizationBilling(ctx, id)
	if err != nil {
		log.ErrorContext(ctx, "Stripe organization customer lookup failed", "organization_id", id)
		return nil
	}
	if state.Customer == "" {
		return nil
	}
	customer, err := h.Client.V1Customers.Retrieve(ctx, state.Customer, nil)
	switch {
	case err != nil:
		log.ErrorContext(ctx, "Failed to sync organization to Stripe", append([]any{"organization_id", id, "customer_id", state.Customer}, stripeErrorAttrs(err)...)...)
	case customer.Deleted:
		log.WarnContext(ctx, "Stripe customer was deleted", "organization_id", id, "customer_id", state.Customer)
	case customer.Name != u.Organization.Name:
		if _, err := h.Client.V1Customers.Update(ctx, state.Customer, &sdk.CustomerUpdateParams{Name: sdk.String(u.Organization.Name)}); err != nil {
			log.ErrorContext(ctx, "Failed to sync organization to Stripe", append([]any{"organization_id", id, "customer_id", state.Customer}, stripeErrorAttrs(err)...)...)
			return nil
		}
		log.InfoContext(ctx, "Synced organization name to Stripe", "organization_id", id, "customer_id", state.Customer)
	}
	return nil
}

// BeforeDeleteOrganization refuses deleting an organization while Stripe
// reports a subscription of its customer other than canceled, incomplete or
// incomplete_expired, across every page, as another runtime does. It also
// refuses while a purchase is pending, which could otherwise complete for a
// deleted organization. A failed lookup is logged and refuses the deletion.
func (h OrganizationHooks) BeforeDeleteOrganization(ctx context.Context, d organization.OrganizationDeletion) error {
	if h.Client == nil || h.Store == nil {
		return errOrganizationHooks
	}
	log, id := h.logger(), d.Organization.ID
	state, err := h.Store.StripeOrganizationBilling(ctx, id)
	if err != nil {
		log.ErrorContext(ctx, "Failed to check organization subscriptions", "organization_id", id)
		return err
	}
	if state.PendingCheckout {
		return ErrOrganizationHasActiveSubscription
	}
	if state.Customer == "" {
		return nil
	}
	params := &sdk.SubscriptionListParams{Customer: sdk.String(state.Customer), Status: sdk.String("all"), ListParams: sdk.ListParams{Limit: sdk.Int64(100)}}
	for sub, err := range h.Client.V1Subscriptions.List(ctx, params).All(ctx) {
		if err != nil {
			log.ErrorContext(ctx, "Failed to check organization subscriptions", append([]any{"organization_id", id, "customer_id", state.Customer}, stripeErrorAttrs(err)...)...)
			return err
		}
		switch sub.Status {
		case sdk.SubscriptionStatusCanceled, sdk.SubscriptionStatusIncomplete, sdk.SubscriptionStatusIncompleteExpired:
		default:
			return ErrOrganizationHasActiveSubscription
		}
	}
	return nil
}
