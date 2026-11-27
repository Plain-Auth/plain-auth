// Package stripe authenticates Stripe webhook deliveries and dispatches their events.
package stripe

import (
	"context"
	"errors"
	"io"
	"net/http"

	authn "github.com/Plain-Org/plain-auth"
	stripesdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

// Options configures delivery of authenticated events. Stripe may retry an
// event, so OnEvent can use its ID to make application side effects idempotent.
type Options struct {
	Organization  *OrganizationOptions
	Subscriptions *SubscriptionOptions
	Portal        *PortalOptions
	// UserCustomers creates users' Stripe customers at sign-up, with or
	// without Subscriptions.
	UserCustomers *UserCustomerOptions
	WebhookSecret string
	OnEvent       func(context.Context, stripesdk.Event) error
}

// New exposes POST /stripe/webhook beneath the configured auth base path.
func New(opts Options) authn.Plugin {
	subs, configErr := configureSubscriptions(opts.Subscriptions)
	if subs != nil {
		subs.organization = opts.Organization
	}
	plugin := authn.Plugin{ID: "stripe", Endpoints: []authn.Endpoint{{
		Method: http.MethodPost, Path: "/stripe/webhook", RawBody: true,
		Handler: func(ctx authn.EndpointContext) (any, error) {
			r := ctx.Request
			// The body is read under the request limit before the signature
			// is checked, so a large body answers 413 even when unsigned,
			// where another runtime checks the signature first.
			payload, err := io.ReadAll(r.Body)
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				return nil, &authn.APIError{Status: 413, Code: "PAYLOAD_TOO_LARGE", Message: "Request body too large"}
			}
			if err != nil || len(payload) == 0 {
				return nil, &authn.APIError{Status: 400, Code: "INVALID_REQUEST_BODY", Message: "Invalid request body"}
			}
			signature := r.Header.Get("Stripe-Signature")
			if signature == "" {
				return nil, &authn.APIError{Status: 400, Code: "STRIPE_SIGNATURE_NOT_FOUND", Message: "Stripe signature not found"}
			}
			if opts.WebhookSecret == "" {
				return nil, &authn.APIError{Status: 500, Code: "STRIPE_WEBHOOK_SECRET_NOT_FOUND", Message: "Stripe webhook secret not found"}
			}
			// Like the upstream JavaScript integration, pass through the event
			// envelope in its original API version. The SDK leaves data.object in Data.Raw.
			event, err := webhook.ConstructEventWithOptions(payload, signature, opts.WebhookSecret, webhook.ConstructEventOptions{IgnoreAPIVersionMismatch: true})
			if err != nil {
				return nil, &authn.APIError{Status: 400, Code: "FAILED_TO_CONSTRUCT_STRIPE_EVENT", Message: "Failed to construct Stripe event"}
			}
			// A reconciliation failure answers 500 STRIPE_WEBHOOK_ERROR without
			// calling OnEvent, so Stripe retries it, where another runtime logs
			// it, calls its event callback and answers 200.
			// An event with an account or a context only reaches OnEvent, where
			// another runtime reconciles it: a connected account's customer IDs
			// belong to another Stripe account.
			if subs != nil && event.Account == "" && event.Context == "" {
				if subs.organization != nil {
					var err error
					ctx, err = subs.organizationEvent(ctx, event)
					if err != nil {
						return nil, &authn.APIError{Status: 500, Code: "STRIPE_WEBHOOK_ERROR", Message: "Subscription reconciliation failed"}
					}
				}
				if err := subs.handleCheckoutEvent(ctx, event); err != nil {
					return nil, &authn.APIError{Status: 500, Code: "STRIPE_WEBHOOK_ERROR", Message: "Subscription reconciliation failed"}
				}
				if (subs.onComplete != nil || subs.observeTrialStarts) && event.Type == stripesdk.EventTypeCheckoutSessionCompleted {
					if err := subs.observeCheckoutCompletion(ctx, event); err != nil {
						return nil, &authn.APIError{Status: 500, Code: "STRIPE_WEBHOOK_ERROR", Message: "Checkout completion reconciliation failed"}
					}
				}
				if err := subs.handleSubscriptionEvent(ctx, event); err != nil {
					return nil, &authn.APIError{Status: 500, Code: "STRIPE_WEBHOOK_ERROR", Message: "Subscription reconciliation failed"}
				}
			}
			if opts.OnEvent != nil {
				if err := opts.OnEvent(r.Context(), event); err != nil {
					return nil, &authn.APIError{Status: 400, Code: "STRIPE_WEBHOOK_ERROR", Message: "Stripe webhook error"}
				}
			}
			return map[string]bool{"success": true}, nil
		},
	}}}
	// The billing portal is mounted by portal options alone, with or
	// without subscriptions, where another runtime mounts it with
	// subscriptions: it needs its own client and customer lookup.
	if opts.Portal != nil {
		plugin.Endpoints = append(plugin.Endpoints, portalEndpoint(*opts.Portal, opts.Organization))
	}
	if opts.Organization != nil && opts.Subscriptions == nil {
		plugin.ValidateStore = func(store authn.Store) error {
			org, ok := store.(OrganizationBillingStore)
			if !ok {
				return errors.New("stripe: organization billing requires an organization billing store")
			}
			return org.CheckStripeOrganizationSchema(context.Background())
		}
	}
	if opts.Subscriptions != nil {
		plugin.ValidateStore = func(store authn.Store) error {
			if configErr != nil {
				return configErr
			}
			// Billing without a signing secret fails at startup, where another
			// runtime fails each delivery.
			if opts.WebhookSecret == "" {
				return errors.New("stripe: subscription checkout requires a webhook signing secret")
			}
			s, ok := store.(SubscriptionStore)
			if !ok {
				return errors.New("stripe: store does not support subscriptions")
			}
			if subs.onUpdate != nil {
				if _, ok := store.(SubscriptionUpdateStore); !ok {
					return errors.New("stripe: subscription update callbacks require a store with committed update receipts")
				}
			}
			if subs.onCreated != nil || subs.onDeleted != nil || subs.onCancel != nil || subs.observeTrialTransitions {
				if _, ok := store.(SubscriptionNotificationStore); !ok {
					return errors.New("stripe: subscription lifecycle callbacks require a store with transition receipts")
				}
			}
			if subs.onComplete != nil || subs.observeTrialStarts {
				if _, ok := store.(CheckoutCompletionStore); !ok {
					return errors.New("stripe: checkout completion callbacks require a store with settled checkout and event receipts")
				}
			}
			if err := s.CheckSubscriptionSchema(context.Background()); err != nil {
				return err
			}
			for _, plan := range subs.plans {
				if plan.FreeTrial != nil {
					if _, ok := store.(TrialCheckoutStore); !ok {
						return errors.New("stripe: free trials require a store with reservation-bound trial eligibility")
					}
				}
				// A membership plan cannot bill correctly without the policy and
				// seat tracking, so it fails at startup, where another runtime
				// logs an error or refuses each organization request.
				if plan.SeatPriceID != "" {
					if opts.Organization == nil || opts.Organization.AuthorizeReference == nil {
						return errors.New("stripe: membership-based billing requires organization authorization")
					}
					if _, ok := store.(SeatStore); !ok {
						return errors.New("stripe: store does not support automatic seats")
					}
				}
			}
			if opts.Organization != nil {
				org, ok := store.(OrganizationBillingStore)
				if !ok {
					return errors.New("stripe: organization billing requires an organization billing store")
				}
				return org.CheckStripeOrganizationSchema(context.Background())
			}
			return nil
		}
		if subs != nil {
			plugin.StoredUserFields = map[string]authn.UserField{"stripeCustomerId": {Type: authn.FieldString}}
			plugin.Endpoints = append(plugin.Endpoints, subs.successEndpoint(),
				authn.Endpoint{Method: http.MethodPost, Path: "/subscription/upgrade", Handler: subs.checkout},
				authn.Endpoint{Method: http.MethodGet, Path: "/subscription/list", Handler: subs.list},
				authn.Endpoint{Method: http.MethodPost, Path: "/subscription/cancel", Handler: subs.cancel},
				authn.Endpoint{Method: http.MethodPost, Path: "/subscription/restore", Handler: subs.restore},
			)
		}
	}
	if opts.UserCustomers != nil {
		customers := &userCustomers{opts: *opts.UserCustomers}
		billingCheck := plugin.ValidateStore
		plugin.ValidateStore = func(store authn.Store) error {
			if billingCheck != nil {
				if err := billingCheck(store); err != nil {
					return err
				}
			}
			return customers.useStore(store)
		}
		plugin.StoredUserFields = map[string]authn.UserField{"stripeCustomerId": {Type: authn.FieldString}}
		if customers.opts.CreateCustomerOnSignUp {
			plugin.DatabaseHooks.User.Create.After = customers.afterSignUp
		}
	}
	return plugin
}
