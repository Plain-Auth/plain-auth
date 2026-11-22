// Package stripe authenticates Stripe webhook deliveries and dispatches their events.
package stripe

import (
	"context"
	"errors"
	"io"
	"net/http"

	authn "github.com/Stonewrit/stonewrit-auth"
	stripesdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

// Options configures delivery of authenticated events. Stripe may retry an
// event, so OnEvent can use its ID to make application side effects idempotent.
type Options struct {
	Organization  *OrganizationOptions
	Subscriptions *SubscriptionOptions
	Portal        *PortalOptions
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
				if subs.onComplete != nil && event.Type == stripesdk.EventTypeCheckoutSessionCompleted {
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
			if subs.onCreated != nil || subs.onDeleted != nil || subs.onCancel != nil {
				if _, ok := store.(SubscriptionNotificationStore); !ok {
					return errors.New("stripe: subscription lifecycle callbacks require a store with transition receipts")
				}
			}
			if subs.onComplete != nil {
				if _, ok := store.(CheckoutCompletionStore); !ok {
					return errors.New("stripe: checkout completion callbacks require a store with settled checkout and event receipts")
				}
			}
			if err := s.CheckSubscriptionSchema(context.Background()); err != nil {
				return err
			}
			for _, plan := range subs.plans {
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
			plugin.Endpoints = append(plugin.Endpoints, subs.successEndpoint(),
				authn.Endpoint{Method: http.MethodPost, Path: "/subscription/upgrade", Handler: subs.checkout},
				authn.Endpoint{Method: http.MethodGet, Path: "/subscription/list", Handler: subs.list},
				authn.Endpoint{Method: http.MethodPost, Path: "/subscription/cancel", Handler: subs.cancel},
				authn.Endpoint{Method: http.MethodPost, Path: "/subscription/restore", Handler: subs.restore},
			)
		}
	}
	return plugin
}
