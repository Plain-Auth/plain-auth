// Package stripe authenticates Stripe webhook deliveries and dispatches their events.
package stripe

import (
	"context"
	"errors"
	"io"
	"net/http"

	authn "github.com/FineStack/finestack-auth"
	stripesdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

// Options configures delivery of authenticated events. Stripe may retry an
// event, so OnEvent can use its ID to make application side effects idempotent.
type Options struct {
	Subscriptions *SubscriptionOptions
	Portal        *PortalOptions
	WebhookSecret string
	OnEvent       func(context.Context, stripesdk.Event) error
}

// New exposes POST /stripe/webhook beneath the configured auth base path.
func New(opts Options) authn.Plugin {
	subs, configErr := configureSubscriptions(opts.Subscriptions)
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
			if subs != nil {
				if err := subs.handleCheckoutEvent(ctx, event); err != nil {
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
		plugin.Endpoints = append(plugin.Endpoints, portalEndpoint(*opts.Portal))
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
			return s.CheckSubscriptionSchema(context.Background())
		}
		if subs != nil {
			plugin.Endpoints = append(plugin.Endpoints, authn.Endpoint{Method: http.MethodPost, Path: "/subscription/upgrade", Handler: subs.checkout}, authn.Endpoint{Method: http.MethodGet, Path: "/subscription/list", Handler: subs.list})
		}
	}
	return plugin
}
