# Recurring Stripe Checkout

Use hosted Checkout to start a single-seat recurring subscription for a signed-in user. The application configures monthly and optional annual Stripe price IDs. Clients select a plan by name. Stripe receives the customer associated with the authenticated user.

```go
ddl, err := schema.Generate("postgres", []string{"stripe-subscriptions"})
if err != nil {
    return err
}
store, err := sqlstore.OpenWithSchema(ctx, "postgres", dsn, ddl)
if err != nil {
    return err
}
defer store.Close()

billing := stripeplugin.New(stripeplugin.Options{
    WebhookSecret: webhookSecret,
    Subscriptions: &stripeplugin.SubscriptionOptions{
        Client: stripesdk.NewClient(apiKey),
        Plans: []stripeplugin.Plan{
            {Name: "pro", PriceID: "price_monthly", AnnualPriceID: "price_annual"},
        },
    },
})
auth, err := fineauth.New(fineauth.Options{
    Store: store, BaseURL: origin, Secret: authSecret,
    Plugins: []fineauth.Plugin{billing},
})
```

Import `github.com/FineStack/finestack-auth/plugins/stripe` as `stripeplugin` and `github.com/stripe/stripe-go/v87` as `stripesdk`. Create the recurring prices in the same Stripe account and mode as the server’s API key. Configure the webhook destination at `/api/auth/stripe/webhook` for `checkout.session.completed` and `checkout.session.expired`. [Stripe Checkout Sessions](https://docs.stripe.com/api/checkout/sessions/create)

## Create a checkout

Send an authenticated POST to `/api/auth/subscription/upgrade`.

```json
{
  "plan": "pro",
  "annual": true,
  "successUrl": "/billing/success",
  "cancelUrl": "/billing",
  "disableRedirect": true
}
```

The response provides the Checkout Session `id`, the hosted `url` and a `redirect` preference. Use the returned URL to open Checkout. Both callback URLs must resolve to an allowed application origin. A successful browser return displays your application page. Signed events establish billing state.

An existing local Stripe customer is reused. For a user without one, the server creates a customer using server-owned user metadata and persists the association. The SQL store serializes reservations per owner and releases its lock before contacting Stripe. Identical requests reuse the local subscription, Stripe idempotency key and cached Checkout Session. A different purchase returns HTTP 409 while that checkout is pending. [Stripe idempotent requests](https://docs.stripe.com/api/idempotent_requests)

A checkout expires after 23 hours. Its signed expiration event releases the reservation. If an outcome remains ambiguous, the server keeps the reservation and returns `CHECKOUT_RECONCILIATION_REQUIRED`. Inspect the matching Stripe Checkout Session and redeliver its completion or expiration event before starting a replacement. For a reservation that never reached Stripe, verify the absence of the remote checkout before clearing the incomplete reservation administratively.

## List active subscriptions

An authenticated GET to `/api/auth/subscription/list` lists that user's local active and trialing subscriptions, with the plan's configured price ID. A new reservation has status `incomplete`. A signed checkout completion retrieves the subscription from Stripe and verifies its customer, price, quantity and the local account references before recording the provider subscription ID, status and available billing dates. Replayed completion and expiration events are safe to deliver again.

The built-in synchronization covers initial checkout completion and expiration. Subsequent renewal, payment failure, cancellation and external plan changes require your application’s signed-event callback to update the canonical subscription state before using this list for entitlements. Organization billing, seat management, scheduled plan changes and the cancel and restore endpoints remain on the [Stripe checklist](parity/plugins/stripe.md). The [SQL lifecycle tests](../adapters/sqlstore/subscriptions_test.go) use the official Stripe Go client with an in-process transport.
