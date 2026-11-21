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
        RequireEmailVerification: true,
        Plans: []stripeplugin.Plan{
            {Name: "pro", PriceID: "price_monthly", AnnualPriceID: "price_annual"},
        },
    },
})
auth, err := stonewrit.New(stonewrit.Options{
    Store: store, BaseURL: origin, Secret: authSecret,
    Plugins: []stonewrit.Plugin{billing},
})
```

Import `github.com/Stonewrit/stonewrit-auth/plugins/stripe` as `stripeplugin` and `github.com/stripe/stripe-go/v87` as `stripesdk`. Create the recurring prices in the same Stripe account and mode as the server’s API key. Configure a snapshot webhook destination for your own Stripe account at `/api/auth/stripe/webhook`. Enable `checkout.session.completed`, `checkout.session.expired`, `customer.subscription.created`, `customer.subscription.updated` and `customer.subscription.deleted`. [Stripe Checkout Sessions](https://docs.stripe.com/api/checkout/sessions/create)

## Create a checkout

Send an authenticated POST to `/api/auth/subscription/upgrade`.

Checkout, listing, cancellation, restoration and the billing portal all use the signed-in user's account. Clients can omit `referenceId` or explicitly supply their own user ID. A foreign reference returns HTTP 400 with `REFERENCE_ID_NOT_ALLOWED`. The optional `customerType` accepts `user`. Requesting `organization` returns HTTP 400 with `ORGANIZATION_SUBSCRIPTION_NOT_ENABLED`. Invalid customer types return `VALIDATION_ERROR`.

The example requires a verified email before starting Checkout. Set `RequireEmailVerification` to `false` (the default) to let any signed-in owner start a subscription.

```json
{
  "plan": "pro",
  "annual": true,
  "successUrl": "/billing/success",
  "cancelUrl": "/billing",
  "disableRedirect": true
}
```

The response provides the Checkout Session `id`, the hosted `url` and a `redirect` preference. Use the returned URL to open Checkout. Both callback URLs must resolve to an allowed application origin. The return handler can confirm a completed Checkout Session with Stripe before sending the customer to your page. Signed webhooks also confirm Checkout and keep the subscription current afterward.

An existing local Stripe customer is reused. For a user without one, the server creates a customer using server-owned user metadata and persists the association. The SQL store serializes reservations per owner and releases its lock before contacting Stripe. Identical requests reuse the local subscription, Stripe idempotency key and cached Checkout Session. A different purchase returns HTTP 409 while that checkout is pending. [Stripe idempotent requests](https://docs.stripe.com/api/idempotent_requests)

A checkout expires after 23 hours. Its signed expiration event releases the reservation. If an outcome remains ambiguous, the server keeps the reservation and returns `CHECKOUT_RECONCILIATION_REQUIRED`. Inspect the matching Stripe Checkout Session and redeliver its completion or expiration event before starting a replacement. For a reservation that never reached Stripe, verify the absence of the remote checkout before clearing the incomplete reservation administratively.

## List active subscriptions

An authenticated GET to `/api/auth/subscription/list` lists that user's local active and trialing subscriptions, with the plan's configured price ID. A new reservation has status `incomplete`. A signed checkout completion retrieves the subscription from Stripe and verifies its customer, price, quantity and the local account references before recording the provider subscription ID, status and available billing dates. Replayed completion and expiration events are safe to deliver again.

## Synchronize subscription changes

The SQL adapters synchronize subscriptions for users with a unique stored Stripe customer ID. A signed creation or update retrieves the current subscription from Stripe, matches its single recurring price to a configured plan and records its status, quantity, billing period, trial dates, cancellation dates and schedule ID. A subscription created in the Stripe Dashboard appears in the same list as a subscription created through Checkout. User and reservation references in Stripe metadata must agree with the local customer and subscription.

Only active and trialing rows appear in the active list. For example, a change to `past_due` removes a subscription from the list. A return to `active` restores it. If an existing subscription changes to an unknown price or a combination of prices, the adapter records the local status `unmapped` until Stripe reports a recognized plan again. A signed deletion records cancellation, preserves billing history and prevents later deliveries from reactivating the subscription.

Processing is safe across replicas. The adapter records processed event IDs for 45 days in the existing `verification` table. It compares the stored revision before applying a Stripe response and fetches again if another instance updated the row. An unseen, delayed update therefore synchronizes the provider’s current state. Checkout completion preserves a lifecycle change that arrived first. A database or provider error leaves the event available for retry. [Stripe delivery behavior](https://docs.stripe.com/webhooks#event-ordering)

Custom stores can implement `stripeplugin.SubscriptionLifecycleStore` to enable these writes. The optional `OnEvent` callback receives authenticated notifications, including retries. Use the Stripe event ID when the callback sends messages or performs other side effects. The SQL tests use a local provider transport and independent database connections. [Subscription lifecycle tests](../adapters/sqlstore/stripe_lifecycle_test.go)

## Cancel or restore a subscription

To open the Stripe cancellation page, send an authenticated POST to `/api/auth/subscription/cancel`. Pass the provider subscription ID from the `stripeSubscriptionId` field returned by the list endpoint. Omitting the ID selects the first active or trialing subscription ordered by local ID.

```json
{"subscriptionId":"sub_example","returnUrl":"/billing","disableRedirect":true}
```

Open the `url` returned by the endpoint. The customer confirms the cancellation on Stripe. Configure cancellation in the Stripe customer portal and send subscription webhooks to your application so it can record subsequent changes. Relative return URLs resolve against the application's public origin. [Stripe customer portal](https://docs.stripe.com/customer-management/configure-portal)

To restore a subscription while it is active or trialing, send an authenticated POST to `/api/auth/subscription/restore` with `{"subscriptionId":"sub_example"}`. For a pending cancellation, the handler clears the date or period-end flag at Stripe. For a scheduled plan change, it verifies that the schedule belongs to the same customer and subscription before releasing it. The response contains the current Stripe subscription. A subscription with no pending change returns HTTP 400 with `SUBSCRIPTION_NOT_PENDING_CHANGE`. [Subscription management tests](../adapters/sqlstore/stripe_management_test.go)

The native Go billing client reuses the session of your existing `client.Client`. Import `github.com/Stonewrit/stonewrit-auth/client/stripe` as `stripeclient`. Your application chooses when to open a hosted page.

```go
billingClient := stripeclient.Client{Auth: signedInClient}
page, err := billingClient.Cancel(ctx, stripeclient.Cancellation{
    SubscriptionID: subscriptionID,
    ReturnURL: "/billing",
    DisableRedirect: true,
})
if err != nil {
    return err
}
return showBillingLink(page.URL)
```

The same client exposes `Upgrade`, `List`, `Restore`, and `BillingPortal`. The general billing portal requires `stripeplugin.PortalOptions`. [Billing portal configuration](plugins.md)

## Verify a hosted Checkout return

Set `successUrl` on the upgrade request to the application page the customer should see, for example `/billing/complete?checkout={CHECKOUT_SESSION_ID}`. With a SQL adapter, the plugin sends Stripe a return URL under the configured auth mount. Stripe fills in the Checkout Session ID and sends the browser there. The handler resolves and checks the final callback before and after filling its template. [Stripe hosted Checkout redirects](https://docs.stripe.com/payments/checkout/custom-success-page?payment-ui=stripe-hosted)

For a signed-in customer, the handler first finds the local reservation belonging to that customer and Checkout Session ID. It uses the server’s Stripe client to read the Checkout Session and subscription, then checks the stored customer, account references, price and quantity. A completed payment or a trial requiring no payment can update the local subscription before the browser redirects to the application. Signing out while Stripe is responding prevents that update.

A signed-out or anonymous browser goes directly to the allowed callback with the original template. An open or unpaid Checkout Session, or a temporary Stripe lookup failure, leaves the purchase pending. The application can display the current status from the subscription list. Keep the signed webhook configured so the purchase can complete even if the customer closes the browser.

The adapters keep an owner-bound return receipt for seven days after completion. Reopening a confirmed return from another server instance reuses that receipt. If the signed webhook arrives during the browser lookup, the stored webhook result takes precedence. Browser returns do not invoke the webhook’s `OnEvent` callback. Earlier pending attempts keep their original Stripe success URL and idempotency key when retried. Custom stores can opt into hosted return confirmation by implementing `stripeplugin.CheckoutReturnStore`. [Checkout return tests](../adapters/sqlstore/stripe_return_test.go)
