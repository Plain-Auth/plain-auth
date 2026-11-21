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

Personal billing defaults to the signed-in user’s account. Clients can omit `referenceId` or supply their own user ID. A foreign personal reference returns HTTP 400 with `REFERENCE_ID_NOT_ALLOWED`. Organization checkout, listing and portal access require the organization billing configuration below.

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

## Bill an organization

Apply the `stripe-organization` schema profile and install the organization plugin alongside Stripe. The profile includes the organization and subscription tables and adds `stripeCustomerId` to the organization. It can also be combined with `organization-teams`.

Set the Stripe plugin’s `Organization` option to an explicit billing policy. This example allows owners and administrators to manage billing. A custom finance role can read subscriptions.

```go
organizationBilling := &stripeplugin.OrganizationOptions{
    AuthorizeReference: func(member stripeplugin.ReferenceAuthorization) bool {
        for _, role := range strings.Split(member.Role, ",") {
            switch strings.TrimSpace(role) {
            case "owner", "admin":
                return true
            case "finance":
                if member.Action == "list-subscription" {
                    return true
                }
            }
        }
        return false
    },
}
billing := stripeplugin.New(stripeplugin.Options{
    Organization: organizationBilling,
    WebhookSecret: webhookSecret,
    Subscriptions: &stripeplugin.SubscriptionOptions{Client: stripeClient, Plans: plans},
    Portal: &stripeplugin.PortalOptions{Client: stripeClient, Customers: store},
})
```

Use `customerType: "organization"` for a new checkout, subscription list or billing portal. Specify an organization ID with `referenceId`, or omit it to use the active organization. With the Go client, set `stripeclient.Checkout.CustomerType` or `stripeclient.Portal.CustomerType` to `"organization"`. Call `ListOrganization(ctx, id)` to read subscriptions and pass an empty ID to select the active organization.

The SQL adapter reads the session and membership under lock and passes the current role and operation to the policy. The supported operations are `upgrade-subscription`, `list-subscription` and `billing-portal`. Keep the callback local and free of side effects. A different authorized administrator can retry the same checkout after a purchaser loses their role. Stripe metadata retains the original purchaser’s ID and the organization’s billing reference. [Authorization and recovery tests](../adapters/sqlstore/stripe_organization_test.go)

The organization receives its own Stripe customer. The server searches for an existing customer using organization metadata, with a paginated list fallback if search is unavailable. Customer creation uses the stored organization name. Signed checkout and subscription webhooks update the organization’s subscription even if the original purchaser has since left. Ambiguous personal and organization references or customer mappings require reconciliation. [Browser client and renewal tests](../conformance/stripe-organization-fixture.mjs)

Organization checkout currently covers a single licensed seat. Automatic member-based pricing, organization plan switches, cancellation and restoration through the subscription endpoints, and synchronization of organization name or deletion events remain open.

## Change an existing plan

Send the new plan name and the current Stripe subscription ID to the same endpoint. Set `annual` to switch billing intervals. A user with exactly one active or trialing subscription can omit `subscriptionId`.

```json
{"plan":"pro","annual":true,"subscriptionId":"sub_example","returnUrl":"/billing","disableRedirect":true}
```

Open the response’s `url` so the customer can review and confirm the change on Stripe. The return URL defaults to the application root. The server scopes the confirmation to the existing customer, subscription and item. Repeating a request can open another review page for that item. The current plan remains active until Stripe confirms the change. The signed subscription webhook synchronizes the new price and interval.

Enable subscription updates and add the target prices to the Stripe customer portal configuration. Stripe applies that configuration’s proration behavior when the customer confirms and calculates any resulting balance adjustment. [Stripe portal deep links](https://docs.stripe.com/customer-management/portal-deep-links)

Plan changes support one licensed seat on one configured monthly or yearly item. Repeating an active subscription’s current price returns `ALREADY_SUBSCRIBED_PLAN`. Resolve any cancellation, attached schedule, pending update or collection pause before requesting a change. Metered and multi-item subscriptions remain outside the supported flow. [Plan change tests](../adapters/sqlstore/stripe_plan_change_test.go)

## Schedule a change for the next billing period

Pass `scheduleAtPeriodEnd: true` to keep the current plan through its paid period. This uses the same endpoint, session, configured price IDs and trusted return URL as an immediate change. The successful response points back to the application. The Go client exposes the option as `stripeclient.Checkout.ScheduleAtPeriodEnd`.

```json
{"plan":"pro","annual":true,"subscriptionId":"sub_example","scheduleAtPeriodEnd":true,"returnUrl":"/billing"}
```

Stripe’s schedule preserves the original price and quantity through the current period. Its second phase begins at the billing boundary with the requested price, one seat and no proration. The subscription continues after Stripe releases the schedule. The list endpoint exposes `stripeScheduleId` while the schedule is attached. Its plan and interval follow Stripe’s subscription updates. Use the restore endpoint to release a schedule before the change takes effect. [Stripe subscription schedules](https://docs.stripe.com/billing/subscriptions/subscription-schedules)

The SQL adapters record the request before calling Stripe. Another server can retry the same request after a lost response. Conflicting destinations return HTTP 409. If a create response was lost and the schedule ID is still unknown after 23 hours, the handler returns `CHECKOUT_RECONCILIATION_REQUIRED`. Check the customer’s subscription and schedule in Stripe before resolving the local reservation. [Schedule recovery and concurrency tests](../adapters/sqlstore/stripe_schedules_test.go)

Scheduling supports an active, automatically charged subscription with one licensed seat. Trialing subscriptions, discounts, tax overrides, Connect transfers and custom phase terms require separate billing management. An existing schedule must be resolved before requesting a different destination. [Browser client and phase-transition tests](../conformance/stripe-lifecycle-fixture.mjs)

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
