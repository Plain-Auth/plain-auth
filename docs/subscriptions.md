# Recurring Stripe Checkout

A signed-in user can start a recurring subscription for their own account or an organization they manage. A plan can charge for licensed seats, add metered usage to those seats, or use one metered price. Configure monthly and optional annual Stripe price IDs, then let the client select a plan by name. Checkout and subsequent changes use the selected account’s Stripe customer.

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
auth, err := plainauth.New(plainauth.Options{
    Store: store, BaseURL: origin, Secret: authSecret,
    Plugins: []plainauth.Plugin{billing},
})
```

Import `github.com/Plain-Auth/plain-auth/plugins/stripe` as `stripeplugin` and `github.com/stripe/stripe-go/v87` as `stripesdk`. Create the recurring prices in the same Stripe account and mode as the server’s API key. Configure a snapshot webhook destination for your own Stripe account at `/api/auth/stripe/webhook`. Enable `checkout.session.completed`, `checkout.session.expired`, `customer.subscription.created`, `customer.subscription.updated` and `customer.subscription.deleted`. [Stripe Checkout Sessions](https://docs.stripe.com/api/checkout/sessions/create)

## Create a checkout

Send an authenticated POST to `/api/auth/subscription/upgrade`.

Personal billing defaults to the signed-in user’s account. Clients can omit `referenceId` or supply their own user ID. A foreign personal reference returns HTTP 400 with `REFERENCE_ID_NOT_ALLOWED`. To manage subscriptions for an organization, configure organization billing as described below.

The example requires a verified email before starting Checkout. Set `RequireEmailVerification` to `false` (the default) to let any signed-in owner start a subscription.

```json
{
  "plan": "pro",
  "annual": true,
  "seats": 5,
  "successUrl": "/billing/success",
  "cancelUrl": "/billing",
  "disableRedirect": true
}
```

The response provides the Checkout Session `id`, the hosted `url` and a `redirect` preference. Use the returned URL to open Checkout. Both callback URLs must resolve to an allowed application origin. The return handler can confirm a completed Checkout Session with Stripe before sending the customer to your page. Signed webhooks also confirm Checkout and keep the subscription current afterward.

For a licensed plan with manually selected quantities, pass a whole-number `seats` value or set `stripeclient.Checkout.Seats` in Go. Omission or zero selects one seat. Values above 2,147,483,647, fractions and negative quantities return HTTP 400. The SQL store records the chosen quantity with the checkout. Retrying with a different quantity while that purchase is pending returns HTTP 409. The SQL adapters verify the completed Checkout Session’s original line-item price and quantity against the reservation, then store the subscription’s current terms. If a customer buys five seats and changes to eight before either webhook arrives, the list shows eight. Historical single-seat reservations retain the checks supported by their saved data. [Seat quantity and retry tests](../adapters/sqlstore/subscriptions_test.go)

An existing local Stripe customer is reused. For a user without one, the server creates a customer using server-owned user metadata and persists the association. The SQL store serializes reservations per owner and releases its lock before contacting Stripe. Identical requests reuse the local subscription, Stripe idempotency key and cached Checkout Session. A different purchase returns HTTP 409 while that checkout is pending. [Stripe idempotent requests](https://docs.stripe.com/api/idempotent_requests)

A checkout expires after 23 hours. Its signed expiration event releases the reservation. If an outcome remains ambiguous, the server keeps the reservation and returns `CHECKOUT_RECONCILIATION_REQUIRED`. Inspect the matching Stripe Checkout Session and redeliver its completion or expiration event before starting a replacement. For a reservation that never reached Stripe, verify the absence of the remote checkout before clearing the incomplete reservation administratively.

## Offer a free trial

Set `FreeTrial` on a plan to offer a positive number of days on a new Checkout. For example, `stripeplugin.Plan{Name: "pro", PriceID: "price_pro", FreeTrial: &stripeplugin.FreeTrial{Days: 14}}` offers two weeks. The client selects the plan by name. The server sends the eligible duration to Stripe as `subscription_data[trial_period_days]`. [Stripe Checkout parameters](https://docs.stripe.com/api/checkout/sessions/create)

The SQL adapters check every subscription belonging to the selected personal account or organization. Any trial start date, trial end date, or current `trialing` status shows prior use across plans. A canceled paid subscription or an abandoned checkout with no trial history leaves the account eligible. Keep historical subscription rows when retaining eligibility across renewals. An organization administrator’s personal subscription history applies only to their personal purchases. [Released-client eligibility cases](../conformance/stripe-organization-fixture.mjs)

The store records the trial decision with the checkout reservation. Concurrent requests and retries after a lost Stripe response reuse the same term and idempotency key. A reservation opened before trial support keeps its original terms. Custom stores supporting trial plans must implement `stripeplugin.TrialCheckoutStore`. Signed subscription events record the provider’s status and trial dates. [Cross-database trial tests](../adapters/sqlstore/stripe_trial_test.go)

Configure trial callbacks on the same `FreeTrial` to observe the following signed events.

| Callback | Signed event and condition |
| --- | --- |
| `OnTrialStart(ctx, subscription)` | A completed Checkout for this plan, when Stripe's current subscription has both trial dates. The start callback runs on each authenticated delivery, before `OnSubscriptionComplete`. |
| `OnTrialEnd(ctx, transition)` | A signed subscription update converts the locally trialing subscription to `active`. This follows `OnSubscriptionUpdate`. |
| `OnTrialExpired(ctx, transition)` | A signed subscription update moves the locally trialing subscription to `incomplete_expired`. This also follows `OnSubscriptionUpdate`. |

`TrialTransition` includes the committed local subscription and a clone of the mounted webhook request. End and expiry require the signed transition and the current provider plan and status to agree. The SQL adapters claim a transition once across replicas. A process that stops after claiming and before invoking host code can miss that notification. These callbacks can run without any subscription observers. [Signed delivery and callback order tests](../conformance/stripe-organization-fixture.mjs)

A callback error or panic skips subsequent lifecycle callbacks for that delivery. The general webhook `OnEvent` still runs. A redelivery of the same completed Checkout can invoke `OnTrialStart` again. Use your application's subscription identity and trial dates to deduplicate trial-start side effects. [Concurrent owner and failure tests](../adapters/sqlstore/stripe_trial_callbacks_test.go)

## Start a metered subscription

Configure the monthly or annual Stripe price ID for the usage-based plan and omit `SeatPriceID`. The subscription’s initial Checkout supports one recurring price with an interval of one month or one year. The server reads the configured price from Stripe before reserving the purchase. If the price lookup fails, the client can retry after Stripe becomes available. Give the Stripe API key permission to read prices. [Stripe Price object](https://docs.stripe.com/api/prices/object)

For a metered price, the server sends the price ID to Checkout and omits its quantity, even when your client supplies `seats`. The reservation retains the original request so retries after an interruption send identical parameters. A completed browser return or signed webhook checks the original Checkout line’s price, interval and metered billing mode. The active subscription list returns `seats: 1` when Stripe supplies no item quantity. Use your application's usage records or Stripe's meter summaries to measure consumption. [Metered checkout and receipt tests](../adapters/sqlstore/stripe_metered_test.go)

Configure a meter in Stripe and report billable usage from your application. This integration handles purchase and subscription status. Combining a metered base with other prices and switching an existing metered plan remain open. Upgrade all application instances that create Checkout sessions or process billing webhooks before enabling a metered price. Custom subscription stores must honor the new-reservation price check in `ReserveStripeCheckout`, retain `CheckoutAttempt.Metered` across retries, and implement `SubscriptionLifecycleStore`. [Stripe usage-based billing](https://docs.stripe.com/billing/subscriptions/usage-based)

## Add metered usage to a licensed plan

Use `MeteredPriceIDs` to include usage charges with a manually quantified licensed base. Both personal and organization billing use the server’s configured price IDs. The following monthly plan charges for each licensed seat and adds metered storage and requests.

```go
stripeplugin.Plan{
    Name: "platform",
    PriceID: "price_platform_monthly",
    MeteredPriceIDs: []string{"price_storage_monthly", "price_requests_monthly"},
}
```

An upgrade request chooses the plan and its licensed seat quantity. Checkout sends the base quantity and one quantity-free line for each configured meter. All prices must be active and share the selected interval. The same add-on configuration applies when the client selects `AnnualPriceID`. Use separate plan configurations for monthly and yearly meters. The platform supports up to 19 distinct metered add-ons alongside one licensed base. Each add-on price must be separate from all configured base and member-seat prices. [Stripe Checkout line items](https://docs.stripe.com/api/checkout/sessions/create)

A pending reservation keeps its original ordered price IDs and quantities across retries, including after a plan configuration edit. Signed events and hosted returns verify the original Checkout receipt. The subscription list then reads the current base’s quantity and period regardless of item order. If a required meter disappears or an unrecognized price appears, an existing subscription becomes `unmapped` until its configured prices return. Custom stores must round-trip `CheckoutAttempt.MeteredPriceIDs`. Deploy all billing nodes before offering a plan with add-ons. [Persistence and account-isolation tests](../adapters/sqlstore/stripe_addons_test.go)

Metered add-ons on membership-managed plans, add-ons with fixed quantities or inline prices, and changes to active add-on plans remain open. The application reports usage to its Stripe meters. [Stripe usage reporting](https://docs.stripe.com/billing/subscriptions/usage-based/recording-usage)

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

Pass `customerType: "organization"` to start checkout, switch plans, list subscriptions, open the billing portal, cancel or restore. Specify `referenceId` to choose an organization, or omit it to use the active organization. In the Go client, set `CustomerType` and `ReferenceID` on `stripeclient.Checkout`, `stripeclient.Portal` or `stripeclient.Cancellation`. Call `ListOrganization(ctx, id)` to read subscriptions and `RestoreOrganization(ctx, id, subscriptionID)` to undo a pending cancellation or release a schedule. An empty organization ID selects the active organization.

The SQL adapter reads the session and membership under lock and passes the current role and operation to the policy. The policy receives `upgrade-subscription`, `list-subscription`, `billing-portal`, `cancel-subscription` or `restore-subscription`. Both immediate and period-end plan changes use `upgrade-subscription`. Keep the callback local and free of side effects. A different authorized administrator can retry the same checkout after a purchaser loses their role. Stripe metadata retains the original purchaser’s ID and the organization’s billing reference. [Authorization and recovery tests](../adapters/sqlstore/stripe_organization_test.go)

The organization receives its own Stripe customer. The server searches for an existing customer using organization metadata, with a paginated list fallback if search is unavailable. Customer creation uses the stored organization name. Signed checkout and subscription webhooks update the organization’s subscription even if the original purchaser has since left. Ambiguous personal and organization references or customer mappings require reconciliation. [Browser client and renewal tests](../conformance/stripe-organization-fixture.mjs)

An authorized member can open Stripe’s cancellation or plan confirmation page, request a different seat quantity, or undo a pending change. A single-seat subscription also supports price changes at the next billing boundary. The server rechecks the acting member’s current permission before disclosing a hosted link or sending a schedule change to Stripe. Signed webhooks record confirmed cancellations and new prices. These flows have local provider coverage on SQLite, PostgreSQL and MySQL. Multi-item plan changes and synchronization of organization name or deletion events remain open. [Organization management tests](../adapters/sqlstore/stripe_organization_management_test.go)

## Bill by organization membership

For monthly organization billing, set `PriceID` to the fixed base price and `SeatPriceID` to a separate licensed price for each member. Use the same Stripe price for both fields when the plan charges only for seats. Install the organization and Stripe plugins with the `stripe-organization` profile and the authorization policy above. Give the worker the same subscription options as the HTTP service.

```go
subscriptions := stripeplugin.SubscriptionOptions{
    Client: stripeClient,
    Plans: []stripeplugin.Plan{{
        Name: "team", PriceID: "price_team_monthly", SeatPriceID: "price_member_monthly",
        ProrationBehavior: "create_prorations",
    }},
}
worker, err := stripeplugin.NewSeatWorker(store, subscriptions)
if err != nil {
    return err
}
// Run in a service worker with its own shutdown context.
return worker.Run(ctx, 10*time.Second, func(err error) { log.Print(err) })
```

Organization checkout counts committed members. With two prices it reserves one base unit plus that many seat units. A seat-only plan reserves one line item with the member count. A supplied `seats` value is ignored for this plan’s organization checkout. Retrying a pending checkout preserves its original price IDs and quantities. When the server verifies the completed checkout, the price and quantity of every item must match the saved reservation. Once Stripe confirms the purchase, the worker catches up with membership changes that happened during checkout. A personal subscription to this price still uses the quantity selected by its owner. [Browser client checkout and membership tests](../conformance/stripe-organization-fixture.mjs)

For an annual base plus membership seats, give the plan three price IDs. `PriceID` is its ordinary base price, `AnnualPriceID` is a different yearly base price and `SeatPriceID` is a separate yearly licensed price. Select that plan with `annual: true` or `stripeclient.Checkout{Annual: true}`. Checkout reserves one annual base unit and the current number of yearly seats. The subscription list returns the annual base price, `billingInterval: "year"` and the confirmed seat count. [Annual checkout and membership tests](../conformance/stripe-organization-fixture.mjs)

For annual seat-only billing, set `AnnualPriceID` and `SeatPriceID` to the same yearly licensed price. Keep `PriceID` as the plan’s ordinary monthly price. Send `annual: true` to bill one yearly item at the organization’s current member count. Adding or removing a member changes the quantity of that same item. [Annual seat-only checkout and renewal tests](../adapters/sqlstore/stripe_seats_test.go)

A plan has one seat price. To offer both monthly and annual organization billing, configure distinct plan names with matching seat prices. A mixed-interval request returns HTTP 409 with `UNSUPPORTED_SUBSCRIPTION_ITEM` before the server reserves a purchase. Stripe Checkout requires the base and seat items to share the same interval. [Stripe Checkout interval limitations](https://docs.stripe.com/billing/subscriptions/mixed-interval#limitations)

The worker reads committed membership changes and updates the subscription’s existing Stripe item. Adding a member, accepting an invitation, leaving, removing a member or deleting a member’s account updates the count. Deleting the final member’s account reduces it to zero. The worker also discovers active and trialing organization subscriptions when you enable seat billing on a previously configured price. Each change uses the plan’s `ProrationBehavior`, which defaults to `create_prorations` and also accepts `always_invoice` and `none`. Subscription lists reflect the most recently confirmed Stripe quantity. [Three-database membership and recovery tests](../adapters/sqlstore/stripe_seats_test.go)

Run at least one worker, or call `worker.SyncOnce(ctx, batchSize)` from a scheduled process with a batch size from 1 to 1,000. Replicas share durable work in the existing verification table. A restart retries the same subscription, item and quantity with the same Stripe idempotency key. A failed organization moves behind other queued work. If a prepared request is more than 23 hours old and the remote quantity differs from its recorded target, inspect the reported organization’s Stripe subscription and reconcile that operation before retrying. [Stripe idempotent requests](https://docs.stripe.com/api/idempotent_requests)

Automatic seat updates support one active or trialing organization subscription with matching monthly or yearly licensed prices. When a plan has a fixed base item, that item supplies the billing period and stays at quantity one. The worker changes the seat item by its Stripe item ID. If a provider edit removes that item or changes the fixed quantity, restore the configured items before resuming synchronization. Resolve a pending provider update, schedule or collection pause before synchronizing again. Metered prices combined with membership-based seats, extra line items, automatic repair of a removed Stripe item, and hosted or scheduled switches involving membership-managed plans remain open.

## Change an existing plan

Send the new plan name and the current Stripe subscription ID to the same endpoint. Set `annual` to switch billing intervals. For an account with exactly one active or trialing subscription, the client can omit `subscriptionId`.

```json
{"plan":"pro","annual":true,"subscriptionId":"sub_example","returnUrl":"/billing","disableRedirect":true}
```

Open the response’s `url` so the customer can review and confirm the change on Stripe. The return URL defaults to the application root. The server scopes the confirmation to the existing customer, subscription and item. Repeating a request can open another review page for that item. The current plan remains active until Stripe confirms the change. The signed subscription webhook synchronizes the new price and interval.

Enable subscription updates and add the target prices to the Stripe customer portal configuration. Stripe applies that configuration’s proration behavior when the customer confirms and calculates any resulting balance adjustment. [Stripe portal deep links](https://docs.stripe.com/customer-management/portal-deep-links)

Plan changes support one configured monthly or yearly licensed item. To change only the quantity, send the current plan and its new `seats` value. An omitted or zero quantity proposes one seat on the hosted page. To keep an existing multi-seat quantity when switching prices, send its current `seats` value. The subscription keeps its current quantity until Stripe confirms the change. Repeating an active subscription’s current price and quantity returns `ALREADY_SUBSCRIBED_PLAN`. Resolve any cancellation, attached schedule, pending update or collection pause before requesting a change. Metered and multi-item subscriptions remain outside the supported flow. [Plan change tests](../adapters/sqlstore/stripe_plan_change_test.go)

## Schedule a change for the next billing period

Pass `scheduleAtPeriodEnd: true` to keep the current plan through its paid period. This uses the same endpoint, session, configured price IDs and trusted return URL as an immediate change. The successful response points back to the application. The Go client exposes the option as `stripeclient.Checkout.ScheduleAtPeriodEnd`.

```json
{"plan":"pro","annual":true,"subscriptionId":"sub_example","scheduleAtPeriodEnd":true,"returnUrl":"/billing"}
```

Stripe’s schedule preserves the original price and quantity through the current period. Its second phase begins at the billing boundary with the requested price, one seat and no proration. The subscription continues after Stripe releases the schedule. The list endpoint exposes `stripeScheduleId` while the schedule is attached. Its plan and interval follow Stripe’s subscription updates. Use the restore endpoint to release a schedule before the change takes effect. [Stripe subscription schedules](https://docs.stripe.com/billing/subscriptions/subscription-schedules)

The SQL adapters record the request before calling Stripe. Another server can retry the same request after a lost response. Conflicting destinations return HTTP 409. If a create response was lost and the schedule ID is still unknown after 23 hours, the handler returns `CHECKOUT_RECONCILIATION_REQUIRED`. Check the customer’s subscription and schedule in Stripe before resolving the local reservation. [Schedule recovery and concurrency tests](../adapters/sqlstore/stripe_schedules_test.go)

Scheduling supports an active, automatically charged subscription with one licensed seat. Trialing subscriptions, discounts, tax overrides, Connect transfers and custom phase terms require separate billing management. An existing schedule must be resolved before requesting a different destination. [Browser client and phase-transition tests](../conformance/stripe-lifecycle-fixture.mjs)

## List active subscriptions

An authenticated GET to `/api/auth/subscription/list` lists the selected user’s or organization’s active and trialing subscriptions with each plan’s configured price ID. A new reservation has status `incomplete`. A signed checkout completion retrieves the subscription from Stripe and verifies its customer, price, quantity and the local account references before recording the provider subscription ID, status and available billing dates. Replayed completion and expiration events are safe to deliver again.

## Synchronize subscription changes

The SQL adapters synchronize subscriptions for users and organizations with a unique stored Stripe customer ID. A signed creation or update retrieves the current subscription from Stripe, matches its recurring prices to a configured plan and records its status, quantity, billing period, trial dates, cancellation dates and schedule ID. A subscription created in the Stripe Dashboard appears in the same list as a subscription created through Checkout. User and reservation references in Stripe metadata must agree with the local customer and subscription.

Only active and trialing rows appear in the active list. For example, a change to `past_due` removes a subscription from the list. A return to `active` restores it. If an existing subscription changes to an unknown price or an unconfigured combination of prices, the adapter records the local status `unmapped` until Stripe reports a recognized plan again. A signed deletion records cancellation, preserves billing history and prevents later deliveries from reactivating the subscription.

Processing is safe across replicas. The adapter records processed event IDs for 45 days in the existing `verification` table. It compares the stored revision before applying a Stripe response and fetches again if another instance updated the row. An unseen, delayed update therefore synchronizes the provider’s current state. Checkout completion preserves a lifecycle change that arrived first. A database or provider error leaves the event available for retry. [Stripe delivery behavior](https://docs.stripe.com/webhooks#event-ordering)

Custom stores can implement `stripeplugin.SubscriptionLifecycleStore` to enable these writes. The optional `OnEvent` callback receives authenticated notifications, including retries. Use the Stripe event ID when the callback sends messages or performs other side effects. The SQL tests use a local provider transport and independent database connections. [Subscription lifecycle tests](../adapters/sqlstore/stripe_lifecycle_test.go)

### Observe committed subscription updates

Set `OnSubscriptionUpdate` on `stripeplugin.SubscriptionOptions` to receive signed `customer.subscription.updated` deliveries for a subscription that is already linked locally or has a verified pending checkout.

```go
subscriptions.OnSubscriptionUpdate = func(ctx context.Context, update stripeplugin.SubscriptionUpdate) error {
    // The event ID identifies this delivery across Stripe retries.
    return app.RecordBillingChange(ctx, update.Event.ID, update.Subscription.ReferenceID,
        update.Subscription.Status, update.StripeSubscription.Status)
}
```

The callback runs after the SQL transaction commits and releases its locks, before the general `OnEvent` hook. `Subscription` holds the local row committed for that event, including its verified personal or organization reference. `StripeSubscription` and `Event` hold the signed provider snapshot. A delayed event can describe an older status than the local row, because reconciliation reads the provider’s current subscription. [Post-commit callback tests](../adapters/sqlstore/stripe_update_callback_test.go)

Each authenticated redelivery can invoke the callback again, including concurrent deliveries on different servers. The adapters retain the committed local result with the event for 45 days. A retry during that window uses the original result even if a later event changed the row. Use the event ID as an idempotency key for application side effects. Events handled while the callback was disabled have no saved notification. Enable it on every webhook-serving instance before relying on it. Custom stores must implement `stripeplugin.SubscriptionUpdateStore`.

A billing or receipt-storage failure returns HTTP 500 so Stripe can retry. A callback error or panic is logged with the Stripe event ID. The general hook still runs and the webhook can acknowledge the delivery. An application that requires guaranteed processing should persist its own work and monitor its failures. [Released-client delivery and failure tests](../conformance/stripe-lifecycle-fixture.mjs)

### Observe a completed Checkout

Set `OnSubscriptionComplete` on `stripeplugin.SubscriptionOptions` to receive a signed `checkout.session.completed` for a personal or organization purchase. The mounted webhook, the browser return, and an earlier subscription event can arrive in any order. Only the signed Checkout delivery invokes this callback. It runs after the database commit and before the general `OnEvent` hook. [Released-client delivery tests](../conformance/stripe-organization-fixture.mjs)

```go
subscriptions.OnSubscriptionComplete = func(ctx context.Context, p stripeplugin.SubscriptionComplete) error {
    return app.RecordPurchase(ctx, p.Event.ID, p.Subscription.ReferenceID, p.Plan.Name)
}
```

`Event` contains the signed Checkout session. `StripeSubscription` contains the subscription retrieved from Stripe for this delivery. `Subscription` and `Plan` describe the local record and configured plan committed for this delivery. `Request` is a clone of the mounted webhook request, with its body already consumed. On an authenticated retry, the server checks the original purchase and ownership, fetches the current subscription, and commits its current plan, status and quantity before the callback. If the live subscription no longer contains a configured plan, the delivery skips this callback and the general hook still runs. Use the Stripe event ID to make application side effects idempotent.

Enable the callback on your checkout-serving and webhook-serving instances. The SQL adapters retain the original purchase binding for 45 days for new checkouts opened with this option. Older checkouts retain their original seven-day window. The first accepted delivery stores a separate event receipt for 45 days. A provider or storage failure allows Stripe to retry. A host callback error or panic is logged by event ID and the general callback still runs. Custom stores must implement `stripeplugin.CheckoutCompletionStore`. [Owner, retry, and retention tests](../adapters/sqlstore/stripe_checkout_completion_test.go)

### Observe creation, cancellation, and deletion

The following hooks on `stripeplugin.SubscriptionOptions` run after a signed provider event commits. Each payload includes the signed event, the provider’s subscription, and the associated local subscription. The local record’s `ReferenceID` identifies the user or organization.

| Hook | Trigger | Additional payload |
| --- | --- | --- |
| `OnSubscriptionCreated` | A signed `customer.subscription.created` first establishes a configured subscription outside Checkout, such as a purchase created in the Stripe Dashboard. | `SubscriptionCreated.Plan` captures the plan configuration used for the purchase. |
| `OnSubscriptionCancel` | A signed update and the current active Stripe subscription both show a pending cancellation, and the local row moves from no cancellation to a period-end flag or an explicit date. Restoring the subscription permits a later cancellation to trigger again. | `SubscriptionCancellation.CancellationDetails` contains Stripe’s optional reason, feedback, and comment. |
| `OnSubscriptionDeleted` | A signed `customer.subscription.deleted` identifies a locally bound subscription. It also runs when an earlier update already set the local status to canceled. | `SubscriptionEvent.Subscription` contains the committed canceled record. |

Creation and cancellation are claimed once across replicas for each transition. A process that stops after claiming and before running host code can miss that notification. Deletion and update run per authenticated delivery and can repeat. Use the Stripe event ID for application idempotency. The SQL adapters keep one compact receipt per event for 45 days. Custom stores that enable these hooks must implement `SubscriptionNotificationStore`.

Within a pending-cancellation delivery, `OnSubscriptionCancel` runs first, followed by `OnSubscriptionUpdate`, then `OnEvent`. A cancellation callback that returns an error or panics skips the update callback on that delivery. The general event callback still runs. On redelivery, the claimed transition stays consumed and the update hook can run. [Signed event comparison](../conformance/stripe-lifecycle-fixture.mjs) · [Concurrent lifecycle tests](../adapters/sqlstore/stripe_lifecycle_callbacks_test.go)

## Cancel or restore a subscription

To open the Stripe cancellation page, send an authenticated POST to `/api/auth/subscription/cancel`. Pass the provider subscription ID from the `stripeSubscriptionId` field returned by the list endpoint. Omitting the ID selects the first active or trialing subscription ordered by local ID.

```json
{"subscriptionId":"sub_example","returnUrl":"/billing","disableRedirect":true}
```

Open the `url` returned by the endpoint. The customer confirms the cancellation on Stripe. Configure cancellation in the Stripe customer portal and send subscription webhooks to your application so it can record subsequent changes. Relative return URLs resolve against the application's public origin. [Stripe customer portal](https://docs.stripe.com/customer-management/configure-portal)

To restore a subscription while it is active or trialing, send an authenticated POST to `/api/auth/subscription/restore` with `{"subscriptionId":"sub_example"}`. For a pending cancellation, the handler clears the date or period-end flag at Stripe. For a scheduled plan change, it verifies that the schedule belongs to the same customer and subscription before releasing it. The response contains the current Stripe subscription. A subscription with no pending change returns HTTP 400 with `SUBSCRIPTION_NOT_PENDING_CHANGE`. [Subscription management tests](../adapters/sqlstore/stripe_management_test.go)

The native Go billing client reuses the session of your existing `client.Client`. Import `github.com/Plain-Auth/plain-auth/client/stripe` as `stripeclient`. Your application chooses when to open a hosted page.

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

The same client exposes `Upgrade`, `List`, `ListOrganization`, `Restore`, `RestoreOrganization` and `BillingPortal`. The general billing portal requires `stripeplugin.PortalOptions`. [Billing portal configuration](plugins.md)

## Verify a hosted Checkout return

Set `successUrl` on the upgrade request to the application page the customer should see, for example `/billing/complete?checkout={CHECKOUT_SESSION_ID}`. With a SQL adapter, the plugin sends Stripe a return URL under the configured auth mount. Stripe fills in the Checkout Session ID and sends the browser there. The handler resolves and checks the final callback before and after filling its template. [Stripe hosted Checkout redirects](https://docs.stripe.com/payments/checkout/custom-success-page?payment-ui=stripe-hosted)

For a signed-in customer, the handler first finds the local reservation belonging to that customer and Checkout Session ID. It uses the server’s Stripe client to check the Checkout Session’s original purchase, customer and account references, then synchronizes the current subscription. A completed payment or a trial requiring no payment can update the local subscription before the browser redirects to the application. Signing out while Stripe is responding prevents that update.

A signed-out or anonymous browser goes directly to the allowed callback with the original template. An open or unpaid Checkout Session, or a temporary Stripe lookup failure, leaves the purchase pending. The application can display the current status from the subscription list. Keep the signed webhook configured so the purchase can complete even if the customer closes the browser.

The adapters keep an owner-bound return receipt for seven days after completion. Reopening a confirmed return from another server instance reuses that receipt. If the signed webhook arrives during the browser lookup, the stored webhook result takes precedence. Browser returns do not invoke the webhook’s `OnEvent` callback. Earlier pending attempts keep their original Stripe success URL and idempotency key when retried. Custom stores can opt into hosted return confirmation by implementing `stripeplugin.CheckoutReturnStore`. [Checkout return tests](../adapters/sqlstore/stripe_return_test.go)
