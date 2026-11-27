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

Import `github.com/Plain-Org/plain-auth/plugins/stripe` as `stripeplugin` and `github.com/stripe/stripe-go/v87` as `stripesdk`. Create the recurring prices in the same Stripe account and mode as the server’s API key. Configure a snapshot webhook destination for your own Stripe account at `/api/auth/stripe/webhook`. Enable `checkout.session.completed`, `checkout.session.expired`, `customer.subscription.created`, `customer.subscription.updated` and `customer.subscription.deleted`. [Stripe Checkout Sessions](https://docs.stripe.com/api/checkout/sessions/create)

## Create a checkout

Send an authenticated POST to `/api/auth/subscription/upgrade`.

Personal billing defaults to the signed-in user’s account. Clients can omit `referenceId` or supply their own user ID. A foreign personal reference returns HTTP 400 with `REFERENCE_ID_NOT_ALLOWED`. When Stripe fails to find or create the customer, personal or organization, the request answers HTTP 400 `UNABLE_TO_CREATE_CUSTOMER` before any Checkout is created, as in another runtime, and can be retried. A failure to reconcile a signed event answers 500 `STRIPE_WEBHOOK_ERROR` without calling `OnEvent`, so Stripe retries it, where another runtime logs the failure, calls its event callback and answers 200, and an unusable billing portal answer from Stripe answers 502 `UNABLE_TO_CREATE_BILLING_PORTAL`. A failed Checkout creation answers 502 `CHECKOUT_CREATION_FAILED` and logs Stripe's status, type, code, parameter and request ID, but not its message. When Stripe definitively refuses it, with a 400, 401, 403 or 404 other than an idempotency conflict, the SQL store releases the reservation and deletes its unsent row, so the next request starts a new purchase; an idempotency conflict, a rate limit, a server error or a network failure keeps the reservation for a retry with the same key. Custom stores opt in by implementing `stripeplugin.CheckoutReleaseStore`. [Release tests](../adapters/sqlstore/stripe_checkout_release_test.go) A price, subscription or response Stripe cannot provide answers 502 `STRIPE_PRICE_UNAVAILABLE`, `STRIPE_SUBSCRIPTION_UNAVAILABLE` or `INVALID_STRIPE_RESPONSE`. These 502 answers carry a fixed message, where another runtime answers 400 with Stripe's code and message, which can disclose account configuration to the browser. [Error code tests](../adapters/sqlstore/stripe_errors_test.go) To manage subscriptions for an organization, configure organization billing as described below.

The example requires a verified email before starting Checkout or changing a plan, as another runtime does; the refusal answers HTTP 400 `EMAIL_VERIFICATION_REQUIRED` before Stripe is contacted. Set `RequireEmailVerification` to `false` (the default) to let any signed-in owner start a subscription. `Subscriptions` mounts the upgrade, list, cancel, restore and success routes; set `Portal` alongside it to expose the billing portal. Subscriptions without a client or plans, without a webhook signing secret, or with a store that lacks the Stripe schema refuse to start. [Option tests](../adapters/sqlstore/stripe_options_test.go)

```json
{
  "plan": "pro",
  "annual": true,
  "seats": 5,
  "successUrl": "/billing/success",
  "cancelUrl": "/billing",
  "locale": "en",
  "disableRedirect": true
}
```

`locale` sets Checkout's display language, as another runtime does. An empty string asks for the browser's language, sent to Stripe as `auto`, even over a `CheckoutSessionParams` locale; omit it to keep the hook's locale or Stripe's default. In Go, set `stripeclient.Checkout.Locale`, to `auto` for the browser's language. The locale is stored with the purchase, so a retry of a pending purchase reopens it with its stored locale, without comparing the new one; one longer than 35 bytes answers 400, since no Stripe locale comes close. A plan change ignores it, as in another runtime. Checkout also saves the buyer's address, and a person's name, onto the existing customer. An unknown request field answers 400 `UNSUPPORTED_CHECKOUT_OPTION`, where another runtime drops it, so a misspelled field is never silently ignored. [Locale tests](../adapters/sqlstore/stripe_checkout_release_test.go)

The response is Stripe's Checkout Session, with its `id` and hosted `url`, plus a `redirect` preference, as in another runtime. A retry of a pending purchase reads the session from Stripe again and answers it whole while it is open. Once it is complete or expired, which leaves it without a URL and, when complete, carries the buyer's details, or when the read fails, it answers only the stored `id`, `url` and `redirect`. Nothing from Stripe is stored. In Go, `stripeclient.HostedPage.Session` holds the session. Use the returned URL to open Checkout. Both callback URLs must resolve to an allowed application origin. The return handler can confirm a completed Checkout Session with Stripe before sending the customer to your page. Signed webhooks also confirm Checkout and keep the subscription current afterward.

For a licensed plan with manually selected quantities, pass a whole-number `seats` value or set `stripeclient.Checkout.Seats` in Go. Omission or zero selects one seat. Values above 2,147,483,647, fractions and negative quantities return HTTP 400. The SQL store records the chosen quantity with the checkout. Retrying with a different quantity while that purchase is pending returns HTTP 409. The SQL adapters verify the completed Checkout Session’s original line-item price and quantity against the reservation, then store the subscription’s current terms. If a customer buys five seats and changes to eight before either webhook arrives, the list shows eight. Historical single-seat reservations retain the checks supported by their saved data. [Seat quantity and retry tests](../adapters/sqlstore/subscriptions_test.go)

A purchase whose stored reservation would exceed 56 KiB, such as one with very long callback URLs, answers HTTP 400 `CHECKOUT_TOO_LARGE` before any row is written or Stripe is asked to create anything, so the reservation fits every supported store's column, although Stripe might accept such URLs. An existing local Stripe customer is reused. For a user without one with a verified email, the server searches Stripe for that email's customer, excluding organization customers, with a list by email when search is unavailable, and reuses the first match whose `userId` metadata is empty or the user's, as another runtime does. Otherwise it creates a customer with the user's email, name and server-owned metadata, and persists the association. Unlike another runtime, an unverified email is not looked up, so a lookup outage cannot block that purchase; and a new customer is created when the match is held elsewhere. As in another runtime, the creation sends no idempotency key of its own, since Stripe replays a key's first answer, an error included, for a day. Two identical purchases at once settle on the first customer bound, and the other request deletes the customer it created, as it does when a refused Checkout released the purchase meanwhile; a response lost after Stripe created a customer can leave it unbound, which a later search for a verified email finds once Stripe indexes it. A match another account, personal or organization, already holds is not shared. The lookup, creation and binding run on their own 30-second budget, so a client that disconnects cannot strand a customer Stripe created before it is bound. [Customer lookup tests](../adapters/sqlstore/stripe_customer_lookup_test.go) The SQL store serializes reservations per owner and releases its lock before contacting Stripe. Identical requests reuse the local subscription, Stripe idempotency key and cached Checkout Session. A different purchase returns HTTP 409 while that checkout is pending. [Stripe idempotent requests](https://docs.stripe.com/api/idempotent_requests)

A checkout expires after 23 hours. Its signed expiration event releases the reservation. If an outcome remains ambiguous, the server keeps the reservation and returns `CHECKOUT_RECONCILIATION_REQUIRED`. Inspect the matching Stripe Checkout Session and redeliver its completion or expiration event before starting a replacement. For a reservation that never reached Stripe, verify the absence of the remote checkout before clearing the incomplete reservation administratively.

### Name plans and their prices

Plan names are trimmed and stored in lowercase, and a request names a plan in any case. Every plan needs a monthly `PriceID` or `LookupKey`; `AnnualPriceID` and `AnnualLookupKey` are optional, and an annual purchase of a plan without one answers 400 "Price ID not found for the selected plan", as in another runtime, but before any Stripe call, where another runtime first finds or creates the customer and lists its subscriptions. Each price names exactly one plan and interval, and a duplicate name or a malformed price ID stops startup. `PriceID` must be a monthly price and `AnnualPriceID` a yearly price, each with an interval count of one, where another runtime accepts any recurring price: a plan models a month and a year, and that interval drives the list, plan changes and Checkout. Another price answers 409 `UNSUPPORTED_SUBSCRIPTION_ITEM` before any purchase is reserved. A yearly subscription of a plan without an annual price lists the monthly price ID, as in another runtime. [Plan rule tests](../plugins/stripe/plans_test.go) · [Price rule tests](../adapters/sqlstore/stripe_plan_rules_test.go)

### Select prices by lookup key

Set `LookupKey`, and `AnnualLookupKey` for the annual price, to sell the active Stripe price that holds the key, as another runtime does. The price is read before each new purchase or plan change and wins over `PriceID`, which is used only when no active price holds the key; a key-only plan without such a price answers 400 "Price ID not found for the selected plan". A failed lookup answers 502 `STRIPE_PRICE_UNAVAILABLE`, where another runtime falls back to the price ID, so a stale price is never sold. A key that resolves to a price this catalog configures for another plan, interval or item answers 409 `UNSUPPORTED_SUBSCRIPTION_ITEM`. A pending purchase keeps the price it was opened with until it completes or expires, so a retry reopens it with no lookup, even during an outage or after the key moved, where another runtime has no reservation; a custom store needs `stripeplugin.PendingCheckoutStore` for this, and without it such a retry answers 409 after a key moved, or 502 during an outage. A subscription Stripe reports on a price holding the key maps to the plan, unless that price is a configured seat or add-on price. To move a key, first add the old price to `RetiredPriceIDs`, so its subscribers keep the plan, where another runtime keeps an unknown single price's stored plan; then move the key. While the key is still on a retired price, the plan sells its `PriceID`, or answers 400 when it has none, so a retired price is never sold. A key-only plan lists no `priceId`, as in another runtime. Keys must be unique across plans and intervals, unpadded and at most 200 bytes, and membership-based plans use price IDs, since seat updates are bound to them. [Lookup key tests](../adapters/sqlstore/stripe_lookup_keys_test.go) · [Key configuration tests](../plugins/stripe/plans_test.go)

### Load plans at request time

Set `LoadPlans` instead of `Plans` to read the plans when they are used, as another runtime accepts a function for its plans:

```go
Subscriptions: &stripeplugin.SubscriptionOptions{
    Client: stripeClient,
    LoadPlans: func(ctx context.Context) ([]stripeplugin.Plan, error) {
        return planCache.Current(ctx) // cache inside the loader
    },
},
```

The plugin calls it once for each request to a subscription route, for each Checkout or subscription webhook event, and for each seat-worker pass, never inside a store transaction; other events do not load plans. One operation uses the plans it loaded throughout, where another runtime calls its function at each use. The result is validated as `Plans` is, an empty list included, and the store and organization options must support it, where another runtime uses its plans unchecked: an error, a panic or an invalid result answers 500 `FAILED_TO_FETCH_PLANS`, and on the webhook the 500 makes Stripe redeliver, where another runtime logs the failure and acknowledges the event. The loader's error is logged without its text. A pending purchase stays bound to its stored price, so a retry after the price changed answers 409. When a plan moves to a new price, keep the old one in `RetiredPriceIDs` while subscriptions use it; otherwise they become `unmapped`. The seat worker needs only the subscription options with `LoadPlans`, and a pass whose plans have no membership plan does nothing until one returns. [Loaded plan tests](../adapters/sqlstore/stripe_loaded_plans_test.go) · [Plan source tests](../plugins/stripe/plans_test.go)

## Customize the Checkout Session

Set `CheckoutSessionParams` to add Stripe Checkout Session parameters to a new purchase, as another runtime's `getCheckoutSessionParams` does:

```go
subscriptions := &stripeplugin.SubscriptionOptions{
    Client: stripeClient,
    Plans:  plans,
    CheckoutSessionParams: func(ctx context.Context, in stripeplugin.CheckoutSessionInput) (*stripesdk.CheckoutSessionCreateParams, error) {
        return &stripesdk.CheckoutSessionCreateParams{
            AllowPromotionCodes: stripesdk.Bool(true),
            TaxIDCollection:     &stripesdk.CheckoutSessionCreateTaxIDCollectionParams{Enabled: stripesdk.Bool(true)},
            Metadata:            map[string]string{"planType": "business"},
        }, nil
    },
}
```

The plugin keeps its own mode, customer, success and cancel URLs, client reference, line items, expiry, hosted page settings, trial and idempotency key, whatever the hook returns, so a recovered session always matches the reservation; host metadata merges beneath the plugin's keys (`userId`, `referenceId`, `subscriptionId`, `checkoutAttemptId`, `customerType`, `organizationId`), which signed webhooks trust. A request's `locale` wins over the hook's, and the hook's `CustomerUpdate` replaces the default.

The hook differs from another runtime's in these ways, for simplicity and identical retries:

- It runs once per new purchase, before the purchase is reserved and outside any store transaction, so its input has no local subscription ID, no trial decision, and `Seats` 0 for a membership plan. A retry of a pending purchase reuses the stored result, and of concurrent first requests, the first stored result wins. Another runtime calls it on every upgrade.
- A returned idempotency key is ignored, and metadata or expansions set on the embedded `Params` join the session's own, which win; a connected account, request headers or extra values answer 500, since a stored reservation cannot replay them.
- The stored parameters are limited to 16 KiB, and a larger result answers 500.

Return a `*plainauth.APIError` to refuse the purchase with that status and code; any other error answers 500 and is logged without its text. Nothing is reserved in either case. A Stripe refusal of the parameters releases the purchase as any refusal does. The parameters are stored with the reservation until it finishes, with the default `customer_update` and the locale, so a retry after a lost response sends what the first request sent. The hook's value is copied, never changed, so it may be shared across purchases. A purchase whose first request was lost before this storage existed is retried without the default, which Stripe can refuse as an idempotency conflict until the purchase expires; let pending purchases settle before upgrading. A replica on an earlier release drops them when it edits a newer purchase, so configure the hook, and roll out this release, only once no purchase is pending on an older replica. A custom store runs the hook only when it answers a new purchase's first reservation with `ErrCheckoutPriceCheck`, and must keep `CheckoutParams` and `Locale` with the reservation. [Checkout parameter tests](../adapters/sqlstore/stripe_checkout_release_test.go)

### Collect tax IDs

Return `TaxIDCollection: &stripesdk.CheckoutSessionCreateTaxIDCollectionParams{Enabled: stripesdk.Bool(true)}`. For an organization purchase, also return `CustomerUpdate` with `Name: stripesdk.String("auto")` and `Address: stripesdk.String("auto")` so Stripe can save the business name, as in another runtime. A returned `CustomerUpdate` replaces the default whole, so keep `Address`: automatic tax needs the buyer's address on a customer the server created without one.

### Calculate tax automatically

Return `AutomaticTax: &stripesdk.CheckoutSessionCreateAutomaticTaxParams{Enabled: stripesdk.Bool(true)}`. It needs Stripe Tax configured in your account.

## Create customers at sign-up

Set `UserCustomers` to give every new user a Stripe customer once the user is stored, with or without `Subscriptions`:

```go
stripeplugin.New(stripeplugin.Options{
    UserCustomers: &stripeplugin.UserCustomerOptions{
        Client:                 stripeClient,
        CreateCustomerOnSignUp: true,
        Logger:                 logger, // the logger in plainauth.Options.Logger
        CustomerCreateParams: func(ctx context.Context, in stripeplugin.NewUserCustomer) (*stripesdk.CustomerCreateParams, error) {
            return &stripesdk.CustomerCreateParams{Description: stripesdk.String("Signed up on the web")}, nil
        },
        OnCustomerCreate: func(ctx context.Context, c stripeplugin.UserCustomerCreated) error {
            return recordCustomer(ctx, c.User.ID, c.Customer.ID)
        },
    },
})
```

The customer is stored as the user's `stripeCustomerId`, so the store needs the `stripe-subscriptions` or `stripe-organization` [schema profile](schema.md), which also adds the subscription table; another runtime adds only the user column for this setup. The hook runs for every new user, from HTTP sign-ups and direct Go calls such as `Auth.SignUpEmail`, anonymous users and phone sign-ups with placeholder addresses included, as in another runtime. For a verified email it links the customer Stripe has for that email, found as Checkout finds it, when its `userId` metadata is empty or the user's and no other account holds it. Otherwise, and for an unverified email, which is not looked up, it creates one with the user's email, name and metadata `userId` and `customerType: "user"`.

`CustomerCreateParams` adds parameters to a created customer; the user's email and name and the plugin's metadata keys replace the host's, as another runtime merges them. Parameters that name a connected account, a Stripe context, headers or extra form values create nothing, since Checkout could not use that customer. `OnCustomerCreate` runs once a created or linked customer is stored. Every failure, a panic included, is logged with the user and customer IDs, never the email or error text, and the sign-up still succeeds. A customer is linked only while the user has none and no personal Checkout is pending, where another runtime overwrites the column; a customer the sign-up created but could not link is deleted, unless a failed commit may have stored the link. The link writes the plugin's column as Checkout does, without the user update database hooks, which another runtime runs for this write. The lookup and creation are bounded to 30 seconds, the link and any deletion to 10 seconds each, and they finish even if the client disconnects. Pass the Auth's logger in `Logger`, since a direct Go call has no endpoint to log through. The hook is a user create database hook, so New refuses it alongside the admin, passkey and SIWE plugins, and `scim.New` refuses such an Auth, since their user creation does not run those hooks yet. A plugin value with `UserCustomers` serves one Auth; call `stripeplugin.New` for each. Custom stores implement `stripeplugin.UserCustomerStore`. [Sign-up customer tests](../adapters/sqlstore/stripe_signup_customer_test.go)

### Keep the customer's email current

Set `SyncEmail` on `UserCustomerOptions` to copy a user's changed email to their Stripe customer once the change is stored, as another runtime always does. The update reads the user's own `stripeCustomerId`, does nothing without one or for a customer Stripe reports deleted, and updates Stripe only when the email differs. A failure is logged with the user and customer IDs, never either address, and the update still succeeds; another runtime logs both addresses. It is a user update database hook, so New refuses it beside the features whose user updates skip those hooks, such as social sign-in, magic links, email codes, phone numbers, SSO and the admin plugin, which also change emails; another runtime syncs it from every update that runs its hooks. [Email sync tests](../adapters/sqlstore/stripe_signup_customer_test.go)

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

Configure a meter in Stripe and report billable usage from your application. This integration handles purchase and subscription status. Combining a metered base with other prices remains open. Upgrade all application instances that create Checkout sessions or process billing webhooks before enabling a metered price. Custom subscription stores must honor the new-reservation price check in `ReserveStripeCheckout`, retain `CheckoutAttempt.Metered` across retries, and implement `SubscriptionLifecycleStore`. [Stripe usage-based billing](https://docs.stripe.com/billing/subscriptions/usage-based)

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

### Add fixed line items

Use `LineItems` instead of `MeteredPriceIDs` to add configured prices after the base line in Checkout, as another runtime adds a plan's line items: an item with a `Quantity` is a licensed price at that fixed quantity, and one without is a metered price sent without a quantity. `MeteredPriceIDs` is shorthand for items without quantities, and a plan sets one or the other.

```go
stripeplugin.Plan{
    Name:    "platform",
    PriceID: "price_platform_monthly",
    LineItems: []stripeplugin.LineItem{
        {Price: "price_support_monthly", Quantity: 2},
        {Price: "price_requests_monthly"},
    },
}
```

Every item must be active at the selected interval: a fixed one licensed and a metered one metered, or the purchase answers 409 `UNSUPPORTED_SUBSCRIPTION_ITEM` before it is reserved. The items are stored with the purchase, so a retry, even after a configuration edit, sends what the first request sent, and signed events and the hosted return check the receipt's prices and quantities exactly. After the purchase, the subscription keeps its plan while it holds the base and every configured item, a fixed item at any quantity of at least one; a missing or unknown item makes it `unmapped`, where another runtime maps it from the base alone. Its seats are the base quantity. A plan with line items needs a store with subscription lifecycle storage, checked at startup for fixed plans, and custom stores must round-trip `CheckoutAttempt.LineItems`. Upgrade every billing node before configuring `LineItems`. [Line item tests](../adapters/sqlstore/stripe_line_items_test.go) · [Line item configuration tests](../plugins/stripe/plans_test.go)

Only a configured price ID with an optional fixed quantity is supported, with no inline prices, adjustable quantities, tax rates or item metadata, where another runtime accepts any Checkout line, so every purchased line can be checked against the configuration. Items are refused on membership-managed plans, since seat updates and membership matching verify an exact base and seat basket, and beside a metered base, whose quantity defines no seats. Each item's price must be separate from every base, seat and retired price. Active plans with add-ons or line items change directly, as described under [Change a plan with several items](#change-a-plan-with-several-items). The application reports usage to its Stripe meters. [Stripe usage reporting](https://docs.stripe.com/billing/subscriptions/usage-based/recording-usage)

## Bill an organization

Apply the `stripe-organization` schema profile and install the organization plugin alongside Stripe. The profile includes the organization and subscription tables and adds `stripeCustomerId` to the organization. It can also be combined with `organization-teams`. Organization billing refuses to start without that column, with or without `Subscriptions`; migrating an existing database to the profile adds it and keeps existing organizations. Without an `AuthorizeReference` policy, an organization's upgrade, list, cancel, restore and billing portal requests answer HTTP 400 `AUTHORIZE_REFERENCE_REQUIRED` before Stripe is contacted or a purchase reserved, as in another runtime, and an organization's Checkout return answers 401 `UNAUTHORIZED`, where another runtime checks no ownership and redirects; personal billing keeps working. [Option tests](../adapters/sqlstore/stripe_options_test.go)

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

The SQL adapter reads the member's role and calls the policy with it and the operation before it opens its transaction, so the policy never runs inside a database transaction, as in another runtime. It then rereads the session and membership under lock and refuses the operation if the role changed. A custom store calls `OrganizationScope.Authorize` before its transaction and rechecks the role under lock. The policy receives `upgrade-subscription`, `list-subscription`, `billing-portal`, `cancel-subscription` or `restore-subscription`. Both immediate and period-end plan changes use `upgrade-subscription`. Keep the callback free of side effects. A different authorized administrator can retry the same checkout after a purchaser loses their role. Stripe metadata retains the original purchaser’s ID and the organization’s billing reference. [Authorization and recovery tests](../adapters/sqlstore/stripe_organization_test.go)

The organization receives its own Stripe customer, which only the server stores: its billing portal uses that customer alone, and answers `CUSTOMER_NOT_FOUND` before Stripe until the customer exists, where another runtime falls back to an active subscription's customer. The server searches for an existing customer using organization metadata, with a paginated list fallback if search is unavailable. Customer creation uses the organization's current name, read when the customer is created, and the server never sets or updates an organization customer's email itself, during Checkout or renewal; return it from `CustomerCreateParams`, or call your own Stripe client with the customer ID from the organization's `stripeCustomerId` column or from `CustomerID` on a row `ListOrganization` returns. A purchase without `customerType` stays on the signed-in user's own customer even while an organization is active, and an explicit `referenceId` names its organization rather than the active one. Signed checkout and subscription webhooks update the organization’s subscription even if the original purchaser has since left. Ambiguous personal and organization references or customer mappings require reconciliation. [Browser client and renewal tests](../conformance/stripe-organization-fixture.mjs)

An authorized member can open Stripe’s cancellation or plan confirmation page, request a different seat quantity, or undo a pending change. A single-seat subscription also supports price changes at the next billing boundary. The server rechecks the acting member’s current permission before disclosing a hosted link or sending a schedule change to Stripe. Signed webhooks record confirmed cancellations and new prices. These flows have local provider coverage on SQLite, PostgreSQL and MySQL. Plans with line items or add-ons change directly under the organization's scope. [Direct change tests](../adapters/sqlstore/stripe_plan_items_test.go) [Organization management tests](../adapters/sqlstore/stripe_organization_management_test.go)

### Customize the organization's customer

Set `CustomerCreateParams` on `stripeplugin.OrganizationOptions` to add parameters, such as a billing email, a description or tax details, to the customer an organization's first purchase creates. It runs after the purchaser's membership is rechecked, with the organization's ID and name, the purchaser and a body-free copy of the request, and never for a customer found in Stripe. The organization's name and the plugin's metadata keys (`organizationId`, `customerType`) replace the host's, as another runtime merges them. An error, or request options such as a connected account, answers 400 `UNABLE_TO_CREATE_CUSTOMER` and creates nothing.

`OnCustomerCreate` runs once the purchase that created the customer has stored it, with the same input and the Stripe customer. Of two identical purchases at once, only the one whose customer was bound reports it. When the binding fails without a verdict, for example because the purchaser lost the billing role meanwhile, the server reads which customer the organization holds: the created one is reported if it was stored after all, and deleted otherwise, so a later purchase never adopts it unreported. An error answers 400 `UNABLE_TO_CREATE_CUSTOMER`, as in another runtime, but the customer stays stored, where another runtime leaves it unstored for a later search to find; the next attempt continues with it without calling `OnCustomerCreate` again. A personal purchase calls neither; users' customers are customized through `UserCustomers`. [Organization customer tests](../adapters/sqlstore/stripe_organization_customer_test.go)

### Keep the organization's customer in step

The Stripe plugin cannot wrap the organization plugin's hooks, as another runtime does, so assign `stripeplugin.OrganizationHooks` methods to `organization.Options`, calling your own hooks first:

```go
hooks := stripeplugin.OrganizationHooks{Client: stripeClient, Store: store, Logger: logger}
orgPlugin, err := organization.New(organization.Options{
    Store:                    store,
    AfterUpdateOrganization:  hooks.AfterUpdateOrganization,
    BeforeDeleteOrganization: hooks.BeforeDeleteOrganization,
})
```

`AfterUpdateOrganization` renames the organization's Stripe customer when the organization's name differs from the customer's, as in another runtime. It does nothing for an organization without a customer or a customer Stripe reports deleted, runs on its own 30-second budget so a client that disconnects cannot cancel it, and logs a failure, missing hook settings included, without Stripe's message, never failing the update. `BeforeDeleteOrganization` refuses with 400 `ORGANIZATION_HAS_ACTIVE_SUBSCRIPTION` while Stripe reports any subscription of the customer other than canceled, incomplete or incomplete_expired, across every page, as in another runtime. It also refuses while a purchase that can still complete is reserved for the organization, so a Checkout cannot complete for a deleted organization; another runtime does not check this. A reservation stops counting once its Checkout Session expires. A failed lookup is logged and refuses the deletion. A purchase started between the check and the deletion is not seen, as in another runtime, since the organization plugin runs the hook outside its deletion transaction. Custom stores implement `stripeplugin.OrganizationBillingReader`. [Organization hook tests](../adapters/sqlstore/stripe_organization_hooks_test.go)

## Bill by organization membership

For monthly organization billing, set `PriceID` to the fixed base price and `SeatPriceID` to a separate licensed price for each member. Use the same Stripe price for both fields when the plan charges only for seats. Install the organization and Stripe plugins with the `stripe-organization` profile and the authorization policy above. Give the worker the same subscription options as the HTTP service. A membership plan refuses to start without an organization policy, or with a store that cannot track seats, where another runtime logs an error or starts and refuses each organization request: such a plan cannot bill correctly without them. A personal checkout of a membership plan bills the caller's base price and quantity, even while an organization is active.

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

A subscription with one item moving to a plan with one item opens that confirmation, licensed or metered; a metered target is confirmed without a quantity. To change only the quantity, send the current plan and its new `seats` value. An omitted or zero quantity proposes one seat on the hosted page. To keep an existing multi-seat quantity when switching prices, send its current `seats` value. The subscription keeps its current quantity until Stripe confirms the change. Repeating an active subscription’s current price and quantity returns `ALREADY_SUBSCRIBED_PLAN`. Resolve any cancellation, attached schedule, pending update or collection pause before requesting a change. The current subscription must be exactly a configured plan: its base and that plan's line items or add-ons, else 409 `UNSUPPORTED_SUBSCRIPTION_ITEM`. [Plan change tests](../adapters/sqlstore/stripe_plan_change_test.go)

### Change a plan with several items

A change to or from a plan with line items or add-ons, including a seat change on one, updates the subscription directly instead, with the target plan's `ProrationBehavior`, and answers the return URL once Stripe holds it. Another runtime also updates directly when the plans' line items differ, but opens the portal confirmation for a seat change or a switch between plans with the same items, which Stripe refuses for a subscription with several items. The base item takes the target price and quantity, without a quantity for a metered price. An item both plans share at the same price and configured quantity is left alone, an item the target lacks is deleted, and the target's new items are added, a fixed one with its configured quantity. A kept fixed item whose quantity drifted returns to its configured quantity. Another runtime ignores quantities when it compares items and adds new ones without them, so Stripe uses one. A metered base with line items answers 409 `UNSUPPORTED_SUBSCRIPTION_ITEM`, and a change scheduled for the next period still needs one licensed item on both sides, where another runtime rewrites line items into the scheduled phase.

The change is reserved in the store before it is sent, under an idempotency key every server retrying it shares, where another runtime keeps neither. A retry after a lost response, active or trialing, finds Stripe already holding the target and succeeds without a second update; a retry after a failure before Stripe sends the same key and items. While a change may still reach Stripe, for 30 minutes after its latest send, another direct change or a new schedule for the subscription answers 409 `SUBSCRIPTION_PENDING_CHANGE`; a single-item confirmation page is not affected. A schedule reservation not yet attached blocks a direct change for up to a day, and a schedule attached since the subscription was read is caught before the update is sent. A key is never reused after 23 hours. A coded Stripe refusal answers 400 with its code and releases the reservation at once, and so does a Stripe server error, which answers 502 `STRIPE_SUBSCRIPTION_UNAVAILABLE` and which Stripe would replay under the same key; any other failure answers 502 and keeps the reservation. The row is then synchronized from Stripe under the session and permission checks, where another runtime writes the plan and a seat count itself: a session revoked meanwhile answers 401, and a result other than the target answers 409 `CHECKOUT_RECONCILIATION_REQUIRED`. Custom stores opt in by implementing `stripeplugin.PlanChangeStore`, and their `ReserveStripeSchedule` must answer `ErrPendingSchedule` while a direct change started within `PlanChangeHold`; without it the change answers 409 `PLAN_CHANGE_UNAVAILABLE` before Stripe is asked. Organization plans with line items or add-ons change the same way. [Direct change tests](../adapters/sqlstore/stripe_plan_items_test.go)

### Choose a proration behavior

Set `ProrationBehavior` on a plan to `create_prorations`, the default, `always_invoice` or `none` for the plugin's own updates to that plan's subscriptions, such as membership seat changes and direct changes to the plan. Every plan's value is checked at startup, and another value stops it, where another runtime sends any value to Stripe when it is used. Callbacks report the effective value, so an unset one reads `create_prorations`. A plan change confirmed on Stripe's portal follows the portal configuration's proration instead. [Proration tests](../plugins/stripe/plans_test.go) · [Default tests](../plugins/stripe/plans_internal_test.go)

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

### Describe plan limits

Give a plan `Limits`, such as `map[string]any{"projects": 5, "features": []any{"api", "sso"}}`, and the list endpoint returns it as `limits` with each subscription of that plan, as another runtime does; a plan without limits lists none. Callbacks receive the plan's `Limits` and `Group`, a label the plugin never sends to Stripe. The plugin keeps a JSON copy of the limits, so numbers come back as float64, arrays as `[]any` and objects as `map[string]any`, and later changes to your map never reach the installed plan; an empty map counts as unset, and limits that do not marshal to JSON of at most 8 KiB refuse to start, so a stored callback receipt always fits. [Plan limit tests](../adapters/sqlstore/stripe_options_test.go)

## Synchronize subscription changes

The SQL adapters synchronize subscriptions for users and organizations with a unique stored Stripe customer ID. A signed creation or update retrieves the current subscription from Stripe, matches its recurring prices to a configured plan and records its status, quantity, billing period, trial dates, cancellation dates and schedule ID. A subscription created in the Stripe Dashboard appears in the same list as a subscription created through Checkout. User and reservation references in Stripe metadata must agree with the local customer and subscription. An event with an `account` or a `context` reaches `OnEvent` but never reads or changes subscriptions, where another runtime reconciles it: a connected account's customer IDs belong to another Stripe account. Point an account-level webhook destination of the platform account at the endpoint, since an organization-level destination sets a context on every event, the platform's own included. [Lifecycle tests](../adapters/sqlstore/stripe_lifecycle_test.go)

Only active and trialing rows appear in the active list. For example, a change to `past_due` removes a subscription from the list. A return to `active` restores it. If an existing subscription changes to an unknown price or an unconfigured combination of prices, the adapter records the local status `unmapped` until Stripe reports a recognized plan again. A signed deletion records cancellation, preserves billing history and prevents later deliveries from reactivating the subscription. Checkout confirmation, signed updates and deletions store `cancelAtPeriodEnd`, `cancelAt`, `canceledAt` and `endedAt` as Stripe reports them, clear them when Stripe does, and a deletion clears `stripeScheduleId`. [Cancellation field tests](../adapters/sqlstore/stripe_lifecycle_test.go)

Processing is safe across replicas. The adapter records processed event IDs for 45 days in the existing `verification` table. It compares the stored revision before applying a Stripe response and fetches again if another instance updated the row. An unseen, delayed update therefore synchronizes the provider’s current state. Checkout completion preserves a lifecycle change that arrived first. A database or provider error leaves the event available for retry. [Stripe delivery behavior](https://docs.stripe.com/webhooks#event-ordering)

Custom stores can implement `stripeplugin.SubscriptionLifecycleStore` to enable these writes. The optional `OnEvent` callback receives authenticated notifications, including retries. Use the Stripe event ID when the callback sends messages or performs other side effects. The SQL tests use a local provider transport and independent database connections. [Subscription lifecycle tests](../adapters/sqlstore/stripe_lifecycle_test.go)

### Retire a price

To move a plan to a new price while existing subscribers stay on the old one, set the new price as `PriceID` or `AnnualPriceID` and list the old one in `RetiredPriceIDs`. A subscription on a retired price keeps its plan, at the monthly or yearly interval the price reports, and lists the plan's configured price. A retired price is never sold: Checkout sends the configured price, and asking for the same plan from a retired price moves the subscription to the configured one rather than answering `ALREADY_SUBSCRIBED_PLAN`. Keep a price listed while any subscription uses it. A price that is configured nowhere marks its subscription `unmapped`, where another runtime keeps an unknown single price's stored plan, so a price nobody configured never keeps a plan's entitlements. Each retired price must be a price ID used nowhere else, at most 100 per plan, and membership-based plans cannot retire prices, since seat updates are bound to the configured prices. [Retired price tests](../adapters/sqlstore/stripe_retired_prices_test.go)

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

Open the `url` returned by the endpoint. The customer confirms the cancellation on Stripe. Configure cancellation in the Stripe customer portal and send subscription webhooks to your application so it can record subsequent changes. Relative return URLs resolve against the application's public origin, and `redirect` is true unless `disableRedirect` is set. When Stripe answers that the subscription is already set to be canceled, the handler first records Stripe's pending cancellation. A subscription of another account, or one Stripe reports as no longer active or trialing, answers `SUBSCRIPTION_NOT_FOUND` without opening a portal; an ended one keeps its local row, updated to Stripe's status, for billing history and trial eligibility, where another runtime deletes it. A subscription Stripe answers with 404 `resource_missing` is left unchanged, since that answer can come from a key for another account or mode; another runtime deletes it on cancel. A Stripe HTTP 400 refusal with a code answers HTTP 400 with that code and a fixed message, and every other Stripe failure, including a refusal without a code, answers 502 `STRIPE_SUBSCRIPTION_UNAVAILABLE`, where another runtime relays Stripe's code and message, which can disclose account configuration to the browser. [Stripe customer portal](https://docs.stripe.com/customer-management/configure-portal) · [Cancellation and restore tests](../adapters/sqlstore/stripe_cancel_restore_test.go)

To restore a subscription while it is active or trialing, send an authenticated POST to `/api/auth/subscription/restore` with `{"subscriptionId":"sub_example"}`. For a pending cancellation, the handler clears the date or period-end flag at Stripe. For a scheduled plan change, it verifies that the schedule belongs to the same customer and subscription before releasing it. The response contains the current Stripe subscription, and the local row stores Stripe's fields after the change rather than nulls of its own. A named subscription already recorded as ended returns HTTP 400 with `SUBSCRIPTION_NOT_ACTIVE`, as in another runtime; an omitted ID with no active subscription, or one Stripe reports as no longer active or trialing, returns `SUBSCRIPTION_NOT_FOUND`; and one with no pending change `SUBSCRIPTION_NOT_PENDING_CHANGE`. Another runtime writes the cleared fields from its local row and clears a stored schedule after any retrieval, where Go stores Stripe's answer and releases only a schedule Stripe reports active on this subscription. A stored schedule Stripe no longer reports is cleared by the opening refresh with no schedule request; a schedule Stripe reports but not as active, or attached elsewhere, returns 409, so nothing Stripe does not attach to this subscription is released. Stripe's refusals follow the cancellation rules above. [Subscription management tests](../adapters/sqlstore/stripe_management_test.go)

The native Go billing client reuses the session of your existing `client.Client`. Import `github.com/Plain-Org/plain-auth/client/stripe` as `stripeclient`. Your application chooses when to open a hosted page.

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

## Block account deletion during a subscription

With `DeleteUserEnabled`, refuse to delete an account while Stripe reports a subscription that still bills, from `BeforeDeleteUser`. This recipe lets accounts without a Stripe customer go, denies the deletion when the lookup fails, and pages through every subscription of the customer:

```go
opts.BeforeDeleteUser = func(ctx context.Context, user plainauth.User, _ *http.Request) error {
    customer, err := store.StripeCustomer(ctx, user.ID)
    if errors.Is(err, plainauth.ErrNotFound) {
        return nil
    }
    if err != nil {
        return err
    }
    list := stripeClient.V1Subscriptions.List(ctx, &stripesdk.SubscriptionListParams{Customer: stripesdk.String(customer), Status: stripesdk.String("all")})
    for sub, err := range list.All(ctx) {
        if err != nil {
            return err
        }
        switch sub.Status {
        case stripesdk.SubscriptionStatusCanceled, stripesdk.SubscriptionStatusIncomplete, stripesdk.SubscriptionStatusIncompleteExpired:
        default:
            return &plainauth.APIError{Status: 400, Code: "ACTIVE_SUBSCRIPTION", Message: "Cancel your active subscription before deleting your account"}
        }
    }
    return nil
}
```

The hook runs before and outside the deletion's transaction, so a subscription created between the hook and the deletion is not caught. [Deletion guard tests](../adapters/sqlstore/stripe_user_deletion_test.go)

## Verify a hosted Checkout return

Set `successUrl` on the upgrade request to the application page the customer should see, for example `/billing/complete?checkout={CHECKOUT_SESSION_ID}`. With a SQL adapter, the plugin sends Stripe a return URL under the configured auth mount. Stripe fills in the Checkout Session ID and sends the browser there. The handler resolves and checks the final callback before and after filling its template. [Stripe hosted Checkout redirects](https://docs.stripe.com/payments/checkout/custom-success-page?payment-ui=stripe-hosted)

For a signed-in customer, the handler first finds the local reservation belonging to that customer and Checkout Session ID. It uses the server’s Stripe client to check the Checkout Session’s original purchase, customer and account references, then synchronizes the current subscription. A completed payment or a trial requiring no payment can update the local subscription before the browser redirects to the application. Signing out while Stripe is responding prevents that update.

A signed-out or anonymous browser goes directly to the allowed callback with the original template. An open or unpaid Checkout Session, or a temporary Stripe lookup failure, leaves the purchase pending. The application can display the current status from the subscription list. Keep the signed webhook configured so the purchase can complete even if the customer closes the browser.

The adapters keep an owner-bound return receipt for seven days after completion. Reopening a confirmed return from another server instance reuses that receipt. If the signed webhook arrives during the browser lookup, the stored webhook result takes precedence. Browser returns do not invoke the webhook’s `OnEvent` callback. Earlier pending attempts keep their original Stripe success URL and idempotency key when retried. Custom stores can opt into hosted return confirmation by implementing `stripeplugin.CheckoutReturnStore`. An organization's Checkout appends `&organizationId=<id>` to Stripe's success URL; its return asks the organization policy with `upgrade-subscription` before reading Stripe and rechecks the member under lock before committing, and a refused return answers HTTP 401, 403 or 404 and never redirects, where another runtime checks no ownership and always redirects: a browser that does not own the purchase is not sent to the purchaser's page and commits nothing. [Checkout return tests](../adapters/sqlstore/stripe_return_test.go)
