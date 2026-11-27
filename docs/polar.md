# Polar customer billing

Use the optional `integrations/polar` Go module to sell a configured product to a signed-in individual. The integration opens a Polar checkout and records its lifecycle from verified deliveries. You can also enable the individual customer’s hosted portal and billing summary. It requires a direct session and a verified email address. Guest accounts, application-key sessions and administrator impersonation cannot open a checkout.

## Configure the integration

To provision the billing tables with the rest of the application schema, run the CLI against a dedicated auth database. Select the same dialect for all three commands and set `AUTH_DSN` for the migration and check.

```sh
authctl generate --dialect postgres --plugins polar
authctl migrate --dialect postgres --plugins polar
authctl check schema --dialect postgres --plugins polar
```

Include other enabled schema profiles in the comma-separated list. Repeating the migration preserves existing reservations and delivery receipts. The runtime also initializes the ledger when `OpenLedger` starts. [All schema profiles](schema.md)

Use an organization access token for the Polar merchant, the merchant’s organization UUID, a configured product UUID, and the exact HTTPS origin of its hosted checkouts. Keep production and sandbox credentials, webhook secrets and products together. The auth database can be SQLite, PostgreSQL or MySQL.

```go
import (
    "net/http"
    "os"
    "time"

    "github.com/Plain-Org/plain-auth/integrations/polar"
    polargo "github.com/polarsource/polar-go"
)

// db is an application-owned *sql.DB pointing to the same canonical auth database.
ledger, err := polar.OpenLedger(ctx, db, "postgres")
if err != nil {
    return err
}
sdk := polargo.New(
    polargo.WithSecurity(os.Getenv("POLAR_ACCESS_TOKEN")),
    polargo.WithClient(&http.Client{
        Timeout: 15 * time.Second,
        CheckRedirect: func(*http.Request, []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }),
)
billing, err := polar.NewService(polar.Options{
    Client:         sdk,
    Ledger:         ledger,
    OrganizationID: os.Getenv("POLAR_ORGANIZATION_ID"),
    Checkout: &polar.CheckoutOptions{
        HostedOrigin: os.Getenv("POLAR_HOSTED_ORIGIN"),
        Products:     map[string]string{"pro": os.Getenv("POLAR_PRO_PRODUCT_ID")},
        SuccessURL:   "/billing/success?checkout_id={CHECKOUT_ID}",
        ReturnURL:    "/billing",
    },
    Webhooks: &polar.WebhookOptions{Secret: os.Getenv("POLAR_WEBHOOK_SECRET")},
})
if err != nil {
    return err
}
opts.Plugins = append(opts.Plugins, billing.Plugin())
```

`Client` and `OrganizationID` are always required, where another runtime needs only the client: every checkout and delivery is checked against the merchant organization. Each section enables one part, as another runtime composes its checkout, portal and webhook parts around one client: `Checkout` mounts `POST /checkout`, `Webhooks` mounts `POST /polar/webhooks`, and `Portal` mounts the portal and customer-state routes. A nil section mounts nothing, and every section needs the `Ledger`. A node with only `Webhooks` still completes the checkouts other nodes reserved on the same ledger; without `Checkout` it has no hosted origin to compare, so it checks a checkout URL's shape alone, and the checkout route checks the exact origin again before handing a stored URL out. `ReconcileCheckout` needs `Checkout`. [Section tests](../integrations/polar/checkout_test.go)

For sandbox requests, also pass `polargo.WithServer(polargo.ServerSandbox)`. `OpenLedger` initializes two tables and can run again after restart. All serving replicas must use the same ledger. It stores provider checkout IDs, the hosted URLs, hashed contact bindings, reservation states and delivery fingerprints. Protect this database as you would the auth database. The module pins the official Go SDK and sends `Polar-Version: 2026-10` on requests. [Polar checkout API](https://polar.sh/docs/api-reference/2026-10/checkouts/create-checkout-session) · [API versioning](https://polar.sh/docs/api-reference/versioning)

## Open a checkout

Post to `/api/auth/checkout` with a configured `slug`, a configured product ID in `products`, or a one-element array in `products`. The server takes the customer’s external ID and verified email from the session, and the redirect destinations from the server configuration. A successful response contains `url` and `redirect`. The optional boolean `redirect` defaults to true.

```js
// Persist this ID with the purchase action when retries must survive a page reload.
const purchaseID = crypto.randomUUID();
async function checkout() {
  const response = await fetch("/api/auth/checkout", {
    method: "POST",
    credentials: "same-origin",
    headers: {"Content-Type": "application/json", "Idempotency-Key": purchaseID},
    body: JSON.stringify({slug: "pro"}),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.code);
  if (result.redirect) window.location.assign(result.url);
}
```

Reuse the same `Idempotency-Key` for every retry of a purchase. Each owner has an independent key space. A changed product, contact email or callback configuration conflicts with the original reservation. Without a key, the integration uses a stable owner/product reservation. Supply a fresh explicit key for a deliberate subsequent purchase after the earlier checkout has completed, failed or expired.

Plain Auth commits the reservation before asking Polar to create a checkout. Only one request sends that POST, including across processes. A lost response returns `409 POLAR_CHECKOUT_PENDING`. A verified checkout event can complete the reservation. An operator who knows the checkout UUID can also call `billing.ReconcileCheckout(ctx, checkoutID)`. This reads Polar’s checkout and validates the merchant, customer, product, destinations and server-generated attempt metadata. The original owner can then retry the same request to obtain an open checkout’s URL. If a process dies before sending the request, a pending reservation may have no remote counterpart. Confirm its absence with the merchant before starting a new purchase. Digests and reservation records survive restart.

## Receive verified deliveries

Configure a Polar webhook endpoint at `/api/auth/polar/webhooks` with raw JSON, API version `2026-10`, and checkout created, updated and expired events. Use the dashboard secret as supplied. For secrets created before September 8, 2026 at 00:00 UTC, set `LegacySecret: true` on `polar.WebhookOptions`. The default uses the Standard Webhooks key format. Verification covers the raw body, delivery ID and timestamp, with five minutes of clock tolerance. [Polar webhook delivery](https://polar.sh/docs/integrate/webhooks/delivery) · [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks)

`WebhookOptions.OnEvent(ctx, event)` receives every verified delivery, where another runtime offers a catch-all handler plus one handler per event type: switch on `event.Type`. It runs once the integration has recorded its own checkout state, never inside a store transaction or while a ledger lock is held, so a handler failure never undoes a recorded checkout. `Body` holds the verified request body, `Timestamp` the payload's timestamp, and `DeliveryID` the `webhook-id` header Polar repeats on every retry. Keep `Body` out of logs: a checkout body carries its client secret and hosted URL, and customer bodies carry personal data.

`Purchase` is set on a checkout event for a checkout this installation reserved when the reservation holds exactly that delivery's state; another runtime has no equivalent. Separate deliveries can carry the same state, so fulfil once per `Purchase.CheckoutID` and `Purchase.Status`, and order states by `Purchase.Changed`, never moving away from succeeded, expired or failed. A stale or replayed state after a newer one has no `Purchase`. A retry, a concurrent copy or a replay inside the five-minute signature window runs `OnEvent` again, as in another runtime, so key other effects on `DeliveryID`. Polar retries a failed delivery for a limited time only.

An error or panic from `OnEvent` answers 400 `POLAR_WEBHOOK_ERROR` "Webhook error: See server logs for more information." so Polar retries, as in another runtime, and logs only the delivery ID and type, where another runtime logs the error: a host error can carry payload data, so log your own. A delivery whose type, API version or data the integration does not use still reaches `OnEvent` with `Body` and answers 200 unless the handler fails. Checkout events still need API version `2026-10` and a valid payload, and a reserved checkout that conflicts with its reservation answers 409, before any handler runs. Without `OnEvent`, a verified delivery answers 200. The ledger still applies each delivery at most once; stale updates cannot reopen a closed checkout. [Event handler tests](../integrations/polar/webhook_test.go) · [Checkout delivery tests](../integrations/polar/checkout_test.go)

### Use typed events

`Event` also carries the decoded object for the delivery's type, at most one field, when the delivery's API version is `2026-10`, the pinned SDK defines its type and its decoder accepts the data:

```go
OnEvent: func(ctx context.Context, e polar.Event) error {
    switch e.Type {
    case components.WebhookEventTypeOrderPaid:
        if e.Order == nil {
            return errors.New("undecodable order") // Polar retries
        }
        return recordPaidOrder(ctx, e.DeliveryID, e.Order)
    case components.WebhookEventTypeCustomerStateChanged:
        return refreshEntitlements(ctx, e.CustomerState, e.Body)
    }
    if p := e.Purchase; p != nil {
        return fulfil(ctx, p.CheckoutID, p.Status, p.Changed)
    }
    return nil
}
```

| Another runtime's handler | `Type` | Field |
| --- | --- | --- |
| `onPayload` | any | `Body`, plus the typed field when set |
| `onCheckoutCreated`, `onCheckoutUpdated` | `checkout.created`, `checkout.updated` | `Checkout`, plus `Purchase` |
| `onOrderCreated`, `onOrderPaid`, `onOrderRefunded` | `order.created`, `order.paid`, `order.refunded` | `Order` |
| `onRefundCreated`, `onRefundUpdated` | `refund.created`, `refund.updated` | `Refund` |
| `onSubscriptionCreated`, `onSubscriptionUpdated`, `onSubscriptionActive`, `onSubscriptionCanceled`, `onSubscriptionRevoked`, `onSubscriptionUncanceled` | `subscription.created` … `subscription.uncanceled` | `Subscription` |
| `onProductCreated`, `onProductUpdated` | `product.created`, `product.updated` | `Product` |
| `onOrganizationUpdated` | `organization.updated` | `Organization` |
| `onBenefitCreated`, `onBenefitUpdated` | `benefit.created`, `benefit.updated` | `Benefit` |
| `onBenefitGrantCreated`, `onBenefitGrantUpdated`, `onBenefitGrantRevoked` | `benefit_grant.created`, `.updated`, `.revoked` | `BenefitGrant` |
| `onCustomerCreated`, `onCustomerUpdated`, `onCustomerDeleted` | `customer.created`, `.updated`, `.deleted` | `Customer` |
| `onCustomerStateChanged` | `customer.state_changed` | `CustomerState`, the full provider object, unlike the reduced `GET /customer/state` |
| none listed | `checkout.expired`, `order.updated`, `subscription.past_due`, `benefit_grant.cycled`, `member.*`, `customer_seat.*` | `Checkout`, `Order`, `Subscription`, `BenefitGrant`, `Member`, `CustomerSeat` |

One handler with typed fields replaces another runtime's catch-all handler and its per-type handlers, for simplicity: switch on `Type`. Data the pinned SDK cannot type, such as an undefined type, another API version, data that is not an object, or data its decoder rejects (an unknown enum or union member, or a missing required field), reaches `OnEvent` with `Body` alone and answers 200 unless the handler fails, where another runtime refuses it with 400: a permanent 400 would fail every retry until Polar disables the endpoint, checkout events that complete purchases included. Only the pinned version is typed, since the SDK checks required fields only for members, customers, customer state, benefits and benefit grants, so another version could decode into silently zeroed fields. To be as strict as another runtime, return an error when the field you need is nil. [Typed event tests](../integrations/polar/webhook_test.go)

## Enable the individual customer portal

Add the `Portal` section to `polar.Options`. Supply the exact public URL for this merchant’s portal. Polar's API token needs `customer_sessions:write` to open a portal and `customers:read` or `customers:write` to read customer state. [Create customer session](https://polar.sh/docs/api-reference/2026-10/customer-sessions/create-customer-session) · [Read customer state by external ID](https://polar.sh/docs/api-reference/2026-10/customers/get-customer-state-by-external-id)

```go
Portal: &polar.PortalOptions{
    URL:       "https://polar.sh/your-merchant/portal",
    ReturnURL: "/account",
    Theme:     "dark",
},
```

`ReturnURL` and `Theme` are optional. The return URL must resolve to a trusted application destination. The two theme values are `light` and `dark`. Leaving `Portal` unset disables both routes.

Use a same-origin request to `GET /api/auth/customer/portal` or `POST /api/auth/customer/portal`. POST accepts an optional boolean `redirect` which defaults to true. Both methods return `{url, redirect}`. Navigate to the returned URL to open the customer’s Polar account. Treat it as a credential until Polar’s session expires and keep it out of logs or analytics. GET requests authenticated with a cookie must carry same-origin fetch metadata or a trusted Origin or Referer. A native caller using a configured signed bearer session can send an Authorization header.

Polar selects the customer using the immutable external ID of the signed-in account. Plain Auth verifies the returned individual customer, merchant, session expiry, configured portal path and token before handing out the URL. It rechecks the direct auth session when the provider responds. A completed checkout in this installation is optional for customers already bound to the same merchant and external ID.

The hosted portal covers that customer’s purchases across this Polar merchant. The checkout product allowlist controls new purchases initiated by Plain Auth. Organization customers and caller-supplied customer or merchant selectors are unsupported.

## Read the customer’s billing summary

`GET /api/auth/customer/state` returns the same customer’s merchant-wide `polar.CustomerState`. Its JSON uses Polar's snake-case field names. It includes the customer ID, external ID, merchant organization ID, display name and email. The response also contains three arrays.

| Field | Available properties |
| --- | --- |
| `active_subscriptions` | Subscription ID, product ID, status, current period end and cancellation at period end |
| `granted_benefits` | Grant ID, benefit ID, benefit type and grant timestamp |
| `active_meters` | Meter entry ID, meter ID, consumed units, credited units and balance |

Applications can match a subscription’s `product_id` when granting product-specific access. A grant or meter may span products. The public summary omits customer metadata, subscription custom fields, grant properties, tax details and payment instrument data. A missing Polar customer returns 404 when the provider reports it. Provider failures or a conflicting customer, merchant or session produce a redacted 502. Portal credentials and state responses use `Cache-Control: no-store`. [Customer state](https://polar.sh/docs/integrate/customer-state)

Local tests exercise the official Go SDK with an in-process HTTP transport on SQLite, PostgreSQL and MySQL. End-to-end use of a live merchant dashboard and real payments requires merchant-side verification. Fulfillment of paid orders, refunds, subscription management or listing endpoints, organization billing, signup customer creation, event ingestion, paginated meter reads and embedded checkout remain open.
