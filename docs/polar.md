# Polar hosted checkout

Use the optional `integrations/polar` Go module to sell a configured product to a signed-in individual. The integration opens a Polar checkout and records its lifecycle from verified deliveries. It requires a direct session and a verified email address. Guest accounts, application-key sessions and administrator impersonation cannot open a checkout.

## Configure the integration

Use an organization access token for the Polar merchant, the merchant’s organization UUID, a configured product UUID, and the exact HTTPS origin of its hosted checkouts. Keep production and sandbox credentials, webhook secrets and products together. The auth database can be SQLite, PostgreSQL or MySQL.

```go
import (
    "net/http"
    "os"
    "time"

    "github.com/Stonewrit/stonewrit-auth/integrations/polar"
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
    Client: sdk,
    Ledger: ledger,
    OrganizationID: os.Getenv("POLAR_ORGANIZATION_ID"),
    HostedOrigin: os.Getenv("POLAR_HOSTED_ORIGIN"),
    Products: map[string]string{"pro": os.Getenv("POLAR_PRO_PRODUCT_ID")},
    SuccessURL: "/billing/success?checkout_id={CHECKOUT_ID}",
    ReturnURL: "/billing",
    WebhookSecret: os.Getenv("POLAR_WEBHOOK_SECRET"),
})
if err != nil {
    return err
}
opts.Plugins = append(opts.Plugins, billing.Plugin())
```

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

StoneWrit commits the reservation before asking Polar to create a checkout. Only one request sends that POST, including across processes. A lost response returns `409 POLAR_CHECKOUT_PENDING`. A verified checkout event can complete the reservation. An operator who knows the checkout UUID can also call `billing.ReconcileCheckout(ctx, checkoutID)`. This reads Polar’s checkout and validates the merchant, customer, product, destinations and server-generated attempt metadata. The original owner can then retry the same request to obtain an open checkout’s URL. If a process dies before sending the request, a pending reservation may have no remote counterpart. Confirm its absence with the merchant before starting a new purchase. Digests and reservation records survive restart.

## Receive verified deliveries

Configure a Polar webhook endpoint at `/api/auth/polar/webhooks` with raw JSON, API version `2026-10`, and checkout created, updated and expired events. Use the dashboard secret as supplied. For secrets created before September 8, 2026 at 00:00 UTC, set `LegacySecret: true`. The default uses the Standard Webhooks key format. Verification covers the raw body, delivery ID and timestamp, with five minutes of clock tolerance. [Polar webhook delivery](https://polar.sh/docs/integrate/webhooks/delivery) · [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks)

`OnCheckout(ctx, tx, event)` receives a typed checkout transition bound to a locally reserved purchase. The delivery receipt, checkout state and callback’s SQL writes commit together. Return an error to roll back and allow Polar to retry. For external work, insert a job in an application outbox through the supplied transaction. Separate provider events have separate delivery IDs. Duplicate deliveries have one effect, and stale updates cannot reopen a closed checkout. Verified events outside the supported checkout types are acknowledged without invoking the callback.

A successful checkout is distinct from an order-paid event. This integration covers hosted personal checkout. Payment fulfillment, refunds, subscriptions, organization billing, customer creation on signup, portal access, usage meters and embedded checkout remain outside this release. Local tests exercise the official Go SDK with an in-process HTTP transport on all three SQL engines. Live purchases and provider dashboards require merchant-side verification.
