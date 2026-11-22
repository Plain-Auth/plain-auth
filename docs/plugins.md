# Plugins and Stripe

Pass plugins to `plainauth.Options.Plugins` during startup. A plugin declares an ID and endpoint definitions with a method and a path relative to the auth mount. Registration checks IDs and route conflicts before the application begins serving. Assign an `Endpoint.RateLimit` rule to limit requests to a plugin endpoint. The host application can [override rate rules](authentication.md#set-limits-for-an-application).

The i18n plugin localizes coded errors from core and plugin endpoints. [Localization guide](localization.md)

The OpenAPI plugin publishes a machine-readable schema and a local API reference for installed endpoints. [OpenAPI guide](openapi.md)

The SCIM handler wraps the auth handler and serves directory provisioning under its existing mount. [SCIM directory provisioning](scim.md)

The phone-number plugin supports verified numbers, account linking, sign-in and password recovery. [Phone-number guide](phone-number.md)

Plugins can write structured records through `c.Auth.Logger()`. [Configure instance logging](environment.md#route-authentication-logs)

## Create a session-aware endpoint

```go
profile := plainauth.Plugin{
    ID: "profile",
    Endpoints: []plainauth.Endpoint{{
        Method: http.MethodGet,
        Path:   "/profile",
        Handler: func(c plainauth.EndpointContext) (any, error) {
            session, err := c.Auth.GetSession(c.Request.Context(), c.Request.Header)
            if err != nil {
                return nil, err
            }
            if session == nil {
                return nil, &plainauth.APIError{
                    Status: 401, Code: "UNAUTHORIZED", Message: "Sign in first",
                }
            }
            return session.User, nil
        },
    }},
}
opts.Plugins = []plainauth.Plugin{profile}
```

The handler is then available at `GET /api/auth/profile`. Endpoint handlers run concurrently. Synchronize state they share or persist it in a transactional store. See the [plugin API](../plugins.go) and [registration tests](../plugins_test.go).

## Receive Stripe webhooks

Import `github.com/Plain-Auth/plain-auth/plugins/stripe` as `authstripe` and the official `github.com/stripe/stripe-go/v87` as `stripesdk`.

```go
opts.Plugins = append(opts.Plugins, authstripe.New(authstripe.Options{
    WebhookSecret: os.Getenv("STRIPE_WEBHOOK_SECRET"),
    OnEvent: func(ctx context.Context, event stripesdk.Event) error {
        // Record event.ID and the corresponding application update atomically.
        return processStripeEvent(ctx, event)
    },
}))
```

Point the Stripe endpoint at `POST /api/auth/stripe/webhook`. Supply the endpoint's signing secret. The plugin verifies the original request bytes and timestamp with Stripe's Go SDK and calls your function after successful verification. Stripe retries deliveries, so use the event ID for idempotency. Your handler's error produces an unsuccessful response so the event can be retried.

Run `go test ./plugins/stripe` to exercise signed deliveries locally. The [Stripe checklist](parity/plugins/stripe.md) tracks subscription, checkout, billing portal, and customer-management behavior separately.

## Authenticate a Go or mobile client with a bearer token

Register `bearer.New(bearer.Options{RequireSignature: true})` from `plugins/bearer` in `Options.Plugins`. After sign-in, read the signed credential from the `Set-Auth-Token` response header. Send it on subsequent requests as `Authorization: Bearer <value>`. Treat it as a credential. Session lookup checks expiry and revocation on each request. With the default `RequireSignature: false` setting the raw session token in the JSON response is also accepted. The response header contains the signed value with its base64 signature. A client that already holds the percent-encoded signed cookie value can send that form too. A valid bearer selects its own account when the request also includes a different session cookie. An invalid signature leaves an independently valid cookie available. The Go client’s bearer view sends only the bearer credential. [Client setup](client.md#use-a-bearer-token) · [HTTP contract tests](../conformance/bearer-contract.mjs)

For an application-owned route, pass `r.Context()` and `r.Header` to `auth.GetSession`. A missing or revoked session yields a nil result, so the handler can return HTTP 401. A storage error is a separate return value. [Handler example](routers.md#protect-an-application-route) · [TLS application test](../client/bearer_test.go)

## Remember the last sign-in method

Register `lastlogin.New(lastlogin.Options{})` from `plugins/lastlogin` to set a browser-readable login-method cookie when the session cookie is issued. The preference follows the host's cookie namespace. Its default lifetime is 30 days. Configure `CookieName`, `MaxAge`, or `Resolve` for your application. Set `Allow` to check user consent before storing the preference. See the [consent and cookie test](../plugins/lastlogin/lastlogin_test.go).

## Open the user's Stripe billing portal

Enable the `stripe-subscriptions` [schema profile](schema.md), and associate the Stripe customer with the authenticated user's `stripeCustomerId`. The SQL store can also resolve a customer through an owned active or trialing subscription.

Configure the portal when creating the plugin. The application supplies its own Stripe API key.

```go
opts.Plugins = append(opts.Plugins, authstripe.New(authstripe.Options{
    WebhookSecret: os.Getenv("STRIPE_WEBHOOK_SECRET"),
    Portal: &authstripe.PortalOptions{
        Client:    stripesdk.NewClient(os.Getenv("STRIPE_SECRET_KEY")),
        Customers: store,
    },
}))
```

Send an authenticated `POST /api/auth/subscription/billing-portal` with `{"returnUrl":"/account","disableRedirect":true}`. The response contains a Stripe portal URL and the redirect preference. The endpoint resolves the customer using the session owner and accepts return URLs on configured trusted origins. The [portal test](../plugins/stripe/portal_test.go) exercises the real Go SDK with a local transport.

## Return an application-defined session view

Register `customsession.New` from `plugins/customsession` to select the data returned by `GET /get-session`. The function receives the authenticated request context, user, and session. It can perform an application lookup through `c.Request.Context()`.

```go
view, err := customsession.New(func(c plainauth.EndpointContext, data plainauth.SessionResult) (any, error) {
    return map[string]string{"viewer": data.User.ID, "displayName": data.User.Name}, nil
})
if err != nil {
    return err
}
opts.Plugins = append(opts.Plugins, view)
```

The view replaces `GET /get-session`. Anonymous or revoked sessions return JSON `null` and skip the callback. At most one session projection can be installed on a server. Direct Go authorization through `auth.GetSession` returns the live typed identity without invoking the application projection. A native HTTP client reads the projected value with `client.GetSessionView[T](ctx, c)`. [Registration and response tests](../plugins/customsession/customsession_test.go)

The handler commits application response headers only after the projection returns valid JSON. It then forwards the core session headers, including renewal and deletion cookies as separate header entries, and preserves `Cache-Control: no-store` and `Pragma: no-cache`. A lookup failure returns HTTP 500 with `FAILED_TO_GET_SESSION`. An ordinary callback error or JSON encoding error returns a redacted HTTP 500. The public error body may differ between implementations. [Released HTTP comparison](../conformance/custom-session-contract.mjs)

A nonempty `disableRefresh` query skips renewal. Omit the parameter to allow refresh. The string `false` also counts as nonempty. Under `DeferSessionRefresh`, an eligible GET passes `NeedsRefresh` to the callback. Applications choose which fields to expose in their view. The installed custom-session endpoint accepts GET only, including in deferred mode. Use ordinary sliding refresh for projected sessions that need automatic renewal. [Method matrix](../plugins/customsession/customsession_test.go)

With `SessionCookieCache` enabled, the projection can receive the core user and session fields from a verified browser snapshot. A nonempty `disableCookieCache` query forces a live read. Deferred live reads include `NeedsRefresh` when eligible, while cache hits skip renewal. With caching disabled, stale data and its numbered chunks expire on authoritative browser reads. [Browser-cache behavior](authentication.md#browser-session-cache) · [Released projection comparison](../conformance/session-cache-compact.mjs)

To project each entry in a remembered-account list, use `customsession.NewWithOptions` and set `ProjectDeviceSessions` to true. The SQL adapter respects current bans and delegation validity on every listing, including after an administrative schema migration on another instance. A failed list projection returns no partial account data. [SQL visibility tests](../adapters/sqlstore/custom_session_test.go) · [Account switching](multi-session.md#customize-list-entries)

### Persist the last login method

To expose the most recent method across devices, enable the `last-login-method` schema profile and pass the same store to the plugin and auth instance.

```go
ddl, err := schema.Generate("postgres", []string{"last-login-method"})
if err != nil { return err }
store, err := sqlstore.OpenWithSchema(ctx, "postgres", dsn, ddl)
if err != nil { return err }
opts.Store = store
opts.Plugins = append(opts.Plugins, lastlogin.New(lastlogin.Options{Database: store}))
```

A recognized HTTP login that issues a session records the method on its account. Session reads expose it as `user.lastLoginMethod`. The browser preference defaults to `authn.last_used_login_method` and uses the `__Secure-` prefix on HTTPS. The `Allow` callback controls setting the browser cookie. Supplying `Database` independently enables account storage. In the Go client, `LastLoginMethod("")` reads the default browser preference and `ClearLastLoginMethod("")` clears it. Supply the exact cookie name when configuring a custom name or namespace. [Storage tests](../adapters/sqlstore/lastlogin_test.go) · [Native client tests](../client/lastlogin_test.go)

For a browser sign-in page, serve the [preference module](../plugins/lastlogin/browser.mjs) as a static asset. The helper reads the cookie on demand. Clearing the preference preserves the active login.

```js
import { loginPreference } from "/assets/login-preference.mjs";

const preference = loginPreference();
if (preference.is("github")) signInWithGitHubButton.focus();
forgetPreferenceButton.addEventListener("click", () => preference.clear());
```

Use the same cookie name and domain on both sides. For example, a Go plugin configured with `CookieName: "__Secure-staff.preference"` and a shared cookie domain of `example.com` uses `loginPreference({ cookieName: "__Secure-staff.preference", domain: "example.com" })` in the browser. Calling `clear()` removes that preference across participating subdomains and preserves the signed-in session. [Two-host Chrome test](../cookie_scope_browser_test.go)
