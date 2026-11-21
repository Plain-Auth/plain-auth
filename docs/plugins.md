# Plugins and Stripe

Pass plugins to `authn.Options.Plugins` during startup. A plugin declares an ID and endpoint definitions with a method and a path relative to the auth mount. Registration checks IDs and route conflicts before the application begins serving. Assign an `Endpoint.RateLimit` rule to limit requests to a plugin endpoint. The host application can [override rate rules](authentication.md#set-limits-for-an-application).

## Create a session-aware endpoint

```go
profile := authn.Plugin{
    ID: "profile",
    Endpoints: []authn.Endpoint{{
        Method: http.MethodGet,
        Path:   "/profile",
        Handler: func(c authn.EndpointContext) (any, error) {
            session, err := c.Auth.GetSession(c.Request.Context(), c.Request.Header)
            if err != nil {
                return nil, err
            }
            if session == nil {
                return nil, &authn.APIError{
                    Status: 401, Code: "UNAUTHORIZED", Message: "Sign in first",
                }
            }
            return session.User, nil
        },
    }},
}
opts.Plugins = []authn.Plugin{profile}
```

The handler is then available at `GET /api/auth/profile`. Endpoint handlers run concurrently. Synchronize state they share or persist it in a transactional store. See the [plugin API](../plugins.go) and [registration tests](../plugins_test.go).

## Receive Stripe webhooks

Import `github.com/nabuhadba/go-better-auth/plugins/stripe` as `authstripe` and the official `github.com/stripe/stripe-go/v87` as `stripesdk`.

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

Register `bearer.New(bearer.Options{RequireSignature: true})` from `plugins/bearer` in `Options.Plugins`. After sign-in, read the signed credential from the `Set-Auth-Token` response header. Send it on subsequent requests as `Authorization: Bearer <value>`. Treat it as a credential. Session lookup checks expiry and revocation on each request. With the default `RequireSignature: false` setting the raw session token in the JSON response is also accepted. See the [bearer flow test](../plugins/bearer/bearer_test.go).

## Remember the last sign-in method

Register `lastlogin.New(lastlogin.Options{})` from `plugins/lastlogin` to set a browser-readable login-method cookie when the session cookie is issued. The default lifetime is 30 days. Configure `CookieName`, `MaxAge`, or `Resolve` for your application. Set `Allow` to check user consent before storing the preference. See the [consent and cookie test](../plugins/lastlogin/lastlogin_test.go).

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
view, err := customsession.New(func(c authn.EndpointContext, data authn.SessionResult) (any, error) {
    return map[string]string{"viewer": data.User.ID, "displayName": data.User.Name}, nil
})
if err != nil {
    return err
}
opts.Plugins = append(opts.Plugins, view)
```

Anonymous requests return JSON `null`. The core completes session validation and handles renewal cookies before returning the view. Direct Go authorization checks through `auth.GetSession` continue to receive the typed user and session. A native HTTP client expecting this custom JSON should call `client.Do` with an output struct matching the configured view. [Integration tests](../plugins/customsession/customsession_test.go)
