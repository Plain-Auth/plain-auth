# Endpoint hooks

Hooks run your code around the mounted HTTP endpoints, so you can adjust one endpoint without writing your own. A before hook can reject a request, rewrite what the endpoint reads, or answer it directly. An after hook can read and replace the endpoint's outcome, read the session it issued and set cookies.

Set `Options.Hooks` for the application. A plugin sets `Plugin.Hooks` to reuse hooks across applications. Options hooks run first, then each plugin's hooks in plugin order.

## Reject or rewrite a request

```go
opts.Hooks = plainauth.EndpointHooks{
    Before: []plainauth.EndpointHook{{
        Match: func(c *plainauth.HookContext) bool { return c.Path == "/sign-up/email" },
        Run: func(c *plainauth.HookContext) error {
            email, _ := c.Body["email"].(string)
            if !strings.HasSuffix(email, "@example.com") {
                return &plainauth.APIError{Status: 400, Code: "BAD_REQUEST", Message: "Email must end with @example.com"}
            }
            if name, ok := c.Body["name"].(string); ok {
                c.Body["name"] = strings.TrimSpace(name)
            }
            return nil
        },
    }},
}
```

`Match` selects the endpoints a hook runs for; leave it nil to run for every endpoint. `Path` is the route relative to the auth mount, with `:name` segments such as `/reset-password/:token` or `/callback/:id`; `Params` holds their values.

A before hook runs after the request passes disabled paths, rate limits, the origin check and body decoding. Requests rejected by those checks run no hooks.

- **Reject:** return an error. It is written as the response and neither the endpoint nor the after hooks run.
- **Rewrite:** edit `c.Body`, `c.Request.Header` or the query in `c.Request.URL`. `c.Request` is a copy, so the host's request is never changed. The endpoint checks rewritten input like caller input, so a bad value gets `400 VALIDATION_ERROR`, and callback URLs are checked again against the trusted origins.
- **Answer:** call `c.Respond(result)`. The remaining before hooks, the endpoint and the after hooks are skipped. A result is written as JSON unless it is a `plainauth.Redirect`, `HTMLPage`, `XMLDocument` or `EmptyResponse`.

```go
c.Respond(map[string]any{"message": "Hello World"})
c.Respond(plainauth.Redirect("/sign-up/name"))
```

Use `c.Redirect(callback)` instead of a literal `Redirect` when the target comes from the request; it checks the target against the trusted origins.

## Read or replace the outcome

```go
opts.Hooks.After = []plainauth.EndpointHook{{
    Run: func(c *plainauth.HookContext) error {
        switch {
        case strings.HasPrefix(c.Path, "/sign-up"):
            // Send a welcome notification.
        case c.Path == "/sign-in/email" && c.Err != nil:
            // Count a failed sign-in.
        }
        return nil
    },
}}
```

After hooks run once the endpoint returns, before the response is written.

- **`c.Result` and `c.Err`** hold the outcome so far: the endpoint's value or its error, as changed by earlier after hooks. Assign either to replace it.
- **Returned errors:** an `APIError` or `OAuthError` replaces the outcome, and the remaining after hooks still run and see it.
- **Status:** the response uses the final error's status, or the endpoint's success status.
- **`c.ResponseHeader`** holds the headers set so far by the endpoint and earlier hooks, including its `Set-Cookie` lines. Add headers there.

An endpoint error that is not an `APIError` or `OAuthError` ends the request with a 500 before any after hook runs.

## Read the new session

```go
opts.Hooks.After = []plainauth.EndpointHook{{
    Match: func(c *plainauth.HookContext) bool { return strings.HasPrefix(c.Path, "/sign-up") },
    Run: func(c *plainauth.HookContext) error {
        session, err := c.NewSession()
        if err != nil || session == nil {
            return err
        }
        notify("user-register", session.User.Name)
        return nil
    },
}}
```

`c.NewSession()` returns the session whose cookie this response issues, with its user, or nil when it issues none, for example after a failed sign-in or a sign-out.

An after hook that turns a successful sign-in into an error should call `c.DeleteSessionCookie()`. It drops the session cookies the response would issue and expires the browser's session cookies instead, so the error response signs nobody in.

## Set and read cookies

```go
c.SetCookie(c.Auth.SignedCookie("theme", "dark", 3600))
theme, ok := c.Auth.SignedCookieValue(c.Request, "theme")
```

- `c.Auth.Cookie(name, value, maxAge)` builds a cookie with the instance's prefix and attributes: `Path=/`, `HttpOnly`, `SameSite=Lax`, `Secure` for an HTTPS base URL and the shared domain when cross-subdomain cookies are on. `c.Auth.Cookie("session_token", "", 0).Name` is the session cookie's name.
- `c.Auth.SignedCookie` signs the value with the instance secret, in the same format as the session cookie. `c.Auth.SignedCookieValue` verifies it against the current and previous secrets and reports false for a missing or tampered cookie. Hooks never read the secret itself.
- `c.SetCookie` adds the cookie to the response, and `c.Request.Cookie(name)` reads an unsigned one.

## Hash passwords

`c.Auth.HashPassword(ctx, password)` and `c.Auth.VerifyPasswordHash(ctx, hash, password)` use the instance's `Options.PasswordHash` and `Options.PasswordVerify`, or the built-in scrypt format, within the same limit on concurrent hashing as sign-in.

## Plugin middleware, requests and responses

A plugin has three more extension points, which run only for HTTP requests:

```go
plainauth.Plugin{
    ID: "maintenance",
    Middleware: []plainauth.Middleware{{
        Path: "/organization/**",
        Run: func(c *plainauth.HookContext) error {
            c.Respond(plainauth.HTMLPage("<p>Back soon</p>"))
            return nil
        },
    }},
    OnRequest: func(c plainauth.RequestContext) error {
        c.Request.Header.Set("X-Tenant", tenantFor(c.Request.Host))
        return nil
    },
    OnResponse: func(c *plainauth.ResponseContext) {
        c.Header.Set("X-Request-ID", requestID(c.Request))
    },
}
```

- **`Middleware`** runs before the endpoint hooks for routes whose mount-relative path matches `Path`.
  - In a pattern, `*` or `:name` matches one segment and a final `**` matches the rest, so `/**` matches every route.
  - Broader patterns run first: `/**`, then `/x/**`, then `/x/*`, then exact paths. Within a level they run in plugin order.
  - It can reject, rewrite or answer a request like a before hook.
- **`OnRequest`** runs for every mounted request before routing, after the disabled-path check.
  - Return an error to interrupt the request with that error's response.
  - `c.Request` is a copy the hook may edit; header and query changes reach the endpoint. The route is not resolved again.
  - Use `Middleware` with `/**` to answer with something other than an error.
- **`OnResponse`** runs once for every response to a request that passed `OnRequest`, including errors, unknown routes and rate limits, before anything is written. It may change `c.Status`, `c.Header` and `c.Body`.
  - When any plugin sets `OnResponse`, responses are buffered until the hooks finish.
  - Every plugin's `OnResponse` runs, in plugin order, and each sees the changes of the ones before.

## Errors and panics

Return a `*plainauth.APIError` to choose the status, code and message. Any other error from a hook, and any panic, ends the request with a generic `500 INTERNAL_SERVER_ERROR`. A panic is logged with its source (`user` or `plugin:<id>`) and the route.

## Use the request context

`HookContext` embeds the plugin `EndpointContext`, so a hook has the same helpers as a plugin endpoint:

- `c.Session()` returns the caller's current session, or nil.
- `c.Auth` is the instance, with `Logger`, `PublicURL`, `CallbackURL` and the typed account and session methods.
- `c.Store()` is the configured store.
- `c.RequestMetadata()` is a body-free copy of the request for background work.

Hooks run only for HTTP requests. Direct Go calls such as `Auth.SignUpEmail` run no endpoint hooks; wrap those call sites in your own code.

See the [hook API](../hooks.go), the [middleware API](../middleware.go), the [hook tests](../conformance/goapi/endpoint_hooks_test.go) and the [middleware tests](../conformance/goapi/plugin_middleware_test.go).
