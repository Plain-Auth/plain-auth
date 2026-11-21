# Email authentication and sessions

Enable `EmailAndPassword` and mount the auth handler. Paths below are relative to `BasePath`, which defaults to `/api/auth`. Send JSON credential requests with `Content-Type: application/json`. On success, the HTTP handler sets an HTTP-only session cookie.

| Method and path | Use |
| --- | --- |
| `POST /sign-up/email` | Send `name`, `email`, `password`, and an optional `image` |
| `POST /sign-in/email` | Send `email` and `password`. Set `rememberMe` to false for a browser-session cookie |
| `GET /get-session` | Read the current user and session. A signed-out request returns JSON `null` |
| `GET /list-sessions` | List the current user's active sessions with a recently authenticated session |
| `POST /revoke-session` | Send `{"token":"<session token>"}` to revoke one of the user's sessions |
| `POST /revoke-other-sessions` | Revoke every other session for the user |
| `POST /revoke-sessions` | Revoke all of the user's sessions |
| `POST /sign-out` | Revoke the current session and expire its cookies |
| `GET /error` | Display an escaped error description or redirect to the configured application error page |
| `GET /ok` | Check the auth mount |

## Configure the instance

| Option | Meaning |
| --- | --- |
| `Store` | Database adapter shared by concurrent requests |
| `Secrets` | Versioned keys for signing and verification. See [key rotation](environment.md#rotate-signing-keys) |
| `Secret` | Stable secret of at least 32 bytes. Generate one with `go run ./cmd/authctl secret` |
| `BaseURL` | Public HTTP(S) origin of the application. HTTPS enables secure cookies |
| `CookiePrefix` | Defaults to `authn`. Choose a namespace such as `myapp` for session cookies and OAuth state. Give separate auth instances distinct prefixes on a shared host. |
| `BasePath` | Mount path, normally `/api/auth` |
| `TrustedOrigins` | Additional exact origins allowed for browser requests and absolute callbacks |
| `EmailAndPassword` | Enables email sign-up and sign-in. Defaults to false |
| `SessionTTL`, `FreshAge` | Default session lifetime is seven days, freshness window is one day |
| `MinPasswordLength`, `MaxPasswordLength` | Default range is 8–128 UTF-16 code units, matching the JavaScript length convention |
| `RateLimit` | Optional boolean override. See [environment precedence](environment.md) for production and HTTPS defaults |
| `Plugins` | Optional extensions registered at startup |

Create one auth instance per configuration and share it among handlers. Use the same secret on application replicas. The default in-process rate limiter keys requests by connection peer and route. Behind a reverse proxy, set `Options.ClientIP.TrustedProxies` to its CIDR ranges as `[]netip.Prefix`. Each proxy should append the actual peer to `X-Forwarded-For` or overwrite the configured `ForwardedHeader`. The library follows trusted hops from right to left and uses the first untrusted address. Direct connections use the socket address. Set `ClientIP.IPv6Subnet` to a prefix length to override the default /64 rate-limit scope. Set `ClientIP.DisableTracking` to omit the address from new sessions and disable per-IP limits. See the [proxy and privacy tests](../ip_test.go).

## Set limits for an application

`RateLimitDefault` controls routes without a built-in or plugin rule. `RateLimitRules` overrides all other rules. The most specific match wins. An exact path takes priority over a trailing `/*` pattern. A nil rule exempts a route. The rules apply to HTTP requests.

```go
opts.RateLimitDefault = &stonewrit.RateLimitRule{Max: 100, Window: time.Minute}
opts.RateLimitRules = map[string]*stonewrit.RateLimitRule{
    "/sign-in/*": {Max: 3, Window: 10 * time.Second},
    "/get-session": nil,
}
```

## Share rate limits across replicas

Apply the `rate-limit` [schema profile](schema.md) and set `Options.RateLimitStorage` to the resulting SQL store on each replica. Enable limiting using `Options.RateLimit` or the [production environment setting](environment.md). Each allowed request updates the counter in a transaction. A rejected request receives HTTP 429 and an `X-Retry-After` value in seconds. Storage errors stop the request. From a maintenance job, call `store.PruneRateLimits(ctx, time.Now().Add(-24*time.Hour))` to clear inactive counters. The longest built-in window is one minute. Adjust the retention period if your application configures a longer window. See the [two-instance storage test](../adapters/sqlstore/ratelimit_test.go).

## Browser and server calls

A browser on the same origin automatically sends the cookie to the API. For cross-origin applications, configure an exact trusted origin and credentialed CORS on the host router. A browser's own SameSite cookie policy still applies. For an authenticated curl POST, send your cookie jar and the configured `Origin`, as in the [quickstart](../README.md#run-it-locally).

The Go methods `SignUpEmail`, `SignInEmail`, `GetSession`, `SignOut`, and the session management methods accept a request context. `GetSession(ctx, headers)` distinguishes an absent session from a storage failure. Use `errors.As(err, &apiErr)` with `var apiErr *stonewrit.APIError` to inspect a public error code and HTTP status. Other errors can carry infrastructure details and belong in application logs.

See the [cross-runtime conformance test](../conformance/core.test.mjs) and [remaining authentication features](parity/authentication.md).

## Examine and unlink sign-in methods

`GET /list-accounts` returns linked account IDs, provider IDs, timestamps, and granted scopes for the current user. Use the returned record's `id` as `accountId` in `POST /unlink-account`. The operation requires a fresh session and preserves the last sign-in method unless the host explicitly sets `AllowUnlinkingAll`. Credentials and provider tokens stay out of the response. See the [account isolation test](../adapters/sqlstore/identity_test.go).

For example, a native sign-in handler can pass an authenticated result’s token to `auth.SessionCookie(result.Token, true)` and write it with `http.SetCookie`. When `result.Challenge` is present, continue the [two-factor flow](2fa.md) before issuing an authenticated cookie. Prefer the mounted sign-in endpoint when you need plugin response headers and cookies as part of the flow.
