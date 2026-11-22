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

## Disable an HTTP endpoint

Set `Options.DisabledPaths` to a list of exact paths relative to your auth mount. Each entry disables every HTTP method on that path for this instance. For example, the configuration below permits trusted Go code to register accounts while hiding public email registration and username availability.

```go
opts.DisabledPaths = []string{"/sign-up/email", "/is-username-available"}
auth, err := stonewrit.New(opts)
```

If the mount is `/identity`, a request to `/identity/sign-up/email` returns 404 before the handler reads credentials, charges a rate limit or runs a request hook. Query parameters and trailing slashes do not change the selection. Supply concrete paths for individual OAuth callbacks or SCIM resources. A collection entry such as `/scim/v2/Users` leaves individual resources separately addressable. Fixed disabled routes are omitted from the generated OpenAPI document. Native Go methods remain available to the host. [HTTP routing tests](../disabled_paths_test.go) · [SCIM tests](../plugins/scim/http_test.go)


## Configure the instance

| Option | Meaning |
| --- | --- |
| `Store` | Database adapter shared by concurrent requests |
| `Secrets` | Versioned keys for signing and verification. See [key rotation](environment.md#rotate-signing-keys) |
| `Secret` | Stable secret of at least 32 bytes. Generate one with `go run ./cmd/authctl secret` |
| `BaseURL` | Public HTTP(S) origin of the application. HTTPS enables secure cookies |
| `CookiePrefix` | Defaults to `authn`. Choose a namespace such as `myapp` for session cookies and OAuth state. Give separate auth instances distinct prefixes on a shared host. |
| `BasePath` | Mount path, normally `/api/auth` |
| `TrustedOrigins` | Additional exact or wildcard HTTP(S) origins allowed for browser requests and absolute callbacks |
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

For shared counters on Redis or Valkey, configure the optional Redis storage adapter. [Redis secondary storage](redis.md)

Apply the `rate-limit` [schema profile](schema.md) and set `Options.RateLimitStorage` to the resulting SQL store on each replica. Enable limiting using `Options.RateLimit` or the [production environment setting](environment.md). Each allowed request updates the counter in a transaction. A rejected request receives HTTP 429 and an `X-Retry-After` value in seconds. Storage errors stop the request. From a maintenance job, call `store.PruneRateLimits(ctx, time.Now().Add(-24*time.Hour))` to clear inactive counters. The longest built-in window is one minute. Adjust the retention period if your application configures a longer window. See the [two-instance storage test](../adapters/sqlstore/ratelimit_test.go).

## Browser and server calls

A browser on the same origin automatically sends the cookie to the API. For cross-origin applications, configure an exact trusted origin and credentialed CORS on the host router. A browser's own SameSite cookie policy still applies. For an authenticated curl POST, send your cookie jar and the configured `Origin`, as in the [quickstart](../README.md#run-it-locally).

### Trust a set of application hosts

Keep `BaseURL` on the public auth server. Add origins for sites you control to `Options.TrustedOrigins` or the comma-separated `AUTH_TRUSTED_ORIGINS` environment variable. The same rules authorize a browser's origin for cookie-authenticated mutations and the application destination for an absolute callback URL. The OAuth provider continues to send its authorization response to the callback on `BaseURL`.

| Rule | Admitted origins |
| --- | --- |
| `https://*.shop.example.com` | HTTPS subdomains, including `orders.eu.shop.example.com`, on the default port. Add `https://shop.example.com` separately to trust the apex. |
| `https://preview-?.example.com:8443` | One character after `preview-` and port 8443. |
| `*.dev.example.com` | HTTP or HTTPS subdomains on each scheme's default port. |
| `http://192.168.*.*:*` | Valid IPv4 addresses in that range on a nondefault port. |

An asterisk matches zero or more hostname characters, including dots. A question mark matches one character. Apply those characters separately to the ASCII hostname and the optional port. Use the ASCII Punycode spelling for internationalized domains. A literal default port is equivalent to omitting it. Specify a port or a port pattern to admit a nondefault port. A port wildcard matches the port present after default-port normalization. Callback paths, queries and fragments are preserved. A trust rule contains only the scheme and authority, or a hostname wildcard with an optional port. [Native validation](../trusted_origins_test.go) · [HTTP comparison](../conformance/trusted-origins.mjs)

### Share a session across subdomains

Cookies are host-only by default. To share a login from `auth.example.com` with `app.example.com`, use a parent domain that you control and explicitly trust the application origin for browser requests.

```go
opts.BaseURL = "https://auth.example.com"
opts.CrossSubDomainCookies = &stonewrit.CrossSubDomainCookiesOptions{Domain: "example.com"}
opts.TrustedOrigins = []string{"https://app.example.com"}
```

An empty `Domain` inside the options uses the exact hostname from `BaseURL`. A domain cookie reaches that host and its descendants. Set the narrowest domain whose subdomains you control. Startup validates the domain against the base host and the public suffix list, including private hosting suffixes.

HTTPS enables `Secure` by default. `UseSecureCookies` accepts a boolean pointer to override that setting. A `__Secure-` prefix requires secure cookies. A `__Host-` prefix also requires host-only scope and a root path. The HTTPS One Tap nonce always uses this host-only scope.

Signing out clears the shared session cookies across eligible hosts and revokes the active session. During a move from host-only cookies, issue a fresh login on the original host to replace its previous browser credential. Each host controls its own older host-only cookies. The login-method preference persists across logout. In the Go client, call `ClearSharedLastLoginMethod(cookieName, domain)` to remove that preference. [Cookie scope tests](../cookie_scope_http_test.go)

With the browser cache disabled (the default), `GET /get-session` expires the cache cookie and any numbered chunks in this instance’s namespace. With a shared domain, the response also removes host-only copies that the browser sent. The store supplies the current session. [Session cache cleanup tests](../conformance/session-cache-cleanup.mjs)

### Compact browser session cache

To cache the public session view on the browser, set the option before constructing the handler.

```go
opts.SessionCookieCache = &stonewrit.SessionCookieCacheOptions{
    MaxAge:  5 * time.Minute,
    Version: "1",
}
```

A matching signed session cookie and a valid, unexpired HMAC-SHA256 snapshot let `GET /get-session` return the core user and session fields saved at issuance. With deferred session refresh enabled, the ordinary `POST /get-session` route also accepts cached views. Add `disableCookieCache=true` on either method to consult the store. A deferred POST then renews a due session unless a nonempty `disableRefresh` suppresses renewal. Anyone holding a snapshot can read those fields, including its session token. The browser cookie is HTTP-only and inherits the configured secure and domain settings. The persistent cache defaults to five minutes. A browser-only login receives a cookie without `Max-Age` whose signed contents expire after one minute. Long profiles are split into at most 100 cookies of at most 4,050 bytes each. If the profile exceeds that limit, the browser reads the store. Logout and size changes retire obsolete base or chunk cookies. [Cookie exchange and logout tests](../conformance/session-cache-compact.mjs)

During the cache window, a browser view can show an old profile or a session revoked from another device. Protected endpoints and the native server method `GetSession(ctx, headers)` continue to verify sessions in storage. Administrative stores, delegated sessions, application or bearer credentials and JWT response-header issuance use live reads. Phone number, username, guest and two-factor profiles also stay live, as do application-defined session-read hooks. SQLite, PostgreSQL and MySQL query the physical schema before accepting a cache hit, so another node can enable administrative controls after startup. [Live authorization tests](../adapters/sqlstore/session_cache_test.go)

All replicas that share browser sessions should use the same signing keys, cookie scope and cache version. Change `Version` to reject earlier snapshots. Removing a signing key also invalidates its snapshots. Keep separate deployments on distinct signing keys. You can implement `stonewrit.SessionCacheStore` on a custom store to permit cached views when its current access rules allow them. Stores without this capability use live reads. [Rotation and binding tests](../session_cache_compact_test.go)

This implementation supports the compact format with a fixed version string and fixed expiry. JWT and JWE cache formats, rolling cache renewal, callback-based versions and global partitioned-cookie defaults remain open.

The Go methods `SignUpEmail`, `SignInEmail`, `GetSession`, `SignOut`, and the session management methods accept a request context. `GetSession(ctx, headers)` distinguishes an absent session from a storage failure. Use `errors.As(err, &apiErr)` with `var apiErr *stonewrit.APIError` to inspect a public error code and HTTP status. Other errors can carry infrastructure details and belong in application logs.

See the [cross-runtime conformance test](../conformance/core.test.mjs) and [remaining authentication features](parity/authentication.md).

## Examine and unlink sign-in methods

`GET /list-accounts` returns linked account IDs, provider IDs, timestamps, and granted scopes for the current user. Use the returned record's `id` as `accountId` in `POST /unlink-account`. The operation requires a fresh session and preserves the last sign-in method unless the host explicitly sets `AllowUnlinkingAll`. Credentials and provider tokens stay out of the response. See the [account isolation test](../adapters/sqlstore/identity_test.go).

For example, a native sign-in handler can pass an authenticated result’s token to `auth.SessionCookie(result.Token, true)` and write it with `http.SetCookie`. When `result.Challenge` is present, continue the [two-factor flow](2fa.md) before issuing an authenticated cookie. Prefer the mounted sign-in endpoint when you need plugin response headers and cookies as part of the flow.
