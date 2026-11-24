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
auth, err := plainauth.New(opts)
```

If the mount is `/identity`, a request to `/identity/sign-up/email` returns 404 before the handler reads credentials, charges a rate limit or runs a request hook. Query parameters and trailing slashes do not change the selection. Supply concrete paths for individual OAuth callbacks or SCIM resources. A collection entry such as `/scim/v2/Users` leaves individual resources separately addressable. Fixed disabled routes are omitted from the generated OpenAPI document. Native Go methods remain available to the host. [HTTP routing tests](../conformance/goapi/disabled_paths_test.go) · [SCIM tests](../plugins/scim/http_test.go)


## Configure the instance

| Option | Meaning |
| --- | --- |
| `Store` | Database adapter shared by concurrent requests |
| `Secrets` | Versioned keys for signing and verification. See [key rotation](environment.md#rotate-signing-keys) |
| `Secret` | Stable secret of at least 32 bytes. Generate one with `go run ./cmd/authctl secret` |
| `BaseURL` | Public HTTP(S) origin of the application. HTTPS enables secure cookies |
| `CookiePrefix` | Defaults to `authn`. Choose a namespace such as `myapp` for session cookies and OAuth state. Give separate auth instances distinct prefixes on a shared host. |
| `BasePath` | Mount path, normally `/api/auth` |
| `TrustedOrigins` | Additional exact or wildcard HTTP(S) origins, and custom-scheme URLs for apps and extensions, allowed for browser requests and absolute callbacks |
| `EmailAndPassword` | Enables email sign-up and sign-in. Defaults to false |
| `AppName` | Name users see, such as the issuer in authenticator apps. Defaults to `Auth` |
| `SessionTTL`, `FreshAge` | Default session lifetime is seven days, freshness window is one day. Deleting the user, unlinking an account and plugin actions that need a fresh session refuse an older session; a negative `FreshAge` turns the check off |
| `MinPasswordLength`, `MaxPasswordLength` | Default range is 8–128 UTF-16 code units, matching the JavaScript length convention |
| `RateLimit` | Optional boolean override. See [environment precedence](environment.md) for production and HTTPS defaults |
| `Plugins` | Optional extensions registered at startup |
| `SkipTrailingSlashes` | Serves `/sign-in/email/` as `/sign-in/email` |
| `DisableCSRFCheck` | Turns off the Origin, Referer and Fetch Metadata checks on state-changing requests. Leaves cookie-authenticated endpoints open to cross-site request forgery |
| `DisableOriginCheck` | Accepts any `callbackURL`, `redirectTo` and other redirect target instead of trusted origins and relative paths, which allows open redirects. Request origins are still checked, and URLs with control characters or backslashes, or with a scheme that can run code or read local data such as `javascript:`, `data:` or `file:`, are still refused |

Create one auth instance per configuration and share it among handlers. Use the same secret on application replicas.

The default in-process rate limiter keys requests by client address and route. Direct connections use the socket address, and address headers are ignored. Behind a reverse proxy, set `Options.ClientIP.TrustedProxies` to its CIDR ranges as `[]netip.Prefix`. Only those peers may supply an address header.

| How requests reach your server | What to set |
| --- | --- |
| A proxy puts the client address in its own header | `TrustedProxies` and `Headers: []string{"CF-Connecting-IP"}` |
| Proxies append addresses to `X-Forwarded-For` | `TrustedProxies` with your proxies' addresses |
| Clients connect directly | Nothing |

`ClientIP.Headers` lists the headers to read, in order, and defaults to `X-Forwarded-For`. The first header that yields an address wins. A proxy must overwrite a single-address header. In a list, trusted hops are skipped from right to left and the first untrusted address is the client. A header that is sent but holds no valid address gives no address, unless a later header has one. Requests without an address share one rate-limit counter per route, and the first one logs a warning.

Set `ClientIP.IPv6Subnet` to a prefix length to override the default /64 rate-limit scope. Set `ClientIP.DisableTracking` to omit the address from new sessions and disable per-IP limits. [Proxy and privacy tests](../ip_test.go) · [Address header tests](../conformance/goapi/client_address_test.go)

### Set email registration and password length

Set `EmailAndPassword: true` to enable registration and sign-in. Add `DisableSignUp: true` to close public email registration while existing users continue to sign in. With email and password disabled, both operations return HTTP 400.

Use `MinPasswordLength` and `MaxPasswordLength` to change the default bounds of 8 and 128. Both endpoints of the range are inclusive. A character such as 🔑 counts as two UTF-16 code units. Registration, password changes and recovery enforce both limits on new passwords. When you raise the minimum, users with shorter existing passwords can still sign in and choose a replacement. Sign-in also enforces the maximum, so lowering it can require password recovery for an existing account. A rejected replacement leaves the reset link available for another attempt. [Client behavior tests](../conformance/email-password-options.mjs)

## Notify an existing account owner about a sign-up attempt

Set `Options.OnExistingUserSignUp` when `RequireEmailVerification` or `DisableAutoSignIn` is enabled. A valid sign-up attempt for an already registered address returns the submitted public profile with a fresh ID and a null token. When the guest and phone plugins are enabled, both fresh and generated profiles report a regular account with empty phone fields. The observer receives the persisted account owner, including a customer who signed up through a social provider. A new account produces no duplicate notification. With ordinary automatic sign-in, an existing address returns HTTP 422 and the observer does not run.

```go
opts.RequireEmailVerification = true
opts.OnExistingUserSignUp = func(ctx context.Context, owner plainauth.User, request *http.Request) error {
    return notifications.EnqueueExistingSignUp(ctx, owner.ID, owner.Email)
}
```

Plain Auth waits for the observer after the insert attempt has released its transaction. Enqueuing a short notification job keeps delivery latency out of the sign-up request. Each duplicate attempt can emit a notification, including concurrent retries. Observer errors and panics produce a fixed diagnostic and preserve the private response. If the mailbox disappears before it can be read, the observer is skipped.

The callback receives the call’s context and the stored public account fields, including ID, name, email, verification status, image and timestamps. A mounted request supplies a copy of its URL and headers with an empty body. Direct calls to `SignUpEmail` pass a nil request. Third-party stores using this option in protected mode must implement `FindAccountUser(context.Context, string) (plainauth.User, error)` to read the mailbox owner independently of its sign-in methods.

The generated profile already carries the fields that built-in plugins add to a real sign-up, such as the admin role or the two-factor flag. To change its values over HTTP, set `Options.CustomSyntheticUser`. It receives the core fields, the public user fields after defaults and the fresh ID, and returns the values to send. The response reads exactly like a real sign-up: the same public fields in the same order and format. Keys it does not know are dropped, and a field the hook leaves out, or sets to a value that does not fit, keeps its generated value. [Synthetic user tests](../conformance/goapi/synthetic_user_test.go) · [Browser comparison](../conformance/synthetic-user.mjs)

## Use an existing password database

Plain Auth stores a salted scrypt hash on the credential account. The built-in format uses NFKC normalization, a 16-byte random salt encoded as hex, and scrypt with N=16384, r=16, p=1 and a 64-byte key. To use a host-managed format, set `Options.PasswordHash` and `Options.PasswordVerify` before calling `plainauth.New`. Each callback receives the request context. A nil callback uses the built-in implementation for that operation.

For a gradual migration, have your verifier recognize both stored formats. The example assumes the application has a `credentials` service whose encoded hashes start with `v2$`.

```go
opts.PasswordHash = credentials.Hash
opts.PasswordVerify = func(ctx context.Context, encoded, password string) (bool, error) {
    if strings.HasPrefix(encoded, "v2$") {
        return credentials.Verify(ctx, encoded, password)
    }
    return plainauth.VerifyPasswordHash(ctx, encoded, password)
}
```

The hasher must return a nonempty, self-describing encoding and generate a fresh salt for each password. The verifier returns `false, nil` for a wrong password. Return an error when a dependency fails. Ordinary callback errors produce a generic HTTP 500. Registration, administrator password changes, reset and recovery use the same hasher. Email, phone and username sign-in, reauthentication and two-factor management use the same verifier. An unknown login spends one hash operation and discards its output. The instance limits concurrent password operations and honors cancellation while a request waits.

Existing accounts keep their stored credentials until a password-setting operation succeeds. Deploy a verifier that accepts the new format on every replica before switching the hasher. Applications with a custom codec can provision their first administrator through `auth.BootstrapAdmin(ctx, name, email, password)`. The standalone `authctl` command uses the built-in format. [Database lifecycle tests](../adapters/sqlstore/password_codec_test.go) · [Cross-runtime password rotation](../conformance/core.test.mjs)

## Set limits for an application

`RateLimitDefault` controls routes without a built-in or plugin rule. `RateLimitRules` overrides all other rules. The most specific match wins. An exact path takes priority over a trailing `/*` pattern. A nil rule exempts a route. The rules apply to HTTP requests.

```go
opts.RateLimitDefault = &plainauth.RateLimitRule{Max: 100, Window: time.Minute}
opts.RateLimitRules = map[string]*plainauth.RateLimitRule{
    "/sign-in/*": {Max: 3, Window: 10 * time.Second},
    "/get-session": nil,
}
```

Sign-in, sign-up, password and email change and two-factor routes have a built-in rule of 3 requests per 10 seconds, and password reset and verification email requests 3 per minute. To choose a limit per request, put a function in `RateLimitRuleFuncs` under the same kind of pattern. It receives the request and the route's plugin, built-in or default rule, and returns the rule to use, or nil to not limit the request. The closest entry in either map wins, so a function for `/sign-in/email` replaces a `/sign-in/*` rule entirely, and returning `current` then applies the built-in rule. A route can appear in only one of the two maps. A function that panics or returns a rule without a positive maximum and window keeps the rule it received.

```go
opts.RateLimitRuleFuncs = map[string]plainauth.RateLimitRuleFunc{
    "/sign-in/*": func(r *http.Request, current plainauth.RateLimitRule) *plainauth.RateLimitRule {
        if isTrustedNetwork(r) {
            return nil
        }
        return &current
    },
}
```

IPv6 clients are counted by their /64 network, whatever the spelling of the address. Set `ClientIP.IPv6Subnet` to another prefix length from 0 to 128. [Rate limit tests](../ratelimit_test.go)

## Share rate limits across replicas

For shared counters on Redis or Valkey, configure the optional Redis storage adapter. [Redis secondary storage](redis.md)

Any type with `ConsumeRateLimit(ctx, key, maximum, window, now) (time.Duration, error)` can be `Options.RateLimitStorage`. It must admit one request atomically and return how long the client must wait, or zero; the key is the client address and the route joined by `|`. [Custom storage test](../conformance/goapi/rate_limit_storage_test.go)

Apply the `rate-limit` [schema profile](schema.md) and set `Options.RateLimitStorage` to the resulting SQL store on each replica. Enable limiting using `Options.RateLimit` or the [production environment setting](environment.md). Each allowed request updates the counter in a transaction. A rejected request receives HTTP 429 and an `X-Retry-After` value in seconds. Storage errors stop the request. From a maintenance job, call `store.PruneRateLimits(ctx, time.Now().Add(-24*time.Hour))` to clear inactive counters. The longest built-in window is one minute. Adjust the retention period if your application configures a longer window. See the [two-instance storage test](../adapters/sqlstore/ratelimit_test.go).

## Browser and server calls

A browser on the same origin automatically sends the cookie to the API. For cross-origin applications, configure an exact trusted origin and credentialed CORS on the host router. A browser's own SameSite cookie policy still applies. For an authenticated curl POST, send your cookie jar and the configured `Origin`, as in the [quickstart](../README.md#quickstart).

### Trust a set of application hosts

Keep `BaseURL` on the public auth server. Add origins for sites you control to `Options.TrustedOrigins` or the comma-separated `AUTH_TRUSTED_ORIGINS` environment variable. The same rules authorize a browser's origin for cookie-authenticated mutations and the application destination for an absolute callback URL. The OAuth provider continues to send its authorization response to the callback on `BaseURL`.

| Rule | Admitted origins |
| --- | --- |
| `https://*.shop.example.com` | HTTPS subdomains, including `orders.eu.shop.example.com`, on the default port. Add `https://shop.example.com` separately to trust the apex. |
| `https://preview-?.example.com:8443` | One character after `preview-` and port 8443. |
| `*.dev.example.com` | HTTP or HTTPS subdomains on each scheme's default port. |
| `http://192.168.*.*:*` | Valid IPv4 addresses in that range on a nondefault port. |

An asterisk matches zero or more hostname characters, including dots. A question mark matches one character. Apply those characters separately to the ASCII hostname and the optional port. Use the ASCII Punycode spelling for internationalized domains: a URL whose host holds non-ASCII characters is never trusted, because a browser visits its Punycode form. A literal default port is equivalent to omitting it. Specify a port or a port pattern to admit a nondefault port. A port wildcard matches the port present after default-port normalization. Callback paths, queries and fragments are preserved. An HTTP(S) trust rule contains only the scheme and authority, or a hostname wildcard with an optional port. [Native validation](../conformance/goapi/trusted_origins_test.go) · [HTTP comparison](../conformance/trusted-origins.mjs)

### Trust app deep links and extensions

A native app or browser extension receives its callbacks on a custom scheme. List it with that scheme:

| Rule | Admitted URLs |
| --- | --- |
| `myapp://` | Any `myapp://` URL. |
| `acme://app/auth` | `acme://app/auth` and paths below it, such as `acme://app/auth/done`. |
| `chrome-extension://abcdefghijklmnop` | Pages of that one extension. |
| `exp://192.168.*.*:*/**` | Expo development URLs on any local IPv4 address, port and path. |

In a custom-scheme rule, `*` and `?` match within the authority, including dots and colons, and within a path segment, and a `**` segment matches any number of segments. A numeric wildcard host matches IPv4 addresses only. A URL whose path holds an encoded slash or backslash, or a `.` or `..` segment, is refused, since an app may resolve it to another route; the query and fragment are ignored. A wildcard without a scheme, such as `*.example.com`, still admits HTTP(S) only, so every custom scheme must be named. Schemes that can run code or read local data, such as `javascript:`, `data:`, `file:` and `blob:`, are refused at startup. A trusted extension origin passes the origin check of a cookie-authenticated request, while One Tap, popups and the OAuth proxy accept only web origins.

Any app on a device can register a custom scheme, so a deep link can reach an app other than yours, together with any token in it, such as a password reset link. Prefer a claimed HTTPS link (an Android App Link or an iOS Universal Link) where the platform offers one.

### Share a session across subdomains

Cookies are host-only by default. To share a login from `auth.example.com` with `app.example.com`, use a parent domain that you control and explicitly trust the application origin for browser requests.

```go
opts.BaseURL = "https://auth.example.com"
opts.CrossSubDomainCookies = &plainauth.CrossSubDomainCookiesOptions{Domain: "example.com"}
opts.TrustedOrigins = []string{"https://app.example.com"}
```

An empty `Domain` inside the options uses the exact hostname from `BaseURL`. A domain cookie reaches that host and its descendants. Set the narrowest domain whose subdomains you control. Startup validates the domain against the base host and the public suffix list, including private hosting suffixes.

HTTPS enables `Secure` by default. `UseSecureCookies` accepts a boolean pointer to override that setting. A `__Secure-` prefix requires secure cookies. A `__Host-` prefix also requires host-only scope and a root path. The HTTPS One Tap nonce always uses this host-only scope.

### Rename cookies and change their attributes

```go
opts.DefaultCookieAttributes = plainauth.CookieAttributes{SameSite: http.SameSiteNoneMode, Partitioned: true}
opts.Cookies = map[string]plainauth.CookieOptions{
    "session_token": {Name: "app_session", Attributes: plainauth.CookieAttributes{Path: "/api"}},
}
```

Every cookie starts as `Path=/`, `HttpOnly`, `SameSite=Lax`, `Secure` for an HTTPS base URL and the shared domain with cross-subdomain cookies. `DefaultCookieAttributes` changes all of them, then `Cookies` overrides one cookie by its base name, such as `session_token`, `session_data`, `dont_remember`, `two_factor` or `trust_device`. A custom `Name` replaces the prefixed name, and Secure cookies still get the `__Secure-` prefix. Zero fields keep the default.

A few cookies keep fixed rules. `admin_session`, the multi-session cookies and the last-login preference take the `session_token` attributes, so set those instead. The preference always uses `Path=/` so every page can read and clear it. On HTTPS the One Tap nonce stays a host-only `__Host-` cookie with `Path=/`.

Startup refuses a configuration a browser would reject or that would hide a cookie from the auth endpoints:
- an invalid name, or two cookies sharing one name;
- `SameSite=None` or `Partitioned` without `Secure`;
- a `__Host-` cookie with a domain or another path;
- a `Path` that does not cover the base path, such as `/app` when the endpoints live under `/api/auth`;
- a `Domain` outside the base host or on a public suffix, using the same checks as `CrossSubDomainCookies`.

When you move a cookie to a new `Domain`, `Path` or partition, the browser keeps its old copy as a separate cookie. When a request still carries one, the response that replaces or expires the cookie also expires the old host-only, `Path=/` or unpartitioned copy.

[Cookie option tests](../conformance/goapi/cookie_options_test.go) · [Write, expiry and old-scope tests](../cookies_test.go)

Signing out clears the shared session cookies across eligible hosts and revokes the active session. During a move from host-only cookies, issue a fresh login on the original host to replace its previous browser credential. Each host controls its own older host-only cookies. The login-method preference persists across logout. In the Go client, call `ClearSharedLastLoginMethod(cookieName, domain)` to remove that preference. [Cookie scope tests](../conformance/goapi/cookie_scope_http_test.go)

With the browser cache disabled (the default), `GET /get-session` expires the cache cookie and any numbered chunks in this instance’s namespace. With a shared domain, the response also removes host-only copies that the browser sent. The store supplies the current session. [Session cache cleanup tests](../conformance/session-cache-cleanup.mjs)

### Browser session cache

To cache the public session view on the browser, set the option before constructing the handler.

```go
opts.SessionCookieCache = &plainauth.SessionCookieCacheOptions{
    Strategy: plainauth.SessionCacheJWE,
    MaxAge:   5 * time.Minute,
    Version:  "1",
}
```

| Strategy | How it protects the snapshot | Browser-only login |
| --- | --- | --- |
| `SessionCacheCompact` (default) | HMAC-SHA256 over compact JSON. A cookie holder can read the session fields. | 1 minute |
| `SessionCacheJWT` | HS256-signed JWT. A cookie holder can read the session fields. | 5 minutes |
| `SessionCacheJWE` | Direct symmetric JWE using A256CBC-HS512. A cookie holder needs the derived key to read the session fields. | 5 minutes |

The Go handler validates the selected strategy at startup. A matching signed session cookie and a valid, unexpired snapshot let `GET /get-session` return the core user and session fields saved at issuance. With deferred session refresh enabled, the ordinary `POST /get-session` also accepts cached views. Add `disableCookieCache=true` on either method to read the store. A deferred POST then renews a due session unless a nonempty `disableRefresh` suppresses renewal.

Each cache contains a session token. The browser cookie is HTTP-only and inherits the configured secure and domain settings. Persistent logins use `MaxAge`, which defaults to five minutes. Browser-only logins omit the cookie’s `Max-Age` and use the fixed lifetimes above. Long profiles split across at most 100 cookies of at most 4,050 bytes each. Larger profiles use a live read. Logout and size changes retire obsolete copies. [Cookie exchange, expiry and logout tests](../conformance/session-cache-compact.mjs)

During the cache window, a browser view can show an old profile or a session revoked from another device. Protected endpoints and the native server method `GetSession(ctx, headers)` continue to verify sessions in storage. Administrative stores, delegated sessions, application or bearer credentials and JWT response-header issuance use live reads. Phone number, username, guest and two-factor profiles also stay live, as do application-defined session-read hooks. SQLite, PostgreSQL and MySQL query the physical schema before accepting a cache hit, so another node can enable administrative controls after startup. [Live authorization tests](../adapters/sqlstore/session_cache_test.go)

Configure replicas with the same format, secrets, cookie scope and cache version. `Options.Secrets` issues with the first key and accepts explicitly retained keys for all three formats. JWE derives a separate 512-bit key per application secret with HKDF-SHA256. The protected key ID identifies the derived key by its RFC 7638 thumbprint. Older encrypted snapshots without an ID can use any retained key. A new `Version` invalidates earlier snapshots. Removing an old key invalidates snapshots issued with it. [Rotation, identity binding and algorithm tests](../session_cache_jose_test.go)

During migration between implementations, a reader that checks only its active HS256 secret needs a fresh signed JWT snapshot after rotation. Shared-key JWE readers can identify snapshots from a retained key. [Cross-runtime rollover tests](../conformance/session-cache-compact.mjs)

For per-user invalidation, supply a concurrency-safe `VersionFor` callback and use the same revision source on every replica. Choose either a fixed `Version` or `VersionFor`. The callback receives the request context and the session and user that will be written or read. For example, an application can keep a per-account revision in its own store.

```go
opts.SessionCookieCache = &plainauth.SessionCookieCacheOptions{
    Strategy: plainauth.SessionCacheJWE,
    VersionFor: func(ctx context.Context, session plainauth.Session, user plainauth.User) (string, error) {
        return accountRevisions.Lookup(ctx, user.ID)
    },
}
```

On a cache hit, the callback receives the authenticated snapshot. Plain Auth checks the signature, expiry, ordinary profile fields and session-token binding before passing snapshot data to the callback. An update to a profile in storage therefore becomes visible after the shared revision changes, the snapshot expires, or the caller requests a live read. When the versions differ, Plain Auth reads the session from storage and computes the replacement version using the live data. Return a stable, nonempty revision. An empty stored revision is read as `"1"`, so a callback that always returns an empty string causes a live lookup on every read. [Public client and replica tests](../conformance/session-cache-version.mjs)

A callback error on a session view fails the request. If a version mismatch is already known, the response clears the stale snapshot even when preparing the replacement fails. The combination `disableCookieCache=true&disableRefresh=true` skips cache reads and writes. Native authorization, protected operations, and administrative or JWT-issuing reads use live identity. Give the callback a bounded lookup and keep it free of side effects. Concurrent registration attempts can prepare a version before storage chooses the successful registration. Private duplicate registration and password recovery keep their account observers and skip cache versioning until a session is actually issued. A failed version lookup during new email registration leaves the address available to retry. If the stored profile changes before publication, the browser receives its session credential and the next live view computes a version from the updated profile. [Callback tests](../session_cache_version_test.go) · [Live authorization tests](../adapters/sqlstore/session_cache_test.go)

Custom stores can implement `plainauth.SessionCacheStore` to permit cached views when current access rules allow them. Other stores use live reads. The expiry and version are fixed for each snapshot. Rolling cache renewal, JWKS-backed public verification of browser snapshots, and global partitioned-cookie defaults remain open.

The Go methods `SignUpEmail`, `SignInEmail`, `GetSession`, `SignOut`, and the session management methods accept a request context. `GetSession(ctx, headers)` distinguishes an absent session from a storage failure. Use `errors.As(err, &apiErr)` with `var apiErr *plainauth.APIError` to inspect a public error code and HTTP status. Other errors can carry infrastructure details and belong in application logs.

See the [cross-runtime conformance test](../conformance/core.test.mjs) and [remaining authentication features](parity/authentication.md).

## Examine and unlink sign-in methods

`GET /list-accounts` returns linked account IDs, provider IDs, timestamps, and granted scopes for the current user. Use the returned record's `id` as `accountId` in `POST /unlink-account`. The operation requires a fresh session and preserves the last sign-in method unless the host explicitly sets `AllowUnlinkingAll`. Credentials and provider tokens stay out of the response. See the [account isolation test](../adapters/sqlstore/identity_test.go).

For example, a native sign-in handler can pass an authenticated result’s token to `auth.SessionCookie(result.Token, true)` and write it with `http.SetCookie`. When `result.Challenge` is present, continue the [two-factor flow](2fa.md) before issuing an authenticated cookie. Prefer the mounted sign-in endpoint when you need plugin response headers and cookies as part of the flow.
