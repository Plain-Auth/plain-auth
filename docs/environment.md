# Environment configuration

The auth instance reads the host process environment once during `plainauth.New`. Environment values take effect when the application constructs a new instance. Set them in your shell, container, hosting dashboard, or secret manager.

## Local development

Use a dedicated local signing secret and the public origin where the example is reachable. From the repository root, run the following in the same shell.

```sh
export "$(go run ./cmd/authctl secret)"
export AUTH_URL=http://127.0.0.1:3000
go run ./examples/basic
```

For a reusable local configuration, run `go run ./cmd/authctl init --url http://127.0.0.1:3000`. It creates a private `.env` with a random secret. Use `--env-file` to choose the destination. An existing file is preserved. See [.env.example](../.env.example) for optional settings. In sh, bash, or zsh, load your own shell-compatible file before starting the application.

```sh
set -a
. ./.env
set +a
go run ./examples/basic
```

This keeps file loading under the host application's control. The example listens on loopback port 3000. `AUTH_URL` configures public URLs and cookie security. The host still chooses which address to listen on.

## Library settings and precedence

| Environment variable | Behavior |
| --- | --- |
| `AUTH_SECRET` | Supplies the signing secret when `Options.Secret` is empty. Use at least 32 random bytes. |
| `AUTH_SECRETS` | Supplies an ordered signing-key list when `Options.Secrets` is nil. The first key in a configured list signs new credentials. |
| `AUTH_URL` | Supplies the absolute public HTTP(S) URL when `Options.BaseURL` is empty. An explicit `Options.BasePath` selects the mount. Otherwise the URL path selects it, with `/api/auth` as the default. |
| `AUTH_TRUSTED_ORIGINS` | Adds comma-separated exact HTTP(S) origins or wildcard hostname and port rules to `Options.TrustedOrigins`. See the [pattern examples](authentication.md#trust-a-set-of-application-hosts). |
| `AUTH_ENV` | The value `production` enables rate limiting and redirects the default error page to `/`. Other nonempty values disable the default rate limiter. With an empty value, HTTPS enables it. `Options.RateLimit` and `Options.ErrorRedirectURL` override these defaults. |

Set the server's public origin and either a signing secret or a versioned key list before startup. Keep signing keys in the server environment.

A versioned key list takes precedence over either single-secret setting. The server first uses `Options.Secrets`, then checks `AUTH_SECRETS` when the Go list is nil. With no key list configured, it uses `Options.Secret` followed by `AUTH_SECRET`. An explicitly empty Go list or an invalid configured list fails startup.

## Native client URL

Pass a URL to `client.New` to select the destination explicitly. An empty argument reads `AUTH_URL` at construction. For example, `AUTH_URL=https://app.example.org` sends session requests to `/api/auth/get-session`. Set `AUTH_URL=https://app.example.org/login` to send them to `/login/get-session`. The native client requires an absolute HTTP(S) URL. [Client configuration tests](../client/environment_test.go)

## Route authentication logs

Set `Options.Logger` to a standard Go `*slog.Logger` when constructing the auth handler. Each instance uses its own handler, format and severity threshold. Leave the option empty to use the process’s current `slog.Default()`. To silence a specific instance, use `slog.New(slog.DiscardHandler)`.

```go
level := new(slog.LevelVar)
level.Set(slog.LevelWarn)
opts.Logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
    Level: level,
})).With("component", "auth")
auth, err := plainauth.New(opts)
```

A plugin can call `c.Auth.Logger().InfoContext(c.Request.Context(), "directory sync completed", "members", count)` to use the same destination and request context. Change the threshold at runtime with `level.Set(slog.LevelError)`. The verification-mail and last-login handlers report delivery or storage failures without putting the email address, token, password or raw callback error in the message. The host controls formatting, including terminal colors, through its handler. [Logger isolation and redaction tests](../logger_test.go)

### Observe endpoint errors

Set `OnAPIError` to receive the original error on the server before Plain Auth writes the HTTP error response. The hook receives the request and the user identity if the endpoint already resolved it. For example, a host can count failures by public API code using its own metrics recorder.

```go
opts.OnAPIError = func(c plainauth.ErrorContext, err error) error {
    code := "INTERNAL_SERVER_ERROR"
    var apiErr *plainauth.APIError
    if errors.As(err, &apiErr) {
        code = apiErr.Code
    }
    return metrics.CountAuthFailure(c.Request.Context(), code)
}
```

The handler waits for the callback, so bound any external reporting call with the request context and a timeout. Returning an error or panicking in the reporter records a diagnostic through the instance logger. The client receives the original HTTP status and the usual public error body, including any configured translation. Redirects, unmatched routes and ordinary rate-limit responses bypass the callback. Native Go methods return errors directly to their callers. [Error reporting tests](../error_reporting_test.go)

## Rotate signing keys

Supply a comma-separated list in the form `2:<new-secret>,1:<old-secret>`. Each entry needs a distinct non-negative version and a secret of at least 32 bytes. The first entry signs new session cookies and email proofs. Keep the previous key in the list while credentials it signed need to work. To retire it, remove that entry from every instance after the overlap period. The same list protects authenticator credentials and JWT private keys at rest. A single secret uses version zero. When moving to a key list, explicitly keep the original key as version zero until the records it protects have been replaced.

## Application and integration settings

| Setting | Consumer |
| --- | --- |
| `AUTH_DSN` | `authctl migrate` applies the selected schema to this database. `authctl check schema` reads its catalog with the same dialect and plugin flags. Applications may pass the same string to `sqlstore.Open`. |
| `AUTH_DB` | The example host chooses its SQLite path from this variable. |
| `POLAR_ACCESS_TOKEN`, `POLAR_WEBHOOK_SECRET`, `POLAR_ORGANIZATION_ID`, `POLAR_HOSTED_ORIGIN`, `POLAR_PRO_PRODUCT_ID` | The host passes these example variables to the official SDK and the checkout plugin. Each application chooses the product slugs and corresponding variables. [Polar configuration](polar.md#configure-the-integration) |
| `STRIPE_WEBHOOK_SECRET`, `STRIPE_SECRET_KEY` | The [Stripe examples](plugins.md) pass the webhook signing secret and server-side API key into the SDK integration. |
| Provider client IDs, provider secrets, and mail credentials | The host application reads its chosen variable names and supplies them when configuring the relevant provider or sender. |
| `AUTH_TEST_POSTGRES_DSN`, `AUTH_TEST_MYSQL_DSN` | The integration tests read these to select disposable databases. |
| `AUTH_FACTOR_POSTGRES_DSN`, `AUTH_FACTOR_MYSQL_DSN` | The two-factor tests use separate disposable databases for schema upgrades and concurrent credential changes. |

The [configuration tests](../env_test.go) cover startup options, key rotation, trusted origins and rate limiting. A [process isolation test](../conformance/env.test.mjs) checks the server and client with their own synthetic environment.

Run `go run ./cmd/authctl info` for runtime and SQL dialect information without printing environment values.
