# Environment configuration

The auth instance reads the host process environment once during `authn.New`. Environment values take effect when the application constructs a new instance. Set them in your shell, container, hosting dashboard, or secret manager.

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

| Setting | Resolution at startup |
| --- | --- |
| Signing secret | `Options.Secret`, then `BETTER_AUTH_SECRET`, then `AUTH_SECRET`. Use a random secret of at least 32 bytes. |
| Versioned signing keys | `Options.Secrets`, then `BETTER_AUTH_SECRETS`, then `AUTH_SECRETS`. A configured list selects the active signing key ahead of any single secret. |
| Public URL | `Options.BaseURL`, then `BETTER_AUTH_URL`, `AUTH_URL`, `NEXT_PUBLIC_BETTER_AUTH_URL`, `PUBLIC_BETTER_AUTH_URL`, `NUXT_PUBLIC_BETTER_AUTH_URL`, `NUXT_PUBLIC_AUTH_URL`, and `BASE_URL`. A value of `/` for the last fallback supplies no origin. |
| Auth mount | An explicit `Options.BasePath` wins, followed by a path in the public URL, followed by `/api/auth`. Register the handler at `auth.BasePath()`. |
| Additional trusted origins | Append the comma-separated entries from `BETTER_AUTH_TRUSTED_ORIGINS` or its fallback `AUTH_TRUSTED_ORIGINS` to `Options.TrustedOrigins`. Whitespace is trimmed. Supply exact origins with schemes. |
| Error page | `Options.ErrorRedirectURL` supplies the application error page. In production the default is `/`. Other modes render a built-in HTML page. |
| HTTP rate limiting | `Options.RateLimit` wins. Otherwise `AUTH_ENV`, then `NODE_ENV`, enables the limiter for `production`. With neither variable configured, HTTPS enables it. |

Empty scalar environment settings fall through to the next name. Existing configurations can keep their prefixed variable names. Use `AUTH_SECRET`, `AUTH_URL`, and `AUTH_TRUSTED_ORIGINS` for a new Go deployment. Public frontend URL variables are suitable for origins only. Keep signing secrets in the server environment.

## Native client URL

Pass a URL to `client.New` to select the destination explicitly. With an empty argument, the constructor tries the public URL aliases in the table above in the same order. For these settings, an origin uses `/api/auth` and a URL with a path uses that path as the auth mount.

If those settings are empty, the client tries `NEXT_PUBLIC_AUTH_URL` followed by `NEXTAUTH_URL`. Both identify the complete mount. For example, `NEXTAUTH_URL=https://app.example.org` sends session requests to `/get-session`, and `NEXTAUTH_URL=https://app.example.org/api/auth` sends them to `/api/auth/get-session`. Finally, `VERCEL_URL` supplies the deployment origin. A bare hostname uses HTTPS and the client appends `/api/auth`. A native Go process needs an absolute host and returns a construction error when it has none.

The server also requires a configured public origin. It enforces the same minimum signing-key length during tests, including when `TEST` or `NODE_ENV=test` is set. [Native client URL tests](../client/environment_test.go) · [reference comparison](../conformance/env.test.mjs)

## Rotate signing keys

Supply a comma-separated list in the form `2:<new-secret>,1:<old-secret>`. Each entry needs a distinct non-negative version and a secret of at least 32 bytes. The first entry signs new session cookies and email proofs. Verification accepts signatures from keys still in the list. To retire a key, remove it from every instance after the intended overlap period. To read unversioned authenticator secrets when moving to a versioned list, retain the original single secret until those records have been rotated. List the old key in the ring during the overlap if its session cookies or email proofs should still verify.

## Application and integration settings

| Setting | Consumer |
| --- | --- |
| `AUTH_DSN` | `authctl migrate` opens this database using the explicitly supplied dialect. Applications may pass the same string to `sqlstore.Open`. |
| `AUTH_DB` | The example host chooses its SQLite path from this variable. |
| `STRIPE_WEBHOOK_SECRET`, `STRIPE_SECRET_KEY` | The [Stripe examples](plugins.md) pass the webhook signing secret and server-side API key into the SDK integration. |
| Provider client IDs, provider secrets, and mail credentials | The host application reads its chosen variable names and supplies them when configuring the relevant provider or sender. |
| `BETTERAUTH_TEST_POSTGRES_DSN`, `BETTERAUTH_TEST_MYSQL_DSN` | The integration tests read these to select disposable databases. |
| `BETTERAUTH_FACTOR_POSTGRES_DSN`, `BETTERAUTH_FACTOR_MYSQL_DSN` | The two-factor tests use separate disposable databases for schema upgrades and concurrent credential changes. |

The runnable [configuration tests](../env_test.go) cover precedence, URL aliases, key rotation, invalid settings, trusted origins, and rate limiting. A [cross-runtime test](../conformance/env.test.mjs) also compares the selected mount, trusted origins, and active signing key using public test values.

Run `go run ./cmd/authctl info` for runtime and SQL dialect information without printing environment values.
