# Contributing

Use the [feature checklist](docs/parity/README.md) to find an open capability. A checked behavior has an implementation and a test that proves it at a public entry point. A larger feature stays open while any required behavior remains unverified.

## Local setup

1. Fork the [repository](https://github.com/Plain-Org/plain-auth) and clone your fork.
2. Install a patched Go 1.26 or newer toolchain and a C compiler. Install Node 24 and npm if you will run the JavaScript client conformance tests.
3. Run `go mod download` and start the [example application](README.md#quickstart).
4. For PostgreSQL and MySQL changes, set up dedicated test databases using the [database guide](docs/databases.md#run-database-integration-tests).

## Source layout

The module root is the `plainauth` package. Everything else is either an optional package that builds on it or tooling around it.

| Path | What belongs there |
| --- | --- |
| Root `*.go` files | The public `plainauth` API: `Options`, the HTTP handler, sessions, cookies, origins and the core endpoints. |
| `plugins/<name>` | One optional feature per package, such as `plugins/organization` or `plugins/twofactor`. A plugin registers its routes through `plainauth.Plugin` and declares the storage interface it needs. |
| `adapters/sqlstore` | The shared SQL storage for SQLite, PostgreSQL and MySQL, including plugin storage and the cross-engine tests. |
| `adapters/<engine>` | Small constructors for `sqlite`, `postgres` and `mysql`, plus the in-memory `memory` store. `adapters/redis` is a separate module for secondary storage. |
| `providers/` | Social sign-in providers and OpenID Connect presets. |
| `schema/` | Table and column definitions that `authctl` and the adapters generate DDL from. |
| `client/` | The typed Go HTTP client. |
| `authtest/` | Fixtures that applications import in their own integration tests. |
| `integrations/<name>` | Separate Go modules for integrations that need extra dependencies, such as routers and Polar. |
| `cmd/authctl` | The schema, migration and secret CLI. |
| `internal/` | Helpers shared between packages that are not part of the public API. |
| `examples/` | Runnable host applications. |
| `docs/` | One guide per capability, indexed in [docs/README.md](docs/README.md). `docs/parity/` is generated; do not edit it by hand. |
| `conformance/` | Cross-runtime HTTP tests, the [evidence registry](conformance/evidence.json) and the checklist generator. |

Put each test where it can see what it needs:

- **White-box tests** use the package under test (`package plainauth`, `package organization`) and sit next to the code.
- **Public API tests** that drive an `Auth` instance only through exported Go calls and HTTP go in `conformance/goapi` (package `goapi_test`).
- **Storage behavior** that must hold on every SQL engine goes in `adapters/sqlstore`.
- **Cross-runtime comparisons** with the JavaScript client go in `conformance/*.mjs`.

Keep the root package focused. Periodic cleanup that moves files or tests without changing behavior is normal maintenance. Do it in its own commit and regenerate the checklist, because test paths change.

## Implement and verify a feature

- Identify the contract first. Write down its accepted options, HTTP or Go API, storage requirements, and observable results. Test a successful call and the errors or retries that could leave data in an incorrect state.
- Pass request contexts through to database and network calls. Use a transaction for related writes, use database uniqueness constraints for collisions, and keep session and credential material out of logs.
- Prefer an existing maintained SDK for a provider's protocol. Keep it inside the integration package and exercise it with local fixtures.
- Link the test to the feature it proves in [the evidence registry](conformance/evidence.json). Regenerate the [checklist](docs/parity/README.md) with the [inventory instructions](conformance/README.md). If a database test was skipped or a provider option remains pending, leave that behavior open.

Run `make verify` for the Go packages, routers, Redis adapter, Polar integration, vet, and cross-runtime checks. Set the four database test DSNs for PostgreSQL and MySQL. Set `CHROME_BIN` for the browser tests. For the Redis tests, install `valkey-server` or `redis-server`, set `AUTH_TEST_REDIS_SERVER` to the executable, or point `AUTH_TEST_REDIS_URL` at a disposable test instance. [Database setup](docs/databases.md#run-database-integration-tests) · [Redis setup](docs/redis.md)

Run individual checks from the repository root. The router and Redis integrations use separate modules.

```sh
go test -race -count=1 ./...
go vet ./...
(cd integrations/routers && go test -race -count=1 ./...)
(cd integrations/routers && go vet ./...)
(cd adapters/redis && go test -race -count=1 ./...)
(cd integrations/polar && go test -race -count=1 ./...)
(cd adapters/redis && go vet ./...)
npm --prefix conformance ci --ignore-scripts --no-audit --no-fund
npm --prefix conformance test
```

## Working in GitHub

Anyone with a GitHub account can [report a bug or request a feature](https://github.com/Plain-Org/plain-auth/issues/new/choose). For a new integration, schema change, or public API, open a feature request first so maintainers and contributors can agree on the behavior. Use the [security reporting guide](SECURITY.md) for suspected vulnerabilities.

1. Create a branch in your fork for one change. A documentation fix or a small bug fix can go straight to a pull request.
2. Implement the change, add or update the relevant tests and docs, and link the evidence in the checklist. Review `git diff` and use a descriptive commit such as `feat: add PostgreSQL session storage`.
3. Run the checks above. Use `make verify-commit` to run the full suite from an archive of your commit. In the pull request, say what you ran and which services you used.
4. Push your branch to your fork. On GitHub, select **Compare & pull request**, set the base to **Plain-Org/plain-auth** and **main**, and describe the user-visible change. A maintainer reviews the change and merges it when the checks pass. [GitHub's fork pull-request guide](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/creating-a-pull-request-from-a-fork)

During the preview, the maintainer also develops directly on `main`, one feature at a time:

1. Update the checkout with `git pull --ff-only origin main`.
2. Build the feature and test it through its real entry points: HTTP, the Go client and each SQL engine.
3. Update the guide and the evidence registry, then regenerate the checklist.
4. Commit, run `make verify-commit`, push, and wait for the **Verify** run to pass before starting the next feature.

On GitHub, open the [feature checklist](docs/parity/README.md), follow the test link on a completed behavior, and use the file's **History** to find the implementing commit. Changes to checkboxes are reviewed alongside the feature implementation and test evidence. Keep credentials, local database files, and session cookie jars out of commits.

Open **Actions → Verify** in GitHub and select the run for your commit. Expand **Test routers, databases, clients and schema profiles** to see the Go race tests, each module’s vet results, browser conformance tests and schema checks. If verification fails, the first failing test or compile error identifies what to reproduce locally. Each job starts PostgreSQL, MySQL and Valkey services. SQLite uses temporary files, and the browser tests use headless Chrome with local fixtures. [Workflow runs](https://github.com/Plain-Org/plain-auth/actions/workflows/verify.yml)
