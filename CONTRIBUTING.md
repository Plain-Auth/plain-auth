# Contributing

Use the [feature checklist](docs/parity/README.md) to find an open capability. A checked behavior has an implementation and a test that proves it at a public entry point. A larger feature stays open while any required behavior remains unverified.

## Local setup

1. Clone the repository using a GitHub account with access.
2. Install Go 1.26 or newer and a C compiler. Install Node 24 and npm if you will run the JavaScript client conformance tests.
3. Run `go mod download` and start the [example application](README.md#run-it-locally).
4. For PostgreSQL and MySQL changes, set up dedicated test databases using the [database guide](docs/databases.md#run-database-integration-tests).

## Implement and verify a feature

- Identify the contract first. Write down its accepted options, HTTP or Go API, storage requirements, and observable results. Test a successful call and the errors or retries that could leave data in an incorrect state.
- Pass request contexts through to database and network calls. Use a transaction for related writes, use database uniqueness constraints for collisions, and keep session and credential material out of logs.
- Prefer an existing maintained SDK for a provider's protocol. Keep it inside the integration package and exercise it with local fixtures.
- Link the test to the feature it proves in [the evidence registry](conformance/evidence.json). Regenerate the [checklist](docs/parity/README.md) with the [inventory instructions](conformance/README.md). If a database test was skipped or a provider option remains pending, leave that behavior open.

Run `make verify` for the package, router, vet, and cross-runtime checks. Set the engine and two-factor test DSNs first to include all live PostgreSQL and MySQL cases. The [database guide](docs/databases.md#run-database-integration-tests) lists all four. The equivalent individual commands below run from the repository root. The separate router module keeps framework dependencies out of application builds.

```sh
go test -race -count=1 ./...
go vet ./...
(cd integrations/routers && go test -race -count=1 ./...)
(cd integrations/routers && go vet ./...)
npm --prefix conformance ci --ignore-scripts --no-audit --no-fund
npm --prefix conformance test
```

## Working in GitHub

During private development, work directly on `main`. Update the local checkout with `git pull --ff-only origin main` before starting. Review `git diff` and `git status`, stage the files for one change, and use a specific commit message such as `feat: add PostgreSQL session storage` or `test: cover sign-out on Gin`. Run the relevant local checks and push with `git push origin main`.

On GitHub, open the [feature checklist](docs/parity/README.md), follow the test link on a completed behavior, and use the file's **History** to find the implementing commit. Changes to checkboxes are reviewed alongside the feature implementation and test evidence. Keep credentials, local database files, and session cookie jars out of commits.

Open **Actions → Verify** in GitHub to see the Go race tests, router tests, vet, client conformance and schema checks for a commit. The browser tests use headless Chrome with a local identity-provider fixture. Set `CHROME_BIN` to your Chrome executable to include them locally. Each job creates its own PostgreSQL and MySQL services and a separate database for authenticator tests. SQLite uses temporary local files. The same `make verify` command runs locally with the disposable database settings in the [database guide](docs/databases.md#run-database-integration-tests).
