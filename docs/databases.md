# Databases and the CLI

Create an empty application database and provide credentials that can create tables and indexes. For SQLite, choose a path in a writable directory. The CLI and application adapters use the same schema implementation. The target is a fresh Go installation.

Configure user profiles, per-login metadata and linked provider attributes with the same field declarations in your application and schema commands. [Schema configuration](schema.md#configure-user-session-and-account-fields)

## Inspect and apply the schema

From the repository checkout, generate SQL for review. Generation writes to stdout and needs no database connection.

```sh
go run ./cmd/authctl generate --dialect postgres > auth-postgres.sql
go run ./cmd/authctl generate --dialect mysql > auth-mysql.sql
go run ./cmd/authctl generate --dialect sqlite > auth-sqlite.sql
```

Supply a connection string in `AUTH_DSN` and run the matching migration. The following examples use local development databases and placeholder credentials.

```sh
AUTH_DSN='./auth.db' go run ./cmd/authctl migrate --dialect sqlite

AUTH_DSN='postgres://auth_user:example@localhost:5432/auth_dev?sslmode=disable' \
  go run ./cmd/authctl migrate --dialect postgres

AUTH_DSN='auth_user:example@tcp(127.0.0.1:3306)/auth_dev' \
  go run ./cmd/authctl migrate --dialect mysql
```

`generate --output FILE` writes the schema to a file instead, creating missing parent directories; when the path is an existing directory, the file inside it is named after the current UTC time, such as `2026-11-25T08-30-00.000Z.sql`. An existing file is replaced only with `-y` or `--yes`. `migrate` applies the schema without asking and accepts `-y` and `--yes` for scripts that pass them. `init`, `check`, `generate`, `migrate` and `create-admin` accept `-c DIR` or `--cwd DIR` to run in another directory, so relative field files, `--output` and a relative SQLite `AUTH_DSN` resolve there. [Command option tests](../cmd/authctl/cli_options_test.go)

Use the deployment's TLS settings for remote databases. The PostgreSQL adapter accepts pgx connection strings. The MySQL adapter accepts go-sql-driver/mysql DSNs and enables timestamp parsing. SQLite uses go-sqlite3 with foreign keys enabled and requires CGO.

## Check a deployed schema

Build the CLI to use its exit codes in a deployment script. Set `AUTH_DSN` to the deployed database and supply the same dialect and plugin profiles as the application.

```sh
go build -o ./authctl ./cmd/authctl
AUTH_DSN='./auth.db' ./authctl check schema --dialect sqlite --plugins organization,two-factor
```

`authctl check` and `authctl check schema` run the same read-only inspection. SQLite requires an existing file. PostgreSQL resolves table names through the connection's search path, and MySQL uses the database selected in its DSN.

| Exit code | Meaning |
| --- | --- |
| 0 | All selected tables and columns were found, and extra columns accept omitted values. |
| 1 | The inspection found a missing table, a missing column or an extra required column. |
| 2 | The CLI could not validate its settings, inspect the database or write the report. |

Add `--json` to receive an array on stdout, with diagnostics on stderr. A matching database returns `[]`. For example, selecting the last-login-method profile before migrating returns the following finding.

```json
[{"kind":"missing-column","table":"user","column":"lastLoginMethod"}]
```

For a missing table or column, review the SQL from `authctl generate` and apply the corresponding migration. For an extra required column, supply a database default or make the column nullable if the application may omit it. The check examines physical column names and whether extra columns can be omitted. Type compatibility, indexes, foreign keys and write permissions require separate verification.

## Open storage in Go

```go
store, err := sqlstore.Open(ctx, "postgres", os.Getenv("AUTH_DSN"))
if err != nil {
    return err
}
defer store.Close()
// Pass store in plainauth.Options{Store: store, ...}.
```

Import `github.com/Plain-Org/plain-auth/adapters/sqlstore`. Use `"mysql"` or `"sqlite"` to change engines. Opening the store also applies its pending schema. Keep one store for the application's lifetime. Each request passes its own context for cancellation and deadlines.

The stores have no generic query layer, so there is nothing to tune with a default row limit, join switch or startup schema check. Each operation is a typed method with its own SQL: listing and revoking read every matching row so nothing is silently cut off, endpoints that page take explicit limits, and related rows are read with SQL joins. For a database migrated by another tool, run `authctl check` or `CheckSchemaWithOptions` to compare it with the expected schema. To use another database or service, implement `plainauth.Store` yourself: see [custom stores](custom-store.md).

### Hosted PostgreSQL and MySQL

Managed services that speak the PostgreSQL protocol, such as Neon, Supabase and Prisma Postgres, use the `"postgres"` engine with the connection string the service provides. MySQL-compatible services such as PlanetScale and TiDB use the `"mysql"` engine. The schema relies on transactions and foreign keys, so enable foreign key constraints on services where they are optional. The integration tests run against PostgreSQL 18 and MySQL 8.4.

## What is stored

| Table | Purpose |
| --- | --- |
| `user` | Profile, unique email, verification state, creation and update timestamps |
| `account` | Account and provider identities, owner reference, optional password hash, OAuth tokens, scopes and expiry |
| `session` | Unique opaque token, owner reference, creation, update and expiry times, and optional network metadata. With [`SecondaryStorage`](redis.md#keep-sessions-in-redis), a copy of each live session is also kept there |
| `verification` | Identifier, value and expiry for temporary verification records |

The default layout uses per-dialect SQL types. A password account has provider ID `credential` and its account ID matches the owning user. Sessions reference that user and expire at their stored timestamp. Account registration writes the user, credential and initial session in one transaction. See the [dialect schemas](../adapters/sqlstore/schema) and [database contract tests](../adapters/sqlstore/engines_test.go).

### Expired verification records

Writes of verification records delete expired ones in passing, so abandoned records do not pile up. In the SQL stores, a write of an OAuth state, magic link, one-time transfer, passkey or SIWE challenge, used ID token, OAuth consent or SAML logout record deletes the expired records of its kind. A trusted device, an email proof or a Stripe checkout or webhook record deletes the expired records under the same user, address or key. DPoP proofs, and password reset and deletion links together with email and phone codes, are swept at most once a minute per store; that sweep gives up after waiting a second for another transaction's lock and never fails the write that starts it. The memory store sweeps a kind's expired entries whenever it writes that kind. Other records, such as two-factor sign-in challenges, stay until their key is written again or you prune them. To keep expired records, for an audit or your own retention job, set `DisableVerificationCleanup`:

```go
auth, err := plainauth.New(plainauth.Options{
	Store:                      store,
	DisableVerificationCleanup: true,
	// ...
})
```

Expired records are still refused, and a record that is used is still removed. A write whose key matches an expired record replaces that one record. Nothing else deletes them, so prune the `verification` table on your own schedule, for example by deleting rows whose `expiresAt` is in the past. Every server sharing a store value must use the same setting; a store that an `Auth` already uses with the other value makes `New` return an error. The SQL stores and `memory.New()` support the option. A custom store supports it by implementing `VerificationCleanupStore`. Without that, `New` refuses the option. The [cleanup tests](../adapters/sqlstore/verification_cleanup_test.go) cover SQLite, PostgreSQL and MySQL.

### Verification identifiers

A verification record's identifier is a purpose prefix followed by a key. For password reset links (`reset-password:`), account deletion links (`delete-account-`), magic links (`magic-link:`) and one-time tokens (`one-time-token:`), the key is the token by default, so anyone who can read the `verification` table can redeem a live link. Set `StoreVerificationIdentifier` to store a hash instead:

```go
auth, err := plainauth.New(plainauth.Options{
	Store:                       store,
	StoreVerificationIdentifier: plainauth.VerificationIdentifierStorage{Hashed: true},
	// ...
})
```

`Hashed` keeps the prefix and replaces the token with the SHA-256 of the whole identifier as unpadded URL-safe Base64: the token `abc` is stored as `reset-password:IMUqJ3lXuvod79AbI4EdsWmdAkZeIP5syfKs7-d5fQQ`. It uses no secret, so rotating `Secret` changes nothing. `Hash` supplies your own function instead, such as an HMAC under a key you manage. It receives the whole identifier and returns the part stored after the prefix: the same value for the same input, 1 to 240 bytes of UTF-8 without NUL. An error or panic fails the request with 500, for registered and unknown reset addresses alike; a one-time token offered in a `Set-Ott` header after sign-in is left out instead. `StoreVerificationIdentifierOverrides` gives one purpose its own storage. A key is the start of a purpose prefix, with or without its separator, and an empty `VerificationIdentifierStorage` keeps that purpose plain: with `StoreVerificationIdentifier` set to `{Hashed: true}`, the override `map[string]plainauth.VerificationIdentifierStorage{"one-time-token": {}}` hashes reset, deletion and magic links and keeps one-time tokens plain. `New` refuses a key that is empty, starts no covered prefix or reaches into the token, two keys for one purpose, and `Hashed` together with `Hash`.

Mailed links and returned one-time tokens are unchanged, and a plugin's `HashTokens` or `HashToken` applies first. The SQL stores, `memory.New()` and custom stores all apply the setting, because the store receives the stored form. The prefix stays, so cleanup, `DisableVerificationCleanup`, and the removal of a user's links on deletion or mailbox proof work as before. The stored value is never accepted as a token, and links issued before a change are refused afterwards, so users request new ones; no migration is needed, and old records expire. Going back to plain while hashed links are live lets their stored value redeem them. Every server sharing a store must use the same settings. Not covered: email and phone codes, whose identifiers hold the address or number while `StoreOTP` protects the code; OAuth and SAML states, stored under an identifier derived from the browser cookie; two-factor records, which need their signed cookie; wallet nonces, which are public; and passkey challenges, DPoP proofs and authorization codes, which are already stored as digests. [Identifier tests](../adapters/sqlstore/verification_identifier_test.go) · [Option tests](../conformance/goapi/store_identifier_test.go) · [Cross-runtime comparison](../conformance/verification-identifiers.mjs)

For isolated development without a database, pass `memory.New()` from `github.com/Plain-Org/plain-auth/adapters/memory` as the store. Its users and sessions live in a single process and are discarded when the process exits. The [in-memory tests](../adapters/memory/memory_test.go) exercise registration and session revocation.

## Run database integration tests

Use disposable databases and dedicated test credentials. The tests create auth tables and records. Tests that isolate schema profiles also create and drop PostgreSQL schemas in the selected database or separate MySQL databases named `orgtest_…`. Grant the test account those permissions on the disposable server.

```sh
export AUTH_TEST_POSTGRES_DSN='postgres://auth_user:example@localhost:5432/auth_test?sslmode=disable'
export AUTH_TEST_MYSQL_DSN='auth_user:example@tcp(127.0.0.1:3306)/auth_test'
go test -race -count=1 -v ./adapters/...
```

For the two-factor tests, create separate empty databases and supply `AUTH_FACTOR_POSTGRES_DSN` and `AUTH_FACTOR_MYSQL_DSN`. These tests exercise adding factor fields to a running installation and need a dedicated schema. A skipped engine test indicates that its DSN was absent. Each engine's result is tracked individually in the [feature checklist](parity/README.md).

## Add optional integration tables

Pass the same comma-separated profile list to generation and migration. For example, inspect the SQL for team memberships and two-factor records, then apply it to the chosen database.

```sh
go run ./cmd/authctl generate --dialect postgres --plugins organization-teams,two-factor
AUTH_DSN='postgres://auth_user:example@localhost:5432/auth_dev?sslmode=disable' \
  go run ./cmd/authctl migrate --dialect postgres --plugins organization-teams,two-factor
```

Use the [schema profile guide](schema.md) for supported combinations and runtime feature status.

For application keys, `authctl migrate --dialect postgres --api-key-ledger` applies the API-key profile and reserves the digests of existing keys. You can combine this option with other schema profiles. The command reads its target from `AUTH_DSN`. [API-key setup and upgrade guide](api-keys.md#custom-key-generation-and-credential-extraction)
