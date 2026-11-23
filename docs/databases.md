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

### Hosted PostgreSQL and MySQL

Managed services that speak the PostgreSQL protocol, such as Neon, Supabase and Prisma Postgres, use the `"postgres"` engine with the connection string the service provides. MySQL-compatible services such as PlanetScale and TiDB use the `"mysql"` engine. The schema relies on transactions and foreign keys, so enable foreign key constraints on services where they are optional. The integration tests run against PostgreSQL 18 and MySQL 8.4.

## What is stored

| Table | Purpose |
| --- | --- |
| `user` | Profile, unique email, verification state, creation and update timestamps |
| `account` | Account and provider identities, owner reference, optional password hash, OAuth tokens, scopes and expiry |
| `session` | Unique opaque token, owner reference, creation, update and expiry times, and optional network metadata |
| `verification` | Identifier, value and expiry for temporary verification records |

The default layout uses per-dialect SQL types. A password account has provider ID `credential` and its account ID matches the owning user. Sessions reference that user and expire at their stored timestamp. Account registration writes the user, credential and initial session in one transaction. See the [dialect schemas](../adapters/sqlstore/schema) and [database contract tests](../adapters/sqlstore/engines_test.go).

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
