# Database schema

Use `authctl generate` to print a complete fresh-database schema for SQLite, PostgreSQL or MySQL. Use `authctl migrate` to apply the selected schema to the database specified by `AUTH_DSN`. Go applications can generate the same SQL with `schema.Generate` and use it with `sqlstore.OpenWithSchema`.

On PostgreSQL, concurrent Plain Auth migrations share a transaction-scoped advisory lock. Each migration uses `READ COMMITTED` so its schema checks and backfills see the preceding migration's committed changes. Other transactions retain the application's configured isolation. [PostgreSQL concurrency tests](../adapters/sqlstore/migrate_postgres_test.go)

```sh
go run ./cmd/authctl generate --dialect postgres --plugins organization-teams,two-factor
AUTH_DSN=auth.db go run ./cmd/authctl migrate --dialect sqlite --plugins organization-teams,two-factor
```

| Profile | Schema features |
| --- | --- |
| Default | User, credential or provider account, session and verification records |
| `username` | Optional unique login name and display spelling |
| `username-only` | Optional unique login name |
| `phone-number` | Optional unique telephone number and nullable verification flag |
| `admin` | User roles, ban status and expiration, and the administrator behind an impersonated session |
| `api-key` | Personal and organization-owned application keys, digest lookup, scopes, per-key budgets and rate counters |
| `anonymous` | Anonymous-account status on the user |
| `last-login-method` | Most recent authentication method on the user |
| `device-authorization` | Expiring device grants with unique device and user codes and client binding |
| `oauth-provider` | Registered OAuth clients, protected resources, client-resource permissions, consent, tokens and single-use client assertions |
| `jwt` | Public verification keys, encrypted signing keys and rotation times |
| `organization` | Organizations, memberships, invitations and active organization selection |
| `organization-teams` | Organization schema with teams, team membership, invitation team selection and active team selection |
| `organization-roles` | Organization schema plus tenant-scoped role definitions, permission data and lookup indexes |
| `passkey` | Public credentials, authenticator counters, transport hints and account ownership |
| `rate-limit` | Shared per-route counters with a unique key, request count and timestamp in milliseconds |
| `scim` | Directory connection bindings, Users, Groups, memberships, subjects, retained external identities and projection grants |
| `scim-managed` | Directory tables plus managed connections, credential digests and the ordered audit log |
| `siwe` | Ethereum wallet addresses, chain IDs, primary designation and owner reference |
| `sso` | Enterprise provider registration with globally unique provider ID, creator, organization, issuer, domains and serialized OIDC configuration |
| `sso-domain-verification` | Enterprise provider catalog with the nullable DNS ownership flag |
| `stripe-subscriptions` | Customer identifiers and subscription records with status, plan, billing and lifecycle fields |
| `stripe-organization` | Organization and subscription tables with a Stripe customer identifier on the organization |
| `two-factor` | User enrollment state, factor secrets, recovery codes and lockout fields |

Select `polar` to create `plainauth_polar_checkout` and `plainauth_polar_delivery`. The first table binds a purchase attempt to a merchant, customer and product. The second records verified webhook deliveries. A core-only installation adds neither table. [Polar hosted checkout](polar.md)

Choose either `organization` or `organization-teams`, and at most one username profile. The `stripe-organization` option also works alongside `organization-teams`. Run `authctl info` for the full profile list in your build, or call `schema.Profiles()` from Go. Profile order produces deterministic output. The profile selector controls database structure. See the [feature checklist](parity/README.md) for runtime support.

## Organization role storage

Use `organization-roles` to install the `organizationRole` table alongside organizations. To upgrade an application with teams, include both profiles. Set `AUTH_DSN` to the target database before running these commands.

```sh
authctl generate --dialect postgres --plugins organization-teams,organization-roles
authctl migrate --dialect postgres --plugins organization-teams,organization-roles
authctl check schema --dialect postgres --plugins organization-teams,organization-roles
```

Choose `mysql` or `sqlite` for those dialects. In Go, `schema.Generate` and `sqlstore.OpenWithOptions` accept the same profile names. You can rerun the migration after organizations and role definitions exist.

Each row has a primary key `id`, the owning `organizationId`, a `role` name, a `permission` text field containing a JSON resource-to-actions map, a required `createdAt`, and an optional `updatedAt`. The organization reference cascades on deletion. Both the organization reference and role name have indexes. Two organizations can use the same role name with different grants. [Three-dialect comparison and CLI tests](../conformance/schema.test.mjs) · [Live migration and isolation tests](../adapters/sqlstore/organization_role_schema_test.go)

Enable `DynamicAccessControl` in the organization plugin to apply stored grants to permission checks, invitations, profile edits and team operations. [Runtime configuration](organizations.md#use-roles-stored-by-an-organization) · [Role management checklist](parity/plugins/organization.md)

## Configure user, session and account fields

Pass `--user-fields FILE`, `--session-fields FILE` and `--account-fields FILE` in any combination to `authctl generate`, `check schema` and `migrate`. Each file is a JSON object keyed by the logical name your app uses. Each model has its own field names. A `column` value selects a physical column on that model. The file can use application names while preserving an existing database column name.

For example, save this user profile as `user-fields.json`.

```json
{
  "locale": {"type": "string", "column": "preferred_locale", "required": true, "default": "en"},
  "newsletter": {"type": "boolean", "default": false},
  "reviewedAt": {"type": "date", "column": "profile_reviewed_at"},
  "supportNote": {"type": "string", "serverOnly": true, "hidden": true}
}
```

For per-login metadata, save a separate `session-fields.json`.

```json
{
  "attempts": {"type": "number", "default": 0, "serverOnly": true}
}
```

Each definition requires a `type` of `string`, `boolean`, `number` (a signed 32-bit integer), or `date` (a timestamp). Optional keys are `column`, `default`, `required`, `serverOnly` and `hidden`. Boolean options default to false. The physical column defaults to the logical name. A typed default may be zero, false or an empty string. Optional fields also accept a null default. Duplicate keys, unknown properties, reserved names, incompatible defaults and conflicting aliases are configuration errors.

A date field accepts a timestamp with an explicit offset, such as `"2026-02-15T06:02:03.123-05:00"`. The API returns `"2026-02-15T11:02:03.123Z"`. New schemas use SQLite `date`, PostgreSQL `timestamptz`, and MySQL `timestamp(3)`. Values must fit the selected database's timestamp range. For example, dates of birth before 1970 exceed MySQL's `TIMESTAMP` range. When adding a required date column to a populated table, supply a static timestamp default to backfill existing rows. Repeated migration preserves previously written values.

Go applications may configure a zero-argument function as a creation default. Schema generation and migration never call it. A nullable column added to a populated table begins with null for existing rows. A required column on that table needs an explicit static backfill before deploying the callback. CLI JSON declaration files accept static defaults.

Use the same declarations and plugin selection for each command. Set `AUTH_DSN` for `check` and `migrate`.

```sh
authctl generate --dialect postgres --plugins admin --user-fields user-fields.json --session-fields session-fields.json
authctl check schema --dialect postgres --plugins admin --user-fields user-fields.json --session-fields session-fields.json --json
authctl migrate --dialect postgres --plugins admin --user-fields user-fields.json --session-fields session-fields.json
```

`generate` emits fresh-schema SQL. `check schema` inspects the target in a read-only transaction. Exit status 0 means the selection matches, 1 reports schema differences, and 2 indicates a configuration or connection error. Findings identify the table and physical column. An existing generated column is incompatible with a declared writable attribute.

`migrate` checks all supplied declarations before applying their column additions. An existing row receives a supplied scalar default when the migration adds a column. Adding a required column to a populated table requires a default or an explicit database backfill. For fresh tables, the auth instance supplies defaults on email/password signup and session issuance. Load the same declarations into that instance to enforce input and visibility.

```go
file, err := os.Open("user-fields.json")
if err != nil {
    return err
}
defer file.Close()
opts.UserAdditionalFields, err = schema.ReadUserFields(file)
if err != nil {
    return err
}
```

Use `schema.ReadSessionFields` for `opts.SessionAdditionalFields`. Use `schema.ReadAccountFields` to read an account declaration. Go applications can pass all three sets in `schema.AdditionalFields` to `schema.GenerateWithAdditionalFields`, `sqlstore.CheckSchemaWithAdditionalFields` and `sqlstore.OpenWithAdditionalFields`. [User fields](user-fields.md) · [Session fields](session-fields.md) · [CLI lifecycle tests](../cmd/authctl/user_fields_test.go)

To add provider-specific metadata to the account table, save a declaration such as the following in `account-fields.json`. A nullable field also fits password accounts and providers that do not supply that information.

```json
{
  "tenant": {"type": "string", "column": "directory_tenant"},
  "lastConsent": {"type": "date", "column": "consented_at"}
}
```

```sh
authctl generate --dialect postgres --account-fields account-fields.json
authctl migrate --dialect postgres --account-fields account-fields.json
authctl check schema --dialect postgres --account-fields account-fields.json
```

Account ownership, credentials, scopes and timestamps use reserved column names. The CLI validates both logical names and physical aliases before applying a migration. [Configure provider account mapping](social.md#store-fields-on-a-linked-account) · [Account migration tests](../cmd/authctl/account_fields_test.go)

## OAuth authorization-server tables

Use the `oauth-provider` profile to prepare storage for an application that will issue tokens to registered clients. You can add it to an existing Plain Auth database and use the resource manager to maintain audiences and client links. HTTP authorization and token issuance have separate checklist entries. [Resource management](oauth-resource-management.md) · [Authorization-server checklist](parity/plugins/oauth-provider.md)

```sh
# Set AUTH_DSN to the target database before running migrate or check.
authctl generate --dialect postgres --plugins oauth-provider
authctl migrate  --dialect postgres --plugins oauth-provider
authctl check schema --dialect postgres --plugins oauth-provider
```

Use `--dialect mysql` or `--dialect sqlite` for those engines. Pass `--plugins oauth-provider,jwt` when the application also needs the signing-key table. In Go, pass the same profile names to `schema.Generate` or `sqlstore.OpenWithOptions`.

| Table | Stored values and relationships |
| --- | --- |
| `oauthClient` | A unique public client ID, redirect URIs, authentication method, optional owner, scopes and registration metadata. Public clients can omit the secret. |
| `oauthResource` | A unique resource identifier, display name, and optional token lifetimes, scopes, signing policy and custom claims. |
| `oauthClientResource` | Links the public client ID to the resource identifier. The database permits one row per pair and removes links when either side is deleted. |
| `oauthRefreshToken` | A unique token value, client, user, scopes, expiry, and optional session, rotation, revocation and proof-of-possession data. |
| `oauthAccessToken` | A unique token value, client, expiry and scopes. A machine grant can omit the user and session. Deleting the parent refresh token also deletes its linked access tokens. |
| `oauthConsent` | The client, optional user and reference, approved scopes and resources, requested claims, and timestamps. |
| `oauthClientAssertion` | A single-use assertion digest as the primary key and the time when that record may be removed. Concurrent inserts for the same digest permit one writer. |

The database clears the session reference on access and refresh tokens when the session is deleted. Deleting a client cascades to its tokens, consent and resource links. On MySQL 8.4 the profile emits explicit foreign keys, uses case-sensitive comparisons for token values and public identifiers, and allows 255-character public identifiers on both sides of a relationship. Reapplying the migration restores a missing foreign key and reports conflicting deletion rules. [Three-database lifecycle test](../adapters/sqlstore/oauth_provider_schema_test.go)

## Schema migrations

The `phone-number` profile adds nullable `phoneNumber` and `phoneNumberVerified` fields to the user table. Existing users keep both fields unset. The database enforces uniqueness for assigned numbers, including after upgrading a populated table. Telephone sign-in, SMS delivery, and number verification are tracked separately. [Phone authentication checklist](parity/plugins/phone-number.md)

```go
sql, err := schema.Generate("sqlite", []string{"organization", "two-factor"})
if err != nil {
    return err
}
store, err := sqlstore.OpenWithSchema(ctx, "sqlite", "auth.db", sql)
if err != nil {
    return err
}
defer store.Close()
```

Migrations initialize missing tables and indexes and add compatible columns to existing tables. Supply the same profiles on each deployment. Adding a profile can expand an existing installation while preserving its records. Removing a selection leaves its existing tables and columns in place. Required columns that cannot be populated from a default need an explicit application backfill. Review generated SQL when changing a database with custom constraints or mappings.

Schema tests compare every one of the 18,432 compatible selections of the original profile set on each SQL dialect, then upgrade a populated SQLite database for each nonempty selection. SCIM adds seven independent tables. For each dialect, the tests compare the full generator with SCIM alone, with each of the 15 other profiles, and with all four compatible maximal selections. Each of these 20 SCIM selections gets a repeated populated SQLite upgrade. An additional comparison requires identical statements for all preexisting schema objects and checks that SCIM contributes only tables and indexes belonging to its seven models. The SQL lifecycle test also opens and upgrades a populated database twice on SQLite, PostgreSQL and MySQL. [Schema comparisons](../conformance/schema.test.mjs) · [SCIM database tests](../adapters/sqlstore/scim_test.go)

The `scim-managed` comparison covers 26 selections per dialect and repeats their populated SQLite upgrades. These include the managed profile alone, each original profile alongside it, both SCIM selectors together, organization billing, and maximal selections with and without organization billing. Each comparison requires the base SCIM schema to remain identical and exactly three managed-catalog tables to account for every additional object. A separate test upgrades the populated basic-directory schema to managed credentials twice on all three database engines. [Schema comparisons](../conformance/schema.test.mjs) · [Managed credential database tests](../adapters/sqlstore/scim_managed_test.go)

The `sso` schema comparison verifies that its provider table and indexes compose with 23 selections per dialect. These include the profile alone, each other profile in isolation and four maximal combinations containing managed SCIM and organization billing. The tests repeat each selected populated SQLite upgrade. The local SQL lifecycle tests also upgrade existing accounts on PostgreSQL and MySQL. [Schema tests](../conformance/schema.test.mjs) · [Provider management tests](../adapters/sqlstore/sso_test.go)

The `sso-domain-verification` checks cover 24 profile selections per SQL dialect, including the base SSO profile combined with its verification extension. Each selection upgrades a populated SQLite provider catalog and repeats the migration. Three-engine tests exercise a live upgrade and domain verification through the public API. [Profile comparison](../conformance/schema.test.mjs) · [Live migration](../adapters/sqlstore/sso_domain_test.go)

## Configure the wallet table

Pass `--wallet-schema wallet.json` with the `siwe` profile on `generate`, `check` and `migrate`. The JSON object accepts the following physical names. Supply only the names you want to override.

```json
{
  "table": "wallet_address",
  "userId": "user_id",
  "address": "wallet_address",
  "chainId": "chain_id",
  "isPrimary": "is_primary",
  "createdAt": "created_at"
}
```

```sh
authctl generate --dialect postgres --plugins siwe --wallet-schema wallet.json
authctl check schema --dialect postgres --plugins siwe --wallet-schema wallet.json --json
authctl migrate --dialect postgres --plugins siwe --wallet-schema wallet.json
```

The commands also accept your user-field and session-field declarations. Repeating the same migration preserves existing wallet associations. To change a populated layout, migrate the physical names and data before applying the new configuration. A Go application can read the same file with `schema.ReadWalletSchema` and pass the result to `schema.Options.Wallet` and `siwe.Options.Schema`. [Wallet schema configuration](siwe.md#map-an-existing-wallet-schema)
