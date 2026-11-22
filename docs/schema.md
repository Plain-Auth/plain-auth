# Database schema

Use `authctl generate` to print a complete fresh-database schema for SQLite, PostgreSQL or MySQL. Use `authctl migrate` to apply the selected schema to the database specified by `AUTH_DSN`. Go applications can generate the same SQL with `schema.Generate` and use it with `sqlstore.OpenWithSchema`.

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
| `jwt` | Public verification keys, encrypted signing keys and rotation times |
| `organization` | Organizations, memberships, invitations and active organization selection |
| `organization-teams` | Organization schema with teams, team membership, invitation team selection and active team selection |
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

Select `polar` to create `stonewrit_polar_checkout` and `stonewrit_polar_delivery`. The first table binds a purchase attempt to a merchant, customer and product. The second records verified webhook deliveries. A core-only installation adds neither table. [Polar hosted checkout](polar.md)

Choose either `organization` or `organization-teams`, and at most one username profile. The `stripe-organization` option also works alongside `organization-teams`. Run `authctl info` for the full profile list in your build, or call `schema.Profiles()` from Go. Profile order produces deterministic output. The profile selector controls database structure. See the [feature checklist](parity/README.md) for runtime support.

## Configure session fields

Pass `--session-fields FILE` to `authctl generate`, `check schema` or `migrate`. The file is a JSON object keyed by the field name your application reads. Each definition requires a `type` of `string`, `number` (signed 32-bit integer) or `boolean`. Optional keys are `column`, `default`, `required`, `serverOnly` and `hidden`. Boolean settings default to false. The physical column defaults to the field name. A default must match the field type. Optional fields can use JSON null. Unknown properties, duplicate keys, reserved names and conflicting aliases produce configuration errors before the command accesses the database.

```json
{
  "locale": {"type": "string", "column": "preferred_locale", "required": true, "default": "en"},
  "attempts": {"type": "number", "default": 0, "serverOnly": true},
  "privateFlag": {"type": "boolean", "hidden": true}
}
```

```sh
authctl generate --dialect postgres --session-fields session-fields.json
authctl check schema --dialect postgres --session-fields session-fields.json --json
authctl migrate --dialect postgres --session-fields session-fields.json
```

Set `AUTH_DSN` for `check` and `migrate`. Add the same `--plugins` selector to each command when using schema profiles. `generate` emits fresh-schema SQL. `check` opens a read-only transaction and reports missing physical columns and incompatible types, nullability or names. Exit status 0 means the selected schema matches, 1 means drift, and 2 means the command could not inspect the configuration or database. The check compares column compatibility. Application defaults and visibility settings come from the field configuration.

On an existing installation, `migrate` adds missing columns and uses supplied scalar defaults to backfill existing session rows. A required field on a populated table needs a default or an explicit database backfill. Migrations reject incompatible existing columns. Fresh-schema defaults are supplied by the auth instance when issuing sessions. Load the same file into your Go options so session creation and update use the declared policies.

```go
file, err := os.Open("session-fields.json")
if err != nil {
    return err
}
defer file.Close()
fields, err := schema.ReadSessionFields(file)
if err != nil {
    return err
}
opts.SessionAdditionalFields = fields
```

The Go equivalents are `schema.GenerateWithSessionFields`, `sqlstore.CheckSchemaWithSessionFields` and `sqlstore.OpenWithSessionFields`. [CLI lifecycle tests](../cmd/authctl/session_fields_live_test.go) · [Physical compatibility tests](../adapters/sqlstore/check_session_fields_test.go)

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
