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
| `admin` | User roles, ban status and expiration, and the administrator behind an impersonated session |
| `api-key` | User-owned application keys, digest lookup, scopes, per-key budgets and rate counters |
| `anonymous` | Anonymous-account status on the user |
| `last-login-method` | Most recent authentication method on the user |
| `device-authorization` | Expiring device grants with unique device and user codes and client binding |
| `jwt` | Public verification keys, encrypted signing keys and rotation times |
| `organization` | Organizations, memberships, invitations and active organization selection |
| `organization-teams` | Organization schema with teams, team membership, invitation team selection and active team selection |
| `passkey` | Public credentials, authenticator counters, transport hints and account ownership |
| `rate-limit` | Shared per-route counters with a unique key, request count and timestamp in milliseconds |
| `stripe-subscriptions` | Customer identifiers and subscription records with status, plan, billing and lifecycle fields |
| `two-factor` | User enrollment state, factor secrets, recovery codes and lockout fields |

Select at most one organization profile and one username profile. Run `authctl info` for the full profile list in your build, or call `schema.Profiles()` from Go. Profile order produces deterministic output. The profile selector controls database structure. See the [feature checklist](parity/README.md) for runtime support.

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

Use the [schema conformance tests](../conformance/schema.test.mjs) to inspect what the CLI and live database comparisons cover.
