# Go packages and integrations

[Feature index](README.md)

These checks exercise the Go HTTP client, router mounts and SQL drivers.

- [ ] Native Go HTTP client
  - [x] Use the typed, cookie-backed client for signup, login and session management ([test](../../client/client_test.go#L21))
  - [x] Preserve caller cancellation and HTTP error status ([test](../../client/client_test.go#L111))
  - [x] Manage accounts, recover passwords and verify authenticator and backup codes using a native client ([test](../../client/account_test.go#L21))
  - [x] Switch and revoke remembered accounts through the typed client over TLS ([test](../../plugins/multisession/multisession_test.go#L97))
  - [x] Use typed client methods for all nine team endpoints over HTTP ([test](../../adapters/sqlstore/organization_teams_test.go#L99))
- [ ] Environment configuration
  - [x] Ignore unrelated host settings when resolving the signing key, public URL, origins and runtime mode ([test](../../env_test.go#L45))
  - [x] Resolve public URL and mount path from explicit options and process settings ([test](../../env_test.go#L19))
  - [x] Give an explicit signing secret precedence over environment defaults ([test](../../env_test.go#L41))
  - [x] Combine configured origins and environment origins for callback validation ([test](../../env_test.go#L33))
  - [x] Sign with the active key and accept cookies from a retained key ([test](../../env_test.go#L79))
  - [x] Accept an email proof signed by a retained key and reject it after retirement ([test](../../env_test.go#L140))
  - [x] Select the production rate limit by default and honor an explicit override ([test](../../env_test.go#L121))
  - [x] Verify startup key selection, mount, trusted origins and client destination in an isolated Go process ([test](../../conformance/env.test.mjs#L10))
  - [x] Resolve the native client destination from an explicit URL or AUTH_URL while ignoring unrelated host settings ([test](../../client/environment_test.go#L17))
  - [x] Protect records with a purpose and an explicitly configured key version ([test](../../twofactor_test.go#L22))
- [ ] HTTP framework mounts
  - [x] ServeMux signup, session lookup and sign-out with multiple cookies ([test](../../integrations/routers/routers_test.go#L37))
  - [x] chi signup, session lookup and sign-out with multiple cookies ([test](../../integrations/routers/routers_test.go#L38))
  - [x] Gorilla signup, session lookup and sign-out with multiple cookies ([test](../../integrations/routers/routers_test.go#L39))
  - [x] Gin signup, session lookup and sign-out with multiple cookies ([test](../../integrations/routers/routers_test.go#L44))
  - [x] Fiber signup, session lookup and sign-out with multiple cookies ([test](../../integrations/routers/routers_test.go#L49))
- [ ] SQL engine contracts
  - [x] Reopen the SQLite database and read stored credentials and sessions ([test](../../adapters/sqlstore/sqlite_test.go#L85))
  - [x] Roll back registration if creating the initial session fails ([test](../../adapters/sqlstore/sqlite_test.go#L125))
  - [x] Resolve concurrent same-email signups across two database connections ([test](../../adapters/sqlstore/sqlite_test.go#L153))
  - [x] Match fresh and repeated SQLite migrations across columns, defaults, primary keys, indexes and foreign keys ([test](../../conformance/schema.test.mjs#L36))
  - [x] Commit concurrent in-memory registration atomically ([test](../../adapters/memory/memory_test.go#L16))
  - [x] Track in-process sessions through the memory adapter ([test](../../adapters/memory/memory_test.go#L47))
  - [x] Preserve a populated PostgreSQL or MySQL account and match fresh plugin tables, indexes and foreign keys after repeat migrations ([test](../../adapters/sqlstore/profiles_test.go#L14))
  - [x] Use exact case-sensitive session tokens and atomic revocation on all three SQL engines ([test](../../adapters/sqlstore/multisession_test.go#L15))
  - [x] Serialize organization-team additions, preserve seat limits and roll back failed invitations on all three SQL engines ([test](../../adapters/sqlstore/organization_teams_test.go#L21))
