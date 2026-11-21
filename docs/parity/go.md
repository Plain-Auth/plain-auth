# Go packages and integrations

[Feature index](README.md)

These checks exercise the Go HTTP client, router mounts and SQL drivers.

- [ ] Native Go HTTP client
  - [x] Use the typed, cookie-backed client for signup, login and session management ([test](../../client/client_test.go#L21))
  - [x] Preserve caller cancellation and HTTP error status ([test](../../client/client_test.go#L111))
  - [x] Manage accounts, recover passwords and verify authenticator and backup codes using a native client ([test](../../client/account_test.go#L21))
- [ ] Environment configuration
  - [x] Resolve public URL and mount path from explicit options and process settings ([test](../../env_test.go#L19))
  - [x] Give an explicit signing secret precedence over environment defaults ([test](../../env_test.go#L43))
  - [x] Combine configured origins and environment origins for callback validation ([test](../../env_test.go#L35))
  - [x] Sign with the active key and accept cookies from a retained key ([test](../../env_test.go#L58))
  - [x] Accept an email proof signed by a retained key and reject it after retirement ([test](../../env_test.go#L119))
  - [x] Select the production rate limit by default and honor an explicit override ([test](../../env_test.go#L100))
  - [x] Match host secret precedence, the active rotation key, URL aliases, and trusted origins across runtimes ([test](../../conformance/env.test.mjs#L13))
  - [x] Resolve the native client base URL and its mount path from environment settings ([test](../../client/environment_test.go#L17))
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
  - [x] Preserve a populated PostgreSQL or MySQL account and match fresh plugin tables, indexes and foreign keys after repeat migrations ([test](../../adapters/sqlstore/profiles_test.go#L15))
