# Published package interfaces

[Feature index](README.md)

Each row tracks the behavior exposed by a published entry point. The Go implementation can provide that behavior through a native package, HTTP endpoint or client integration. The [maintainer catalog](../../conformance/reference.json) records exact package coordinates, source files, runtime conditions and named exports. The checks below link to tested behavior.

## API keys

- [ ] API keys
  - [ ] Default interface (`.`)
    - [x] Issue a user-owned key and return its secret to the official client ([test](../../conformance/core.test.mjs#L866))
    - [x] Issue a key whose reference identifies the caller’s organization ([test](../../conformance/core.test.mjs#L938))
  - [ ] Client integration (`./client`)
    - [x] Create, retrieve, update, list and revoke user-owned keys with the official client ([test](../../conformance/core.test.mjs#L866))
    - [x] Manage organization keys alongside separately authenticated automation clients ([test](../../conformance/core.test.mjs#L917))
  - [ ] Configuration and result types (`./types`)

## Authentication server and framework bindings

- [ ] Authentication server and framework bindings
  - [ ] Default interface (`.`)
    - [x] Create a password account and return a usable session token on SQLite ([test](../../conformance/core.test.mjs#L193))
    - [x] Apply configured email-verification gates ([test](../../account_lifecycle_test.go#L15))
    - [x] Return the signed-in user and session with the default seven-day lifetime ([test](../../conformance/core.test.mjs#L195))
    - [x] Support the sliding session window, deferred writes and expiration ([test](../../session_refresh_test.go#L46))
    - [x] Expose the application credential type and keep the presented key out of browser session lookup ([test](../../adapters/sqlstore/apikey_session_test.go#L201))
  - [ ] Minimal server initialization (`./minimal`)
  - [ ] Social provider registration and profiles (`./social-providers`)
    - [x] Verify the signature and claims of a Google ID token against a test issuer ([test](../../providers/providers_test.go#L19))
  - [ ] Client integration (`./client`)
    - [x] Use the typed, cookie-backed client for signup, login and session management ([test](../../client/client_test.go#L21))
    - [x] Preserve caller cancellation and HTTP error status ([test](../../client/client_test.go#L111))
    - [x] Manage accounts, recover passwords and verify authenticator and backup codes using a native client ([test](../../client/account_test.go#L21))
    - [x] Switch and revoke remembered accounts through the typed client over TLS ([test](../../plugins/multisession/multisession_test.go#L97))
    - [x] Use typed client methods for all nine team endpoints over HTTP ([test](../../adapters/sqlstore/organization_teams_test.go#L99))
    - [x] Manage and revoke administrative sessions through the typed cookie-backed client ([test](../../adapters/sqlstore/admin_test.go#L21))
    - [x] Use the typed client to register, sign in, rename a public handle and query availability ([test](../../adapters/sqlstore/username_test.go#L23))
  - [ ] Client-side plugin registration (`./client/plugins`)
  - [ ] Configuration and result types (`./types`)
  - [ ] Cryptographic functions (`./crypto`)
  - [ ] Session cookie handling (`./cookies`)
  - [ ] Cookie parsing and serialization (`./cookies/utils`)
  - [ ] OAuth protocol operations (`./oauth2`)
  - [ ] React client hooks (`./react`)
  - [ ] Solid client bindings (`./solid`)
  - [ ] Lynx client bindings (`./lynx`)
  - [ ] Authentication test fixtures (`./test`)
  - [ ] Programmatic API (`./api`)
  - [ ] Database interfaces (`./db`)
  - [ ] Vue client bindings (`./vue`)
  - [ ] Plugin registration (`./plugins`)
  - [ ] SvelteKit request handling (`./svelte-kit`)
  - [ ] SolidStart request handling (`./solid-start`)
  - [ ] Svelte client bindings (`./svelte`)
  - [ ] Next.js request handling (`./next-js`)
  - [ ] TanStack Start request handling (`./tanstack-start`)
  - [ ] TanStack Start for Solid (`./tanstack-start/solid`)
  - [ ] Node host integration (`./node`)
  - [ ] Database adapter contract (`./db/adapter`)
  - [ ] Minimal database adapter contract (`./db/adapter/minimal`)
  - [ ] Schema discovery and migration (`./db/migration`)
    - [x] Emit SQL DDL for SQLite, PostgreSQL and MySQL ([test](../../cmd/authctl/main_test.go#L28))
    - [x] Compare every base-profile combination and independent SCIM profile witnesses across all three dialects ([test](../../conformance/schema.test.mjs#L106))
    - [x] Prove SCIM adds exactly seven disjoint tables and preserves every preexisting schema statement ([test](../../conformance/schema.test.mjs#L169))
  - [ ] Adapter binding for prisma (`./adapters/prisma`)
  - [ ] Adapter binding for drizzle (`./adapters/drizzle`)
  - [ ] Adapter binding for mongodb (`./adapters/mongodb`)
  - [ ] Adapter binding for memory (`./adapters/memory`)
  - [ ] Database adapter selection (`./adapters`)
  - [ ] Plugin interface for access (`./plugins/access`)
    - [x] Check all or any requested actions across resources and reject empty or ungranted requests ([test](../../plugins/access/access_test.go#L12))
    - [x] Compare nested permission decisions with the pinned client using the same test cases ([test](../../conformance/access.test.mjs#L6))
  - [ ] Plugin interface for admin (`./plugins/admin`)
  - [ ] Plugin interface for admin permissions (`./plugins/admin/access`)
  - [ ] Plugin interface for anonymous (`./plugins/anonymous`)
  - [ ] Plugin interface for bearer (`./plugins/bearer`)
  - [ ] Plugin interface for captcha (`./plugins/captcha`)
  - [ ] Plugin interface for custom session (`./plugins/custom-session`)
  - [ ] Plugin interface for email otp (`./plugins/email-otp`)
  - [ ] Plugin interface for generic oauth (`./plugins/generic-oauth`)
  - [ ] Plugin interface for jwt (`./plugins/jwt`)
  - [ ] Plugin interface for haveibeenpwned (`./plugins/haveibeenpwned`)
  - [ ] Plugin interface for magic link (`./plugins/magic-link`)
  - [ ] Plugin interface for multi session (`./plugins/multi-session`)
  - [ ] Plugin interface for oauth proxy (`./plugins/oauth-proxy`)
  - [ ] Plugin interface for organization (`./plugins/organization`)
  - [ ] Plugin interface for organization permissions (`./plugins/organization/access`)
  - [ ] Plugin interface for one time token (`./plugins/one-time-token`)
  - [ ] Plugin interface for one tap (`./plugins/one-tap`)
  - [ ] Plugin interface for open api (`./plugins/open-api`)
  - [ ] Plugin interface for phone number (`./plugins/phone-number`)
  - [ ] Plugin interface for two factor (`./plugins/two-factor`)
  - [ ] Plugin interface for username (`./plugins/username`)
  - [ ] Plugin interface for siwe (`./plugins/siwe`)
  - [ ] Plugin interface for device authorization (`./plugins/device-authorization`)

## Client ID metadata documents

- [ ] Client ID metadata documents
  - [ ] Default interface (`.`)
  - [ ] Node host integration (`./node`)

## Command-line tools

- [ ] Command-line tools
  - [ ] Programmatic API (`./api`)

## Core authentication contracts

- [ ] Core authentication contracts
  - [ ] Default interface (`.`)
  - [ ] Programmatic API (`./api`)
  - [ ] Request-local execution context (`./async_hooks`)
    - [ ] Runtime target node
    - [ ] Runtime target deno
    - [ ] Runtime target bun
    - [ ] Runtime target workerd
    - [ ] Runtime target edge
    - [ ] Runtime target browser
  - [ ] Authentication context (`./context`)
  - [ ] Environment configuration (`./env`)
    - [x] Ignore unrelated host settings when resolving the signing key, public URL, origins and runtime mode ([test](../../env_test.go#L46))
    - [x] Resolve public URL and mount path from explicit options and process settings ([test](../../env_test.go#L20))
    - [x] Use Options.Secret ahead of AUTH_SECRET when no key list is configured ([test](../../env_test.go#L42))
    - [x] Sign with the configured key list ahead of single secrets and prefer the explicit list ([test](../../env_test.go#L194))
    - [x] Combine configured origins and environment origins for callback validation ([test](../../env_test.go#L34))
    - [x] Sign with the active key and accept cookies from a retained key ([test](../../env_test.go#L80))
    - [x] Accept an email proof signed by a retained key and reject it after retirement ([test](../../env_test.go#L141))
    - [x] Select the production rate limit by default and honor an explicit override ([test](../../env_test.go#L122))
    - [x] Verify startup key selection, mount, trusted origins and client destination in an isolated Go process ([test](../../conformance/env.test.mjs#L10))
    - [x] Resolve the native client destination from an explicit URL or AUTH_URL while ignoring unrelated host settings ([test](../../client/environment_test.go#L17))
    - [x] Protect records with a purpose and an explicitly configured key version ([test](../../twofactor_test.go#L22))
  - [ ] Error representation (`./error`)
  - [ ] Shared utilities for async (`./utils/async`)
  - [ ] Shared utilities for db (`./utils/db`)
  - [ ] Shared utilities for deprecate (`./utils/deprecate`)
  - [ ] Shared utilities for email (`./utils/email`)
  - [ ] Shared utilities for error codes (`./utils/error-codes`)
  - [ ] Shared utilities for fetch metadata (`./utils/fetch-metadata`)
  - [ ] Shared utilities for host (`./utils/host`)
  - [ ] Shared utilities for id (`./utils/id`)
  - [ ] Shared utilities for ip (`./utils/ip`)
  - [ ] Shared utilities for is api error (`./utils/is-api-error`)
  - [ ] Shared utilities for json (`./utils/json`)
  - [ ] Shared utilities for redirect uri (`./utils/redirect-uri`)
  - [ ] Shared utilities for state (`./utils/state`)
  - [ ] Shared utilities for string (`./utils/string`)
  - [ ] Shared utilities for url (`./utils/url`)
  - [ ] Social provider registration and profiles (`./social-providers`)
  - [ ] Database interfaces (`./db`)
  - [ ] Underlying database operations (`./db/internal`)
  - [ ] Database adapter contract (`./db/adapter`)
  - [ ] OAuth protocol operations (`./oauth2`)
  - [ ] Underlying OAuth operations (`./oauth2/internal`)
  - [ ] Instrumentation and tracing (`./instrumentation`)
    - [ ] Runtime target workerd
    - [ ] Runtime target edge
    - [ ] Runtime target browser
    - [ ] Runtime target node
    - [ ] Runtime target deno
    - [ ] Runtime target bun
    - [ ] Runtime target import

## Drizzle adapter

- [ ] Drizzle adapter
  - [ ] Default interface (`.`)
  - [ ] Relations v2 (`./relations-v2`)

## Electron integration

- [ ] Electron integration
  - [ ] Default interface (`.`)
  - [ ] Client integration (`./client`)
  - [ ] Browser-to-desktop proxy (`./proxy`)
  - [ ] Renderer preload bridge (`./preload`)
  - [ ] Desktop credential storage (`./storage`)

## Expo integration

- [ ] Expo integration
  - [ ] Default interface (`.`)
  - [ ] Client integration (`./client`)
  - [ ] Plugin registration (`./plugins`)

## Localization

- [ ] Localization
  - [ ] Default interface (`.`)
    - [x] Read translated errors through real HTTP on both runtimes ([test](../../conformance/i18n-contract.mjs#L26))
  - [ ] Client integration (`./client`)
    - [x] Read the translated message, original message, stable code and HTTP status through the published browser client ([test](../../conformance/i18n-contract.mjs#L26))
  - [ ] Bundled locale dictionaries (`./locales`)

## Kysely adapter

- [ ] Kysely adapter
  - [ ] Default interface (`.`)
  - [ ] Node SQLite dialect (`./node-sqlite-dialect`)

## Model Context Protocol

- [ ] Model Context Protocol
  - [ ] Default interface (`.`)

## In-memory adapter

- [ ] In-memory adapter
  - [ ] Default interface (`.`)

## MongoDB adapter

- [ ] MongoDB adapter
  - [ ] Default interface (`.`)

## OAuth authorization server

- [ ] OAuth authorization server
  - [ ] Default interface (`.`)
  - [ ] Client integration (`./client`)
  - [ ] Protected resource client (`./resource-client`)
  - [ ] Low-level protocol operations (`./internal`)

## Passkeys

- [ ] Passkeys
  - [ ] Default interface (`.`)
    - [x] List only credentials owned by the authenticated account ([test](../../adapters/sqlstore/passkey_test.go#L256))
  - [ ] Client integration (`./client`)

## Prisma adapter

- [ ] Prisma adapter
  - [ ] Default interface (`.`)

## Redis secondary storage

- [ ] Redis secondary storage
  - [ ] Default interface (`.`)
    - [x] Store expiring values and enforce distributed rate limits using the optional Redis module ([test](../../adapters/redis/storage_test.go#L299))

## SCIM provisioning

- [ ] SCIM provisioning
  - [ ] Default interface (`.`)
    - [x] Provision and synchronize directory Users over authenticated SCIM HTTP using compatible SQL records ([test](../../conformance/scim-contract.mjs#L45))
    - [x] Exchange canonical Group and membership records with the reference runtime ([test](../../conformance/scim-contract.mjs#L92))
    - [x] Issue, rotate, authenticate and revoke managed directory credentials from either runtime on shared SQLite ([test](../../conformance/scim-managed.mjs#L13))
    - [x] Retire managed directories across runtimes and retain their canonical status and audit records ([test](../../conformance/core.test.mjs#L1037))

## Single sign-on

- [ ] Single sign-on
  - [ ] Default interface (`.`)
    - [x] Register persisted OIDC providers and read sanitized configuration through the official client on both implementations ([test](../../conformance/sso-providers.mjs#L11))
    - [x] Create reusable enterprise sessions through both browser callback routes while preserving a single linked account ([test](../../conformance/sso-browser.mjs#L13))
  - [ ] Client integration (`./client`)

## Stripe billing

- [ ] Stripe billing
  - [ ] Default interface (`.`)
    - [x] Reserve an owner-scoped checkout, send the configured recurring price and return the same checkout on retries ([test](../../adapters/sqlstore/subscriptions_test.go#L209))
    - [x] Reuse an existing Stripe customer when starting a monthly subscription ([test](../../adapters/sqlstore/subscriptions_test.go#L346))
    - [x] Match the browser client's session, customer-type and foreign-reference errors before contacting Stripe ([test](../../conformance/stripe-lifecycle-fixture.mjs#L210))
    - [x] Reject a missing plan and a subscription owned by another signed-in user ([test](../../conformance/stripe-lifecycle-fixture.mjs#L192))
    - [x] Open monthly and annual confirmation pages for the owner’s existing subscription and preserve its price until Stripe confirms ([test](../../conformance/stripe-lifecycle-fixture.mjs#L269))
    - [x] Reject pending changes, unsupported recurring items, foreign customers and a session revoked during Stripe’s reply on three SQL engines ([test](../../adapters/sqlstore/stripe_plan_change_test.go#L105))
    - [x] Schedule a configured annual price at the current period boundary with no proration and observe the signed transition through the browser client ([test](../../conformance/stripe-lifecycle-fixture.mjs#L387))
    - [x] Recover lost create, update and release responses, reject competing destinations and preserve custom phases on three SQL engines ([test](../../adapters/sqlstore/stripe_schedules_test.go#L181))
    - [x] Use the active or selected organization for single-seat checkout and keep its Stripe customer separate from personal accounts ([test](../../conformance/stripe-organization-fixture.mjs#L99))
    - [x] Recheck membership and active organization around Stripe responses, recover checkout under a different administrator, and refuse ambiguous customer ownership on three SQL engines ([test](../../adapters/sqlstore/stripe_organization_test.go#L24))
    - [x] Open an annual price confirmation for the selected organization and its existing subscription item ([test](../../adapters/sqlstore/stripe_organization_management_test.go#L167))
    - [x] Schedule a single-seat annual organization plan and reconcile its signed phase transition through the browser client ([test](../../conformance/stripe-lifecycle-fixture.mjs#L464))
    - [x] Reserve an explicit seat quantity, reject a conflicting retry and preserve single-seat reservations from earlier releases ([test](../../adapters/sqlstore/subscriptions_test.go#L293))
    - [x] Verify a five-seat organization purchase and read the eight seats already active when the webhook arrives ([test](../../conformance/stripe-organization-fixture.mjs#L123))
    - [x] Open a hosted confirmation for a quantity-only change and suppress the link if the existing quantity changes concurrently ([test](../../adapters/sqlstore/stripe_plan_change_test.go#L225))
    - [x] Propose one seat when quantity is omitted and keep all five existing seats until the customer confirms ([test](../../conformance/stripe-lifecycle-fixture.mjs#L264))
    - [x] Count organization members for a monthly licensed checkout and ignore the caller’s seat override ([test](../../conformance/stripe-organization-fixture.mjs#L151))
    - [x] Purchase one fixed monthly base unit and a separate licensed unit for each member with the browser client ([test](../../conformance/stripe-organization-fixture.mjs#L149))
    - [x] Bind both price IDs across a lost Checkout response, reject a repriced retry and resume on a second server ([test](../../adapters/sqlstore/stripe_seats_test.go#L238))
  - [ ] Client integration (`./client`)

## Telemetry

- [ ] Telemetry
  - [ ] Default interface (`.`)
    - [ ] Runtime target node

## Adapter and provisioning test utilities

- [ ] Adapter and provisioning test utilities
  - [ ] Database adapter contract tests (`./adapter`)
  - [ ] SCIM lifecycle test helpers (`./scim`)
