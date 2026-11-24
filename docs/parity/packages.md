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
    - [x] Apply configured email-verification gates ([test](../../conformance/goapi/account_lifecycle_test.go#L15))
    - [x] Keep callback failures private and honor cancellation while password operations are queued ([test](../../conformance/goapi/password_codec_test.go#L15))
    - [x] Keep failed version lookup retryable and issue a snapshot only for the stored ordinary profile ([test](../../session_cache_version_test.go#L147))
    - [x] Keep private duplicate observers and password recovery independent of cache version callbacks until a real session is issued ([test](../../client/session_cache_version_test.go#L88))
    - [x] Round-trip configured profile values, private inputs, required fields and server-owned signup defaults on shared SQLite ([test](../../conformance/user-fields.mjs#L32))
    - [x] Keep another account’s profile and hidden inputs out of protected duplicate signup and verification output ([test](../../adapters/sqlstore/user_fields_test.go#L264))
    - [x] ValidateUserInfo refuses an email sign-up with a 403, or with the private duplicate answer in protected mode ([test](../../conformance/goapi/user_validation_test.go#L62))
    - [x] Return the signed-in user and session with the default seven-day lifetime ([test](../../conformance/core.test.mjs#L195))
    - [x] Support the sliding session window, deferred writes and expiration ([test](../../session_refresh_test.go#L46))
    - [x] Expose the application credential type and keep the presented key out of browser session lookup ([test](../../adapters/sqlstore/apikey_session_test.go#L215))
    - [x] Compare ordinary GET and deferred POST without the projection on both runtimes ([test](../../conformance/custom-session-contract.mjs#L113))
    - [x] Force live reads on request and preserve the exact signed cache deadline while a browser view remains cacheable ([test](../../session_cache_compact_test.go#L135))
    - [x] Retain live JWT issuance, protected session checks and administrative controls after a physical schema migration on another node ([test](../../adapters/sqlstore/session_cache_test.go#L135))
    - [x] Compare deferred GET and POST cache hits, forced store reads and independent renewal flags on both runtimes ([test](../../conformance/session-cache-compact.mjs#L138))
    - [x] Use live authorization on independently opened JWT and administration nodes for signed or encrypted session views ([test](../../adapters/sqlstore/session_cache_test.go#L20))
    - [x] Read configured user fields under their logical names and keep hidden storage values out of session views ([test](../../adapters/sqlstore/user_fields_test.go#L47))
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
  - Client-side plugin registration (`./client/plugins`) — *not applicable: JavaScript only*
  - [ ] Configuration and result types (`./types`)
  - [ ] Cryptographic functions (`./crypto`)
  - [ ] Session cookie handling (`./cookies`)
  - [ ] Cookie parsing and serialization (`./cookies/utils`)
  - [ ] OAuth protocol operations (`./oauth2`)
  - React client hooks (`./react`) — *not applicable: JavaScript only*
  - Solid client bindings (`./solid`) — *not applicable: JavaScript only*
  - Lynx client bindings (`./lynx`) — *not applicable: JavaScript only*
  - [ ] Authentication test fixtures (`./test`)
  - [ ] Programmatic API (`./api`)
  - [ ] Database interfaces (`./db`)
  - Vue client bindings (`./vue`) — *not applicable: JavaScript only*
  - [ ] Plugin registration (`./plugins`)
  - SvelteKit request handling (`./svelte-kit`) — *not applicable: JavaScript only*
  - SolidStart request handling (`./solid-start`) — *not applicable: JavaScript only*
  - Svelte client bindings (`./svelte`) — *not applicable: JavaScript only*
  - Next.js request handling (`./next-js`) — *not applicable: JavaScript only*
  - TanStack Start request handling (`./tanstack-start`) — *not applicable: JavaScript only*
  - TanStack Start for Solid (`./tanstack-start/solid`) — *not applicable: JavaScript only*
  - Node host integration (`./node`) — *not applicable: JavaScript only*
  - [ ] Database adapter contract (`./db/adapter`)
  - [ ] Minimal database adapter contract (`./db/adapter/minimal`)
  - [ ] Schema discovery and migration (`./db/migration`)
    - [x] Emit SQL DDL for SQLite, PostgreSQL and MySQL ([test](../../cmd/authctl/main_test.go#L29))
    - [x] Compare every base-profile combination and independent SCIM profile witnesses across all three dialects ([test](../../conformance/schema.test.mjs#L106))
    - [x] Prove SCIM adds exactly seven disjoint tables and preserves every preexisting schema statement ([test](../../conformance/schema.test.mjs#L169))
    - [x] Generate the optional Polar checkout and delivery tables on every SQL dialect ([test](../../cmd/authctl/main_test.go#L79))
    - [x] Emit physical columns from a JSON field definition for each supported SQL dialect ([test](../../cmd/authctl/session_fields_test.go#L13))
    - [x] Generate the selected plugin schema with independent user and session JSON declarations on all three dialects ([test](../../cmd/authctl/user_fields_test.go#L111))
    - [x] Generate the configured wallet model alongside user and session fields from one portable JSON declaration ([test](../../cmd/authctl/wallet_schema_test.go#L124))
    - [x] Generate typed date columns for both models on each SQL dialect and reject invalid static timestamps ([test](../../cmd/authctl/user_fields_test.go#L205))
  - Adapter binding for prisma (`./adapters/prisma`) — *not applicable: JavaScript only*
  - Adapter binding for drizzle (`./adapters/drizzle`) — *not applicable: JavaScript only*
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
  - [x] Plugin interface for oauth proxy (`./plugins/oauth-proxy`) ([test](../../adapters/sqlstore/oauth_proxy_test.go#L42))
    - [x] Initialize the Go plugin and complete a browser-bound authorization across separate stores ([test](../../adapters/sqlstore/oauth_proxy_test.go#L42))
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
  - Node host integration (`./node`) — *not applicable: JavaScript only*

## Command-line tools

- [ ] Command-line tools
  - [ ] Programmatic API (`./api`)

## Core authentication contracts

- [ ] Core authentication contracts
  - [ ] Default interface (`.`)
  - [ ] Programmatic API (`./api`)
  - [ ] Request-local execution context (`./async_hooks`)
    - Runtime target node — *not applicable: JavaScript runtime*
    - Runtime target deno — *not applicable: JavaScript runtime*
    - Runtime target bun — *not applicable: JavaScript runtime*
    - Runtime target workerd — *not applicable: JavaScript runtime*
    - Runtime target edge — *not applicable: JavaScript runtime*
    - Runtime target browser — *not applicable: JavaScript runtime*
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
    - Runtime target workerd — *not applicable: JavaScript runtime*
    - Runtime target edge — *not applicable: JavaScript runtime*
    - Runtime target browser — *not applicable: JavaScript runtime*
    - Runtime target node — *not applicable: JavaScript runtime*
    - Runtime target deno — *not applicable: JavaScript runtime*
    - Runtime target bun — *not applicable: JavaScript runtime*
    - Runtime target import — *not applicable: JavaScript runtime*

## Drizzle adapter

- Drizzle adapter — *not applicable: JavaScript only*
  - Default interface (`.`)
  - Relations v2 (`./relations-v2`)

## Electron integration

- [ ] Electron integration
  - [ ] Default interface (`.`)
  - Client integration (`./client`) — *not applicable: JavaScript only*
  - Browser-to-desktop proxy (`./proxy`) — *not applicable: JavaScript only*
  - Renderer preload bridge (`./preload`) — *not applicable: JavaScript only*
  - Desktop credential storage (`./storage`) — *not applicable: JavaScript only*

## Expo integration

- [ ] Expo integration
  - [ ] Default interface (`.`)
  - Client integration (`./client`) — *not applicable: JavaScript only*
  - Plugin registration (`./plugins`) — *not applicable: JavaScript only*

## Localization

- [ ] Localization
  - [ ] Default interface (`.`)
    - [x] Read translated errors through real HTTP on both runtimes ([test](../../conformance/i18n-contract.mjs#L26))
  - [ ] Client integration (`./client`)
    - [x] Read the translated message, original message, stable code and HTTP status through the published browser client ([test](../../conformance/i18n-contract.mjs#L26))
  - [ ] Bundled locale dictionaries (`./locales`)

## Kysely adapter

- Kysely adapter — *not applicable: JavaScript only*
  - Default interface (`.`)
  - Node SQLite dialect (`./node-sqlite-dialect`)

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

- Prisma adapter — *not applicable: JavaScript only*
  - Default interface (`.`)

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
    - [x] Register persisted OIDC providers and read sanitized configuration through the official client on both implementations ([test](../../conformance/sso-providers.mjs#L12))
    - [x] Create reusable enterprise sessions through both browser callback routes while preserving a single linked account ([test](../../conformance/sso-browser.mjs#L43))
    - [x] Require each domain to publish the token and accept split TXT character strings and labeled values ([test](../../conformance/sso-domains.mjs#L92))
  - [ ] Client integration (`./client`)

## Stripe billing

- [ ] Stripe billing
  - [ ] Default interface (`.`)
    - [x] Reserve an owner-scoped checkout, send the configured recurring price and return the same checkout on retries ([test](../../adapters/sqlstore/subscriptions_test.go#L211))
    - [x] Reuse an existing Stripe customer when starting a monthly subscription ([test](../../adapters/sqlstore/subscriptions_test.go#L348))
    - [x] Match the browser client's session, customer-type and foreign-reference errors before contacting Stripe ([test](../../conformance/stripe-lifecycle-fixture.mjs#L211))
    - [x] Reject a missing plan and a subscription owned by another signed-in user ([test](../../conformance/stripe-lifecycle-fixture.mjs#L193))
    - [x] Open monthly and annual confirmation pages for the owner’s existing subscription and preserve its price until Stripe confirms ([test](../../conformance/stripe-lifecycle-fixture.mjs#L270))
    - [x] Reject pending changes, unsupported recurring items, foreign customers and a session revoked during Stripe’s reply on three SQL engines ([test](../../adapters/sqlstore/stripe_plan_change_test.go#L105))
    - [x] Schedule a configured annual price at the current period boundary with no proration and observe the signed transition through the browser client ([test](../../conformance/stripe-lifecycle-fixture.mjs#L388))
    - [x] Recover lost create, update and release responses, reject competing destinations and preserve custom phases on three SQL engines ([test](../../adapters/sqlstore/stripe_schedules_test.go#L181))
    - [x] Use the active or selected organization for single-seat checkout and keep its Stripe customer separate from personal accounts ([test](../../conformance/stripe-organization-fixture.mjs#L134))
    - [x] Recheck membership and active organization around Stripe responses, recover checkout under a different administrator, and refuse ambiguous customer ownership on three SQL engines ([test](../../adapters/sqlstore/stripe_organization_test.go#L24))
    - [x] Open an annual price confirmation for the selected organization and its existing subscription item ([test](../../adapters/sqlstore/stripe_organization_management_test.go#L167))
    - [x] Schedule a single-seat annual organization plan and reconcile its signed phase transition through the browser client ([test](../../conformance/stripe-lifecycle-fixture.mjs#L465))
    - [x] Reserve an explicit seat quantity, reject a conflicting retry and preserve single-seat reservations from earlier releases ([test](../../adapters/sqlstore/subscriptions_test.go#L295))
    - [x] Verify a five-seat organization purchase and read the eight seats already active when the webhook arrives ([test](../../conformance/stripe-organization-fixture.mjs#L158))
    - [x] Open a hosted confirmation for a quantity-only change and suppress the link if the existing quantity changes concurrently ([test](../../adapters/sqlstore/stripe_plan_change_test.go#L225))
    - [x] Propose one seat when quantity is omitted and keep all five existing seats until the customer confirms ([test](../../conformance/stripe-lifecycle-fixture.mjs#L265))
    - [x] Count organization members for a monthly licensed checkout and ignore the caller’s seat override ([test](../../conformance/stripe-organization-fixture.mjs#L190))
    - [x] Purchase one fixed monthly base unit and a separate licensed unit for each member with the browser client ([test](../../conformance/stripe-organization-fixture.mjs#L188))
    - [x] Bind both price IDs across a lost Checkout response, reject a repriced retry and resume on a second server ([test](../../adapters/sqlstore/stripe_seats_test.go#L267))
    - [x] Pair an annual base and a separate yearly member price through the public client and retain annual terms after membership changes ([test](../../conformance/stripe-organization-fixture.mjs#L186))
    - [x] Charge a single yearly item at the organization member count and synchronize that same item after a member joins or leaves ([test](../../conformance/stripe-organization-fixture.mjs#L184))
    - [x] Buy a configured annual metered price through the browser client and omit the Checkout item quantity even when the caller specifies seats ([test](../../conformance/stripe-organization-fixture.mjs#L262))
    - [x] Retry the original monthly or annual metered purchase across replicas using the native Go client and three SQL engines ([test](../../adapters/sqlstore/stripe_metered_test.go#L130))
    - [x] Leave the database free of an ambiguous purchase if the provider cannot identify the price’s billing mode ([test](../../adapters/sqlstore/stripe_metered_test.go#L118))
    - [x] Buy a licensed base and two fixed metered add-ons for a personal or organization account, sending a quantity only for the base ([test](../../conformance/stripe-organization-fixture.mjs#L256))
    - [x] Replay the exact original add-on basket after a lost Checkout response on independent SQL connections ([test](../../adapters/sqlstore/stripe_addons_test.go#L158))
    - [x] Offer the configured trial only for a new personal or organization billing reference with no trial history across plans ([test](../../conformance/stripe-organization-fixture.mjs#L392))
  - [ ] Client integration (`./client`)

## Telemetry

- [ ] Telemetry
  - [ ] Default interface (`.`)
    - Runtime target node — *not applicable: JavaScript runtime*

## Adapter and provisioning test utilities

- [ ] Adapter and provisioning test utilities
  - [ ] Database adapter contract tests (`./adapter`)
  - [ ] SCIM lifecycle test helpers (`./scim`)
