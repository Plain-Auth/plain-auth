# Reference and configuration

[Feature index](README.md)

## account_already_linked_to_different_user

- [ ] account_already_linked_to_different_user
  - [ ] What is it?
  - [ ] How to resolve
    - [ ] Typical resolutions
    - [ ] Common Causes
    - [ ] Safer patterns and prevention
    - [ ] Debug locally
    - [ ] Provider considerations

## account_not_linked

- [ ] account_not_linked
  - [ ] What is it?
  - [ ] Common Causes
  - [ ] How to resolve
    - [ ] Enable or configure account linking
    - [ ] Verify user identity matching
    - [ ] Prompt user action
    - [ ] Review configuration consistency

## email_doesn't_match

- [ ] email_doesn't_match
  - [ ] What is it?
  - [ ] Common Causes
  - [ ] How to resolve
    - [ ] Ask the user to align identities
    - [ ] Debug locally

## email_not_found

- [ ] email_not_found
  - [ ] What is it?
  - [ ] Common Causes
  - [ ] How to resolve
    - [ ] Request the correct scopes
    - [ ] Verify provider app/dashboard settings
    - [ ] Debug locally

## Errors

- [ ] Errors
  - [ ] List of errors

## internal_server_error

- [ ] internal_server_error
  - [ ] How to fix

## invalid_callback_request

- [ ] invalid_callback_request
  - [ ] What is it?
  - [ ] Common Causes
  - [ ] How to resolve
    - [ ] Verify callback method and parameters
    - [ ] Preserve query/body through infrastructure
    - [ ] Debug locally
    - [ ] Edge cases to consider

## invalid_code

- [ ] invalid_code
  - [ ] How to fix

## no_callback_url

- [ ] no_callback_url
  - [ ] What is it?
  - [ ] Common Causes
  - [ ] How to resolve
    - [ ] Start the flow through authentication

## no_code

- [ ] no_code
  - [ ] What is it?
  - [ ] Common Causes
  - [ ] How to resolve
    - [ ] Use the standard Authorization Code flow
    - [ ] Verify callback URL and parameter delivery
  - [ ] Debug locally

## oauth_provider_not_found

- [ ] oauth_provider_not_found
  - [ ] What is it?
  - [ ] Common Causes
  - [ ] How to resolve
    - [ ] Use the correct callback route shape
    - [ ] Configure infrastructure to preserve the path
    - [ ] Avoid manual access to the base callback route
  - [ ] Debug locally
  - [ ] Edge cases to consider

## signup_disabled

- [ ] signup_disabled
  - [ ] How to fix

## state_invalid

- [ ] state_invalid
  - [ ] What is it?
  - [ ] Common Causes
  - [ ] How to resolve
    - [ ] Avoid rotating secrets during active flows
    - [ ] Check proxies and middleware
    - [ ] Verify cookie names and values
    - [ ] Switch to the database strategy

## state_mismatch

- [ ] state_mismatch
  - [ ] What is it?
  - [ ] Error codes at a glance
    - [ ] `state_mismatch`
    - [ ] `state_invalid`
    - [ ] `state_security_mismatch`
    - [ ] `state_generation_error`
  - [ ] `state_mismatch` - verification not found (database strategy)
    - [ ] Common causes
    - [ ] How to fix
  - [ ] `state_mismatch` - auth state cookie not found (cookie strategy)
    - [ ] Common causes
    - [ ] How to fix
  - [ ] `state_mismatch` - request expired
    - [ ] Common causes
    - [ ] How to fix
  - [ ] `state_invalid` - failed to decrypt or parse (cookie strategy)
    - [ ] Common causes
    - [ ] How to fix
  - [ ] `state_security_mismatch` - state not persisted correctly (database strategy)
    - [ ] Common causes
    - [ ] How to fix
  - [ ] `state_generation_error` - unable to create verification
    - [ ] Common causes
    - [ ] How to fix
  - [ ] Common causes and fixes
    - [ ] Very high
    - [ ] High
    - [ ] Medium
    - [ ] Low
    - [ ] Very low
  - [ ] Debugging checklist

## state_not_found

- [ ] state_not_found
  - [ ] What is it?
  - [ ] Common Causes
  - [ ] How to resolve
    - [ ] Start the flow via authentication APIs
    - [ ] Verify the callback URL and method
    - [ ] Check proxies, rewrites, and middleware
    - [ ] Debug locally
    - [ ] Edge cases to consider

## unable_to_create_session

- [ ] unable_to_create_session
  - [ ] What is it?
  - [ ] Common Causes
  - [ ] How to resolve
    - [ ] Verify database and session storage
    - [ ] Check schema and migrations
    - [ ] Review configuration
    - [ ] Inspect logs

## unable_to_create_user

- [ ] unable_to_create_user
  - [ ] What is it?
  - [ ] Common Causes
  - [ ] How to resolve
    - [ ] Verify database connectivity
    - [ ] Validate schema and constraints
    - [ ] Run migrations
    - [ ] Review custom hooks
    - [ ] Inspect logs

## unable_to_get_user_info

- [ ] unable_to_get_user_info
  - [ ] What is it?
  - [ ] Common Causes
  - [ ] How to resolve
    - [ ] Request the right data
    - [ ] Verify configuration and environment

## unable_to_link_account

- [ ] unable_to_link_account
  - [ ] What is it?
  - [ ] Common Causes
  - [ ] How to resolve
    - [ ] Allow linking for the intended provider
    - [ ] Fix database reliability and constraints
    - [ ] Verify environment configuration

## Unknown error

- [ ] Unknown error

## Instrumentation (Experimental)

- [ ] Instrumentation (Experimental)
  - [ ] Setup
    - [ ] Node.js getting started
  - [ ] Disable Instrumentation
  - [ ] Supported Spans
    - [ ] Endpoint Spans
      - [ ] `{METHOD} {route}`
      - [ ] `handler {route}`
      - [ ] Attributes:
      - [ ] `http.route`
      - [ ] `auth.operation_id`
      - [ ] `hook before {route} {source}`
      - [ ] `hook after {route} {source}`
      - [ ] `auth.hook.type`
      - [ ] `auth.context`
      - [ ] `onRequest {pluginId}`
      - [ ] `onResponse {pluginId}`
      - [ ] `middleware {route} {pluginId}`
      - [ ] `http.response.status_code`
    - [ ] Database Spans
      - [ ] `db {operation} {model}`
      - [ ] Attributes:
      - [ ] `db.operation.name`
      - [ ] `db.collection.name`
      - [ ] `db {operation}.before {model}`
      - [ ] `db {operation}.after {model}`
      - [ ] `auth.hook.type`
      - [ ] `auth.context`

## Options

- [ ] Options
  - [ ] `appName`
  - [ ] `baseURL`
    - [x] Resolve public URL and mount path from explicit options and process settings ([test](../../env_test.go#L20))
    - [ ] Dynamic Base URL
      - [ ] `allowedHosts`
      - [ ] `protocol`
      - [ ] `fallback`
  - [ ] `basePath`
    - [x] Resolve public URL and mount path from explicit options and process settings ([test](../../env_test.go#L20))
  - [ ] `trustedOrigins`
    - [x] Combine configured origins and environment origins for callback validation ([test](../../env_test.go#L34))
    - [ ] Static Origins
    - [ ] Dynamic Origins
      - [ ] On a direct `auth.api` call with a static `baseURL`
    - [ ] Wildcard Support
      - [x] Compare cookie-authenticated mutations and absolute login callback decisions for HTTP(S) wildcard origins on both servers ([test](../../conformance/trusted-origins.mjs#L76))
      - [ ] Pattern Syntax
        - [x] Separate hostname and port matching and restrict numeric address patterns to IPv4 ([test](../../trusted_origins_test.go#L11))
        - [ ] `?`
        - [ ] `*`
        - [ ] ``
      - [ ] Pattern Examples
        - [ ] `http://*.example.com`
        - [ ] `https://.example.com`
        - [ ] `https://example.com`
        - [ ] `exp://192.168.*.*:*/`
        - [ ] `myapp://`
        - [ ] Notes
  - [ ] `secret`
    - [x] Use Options.Secret ahead of AUTH_SECRET when no key list is configured ([test](../../env_test.go#L42))
    - [x] Sign with the configured key list ahead of single secrets and prefer the explicit list ([test](../../env_test.go#L194))
    - [ ] `AUTH_SECRET`
    - [ ] `process.env.AUTH_SECRET`
  - [ ] `secrets`
    - [x] Sign with the active key and accept cookies from a retained key ([test](../../env_test.go#L80))
    - [x] Accept an email proof signed by a retained key and reject it after retirement ([test](../../env_test.go#L141))
  - [ ] `database`
  - [ ] `secondaryStorage`
  - [ ] `emailVerification`
    - [ ] `sendVerificationEmail`
    - [ ] `sendOnSignUp`
    - [ ] `sendOnSignIn`
    - [ ] `autoSignInAfterVerification`
      - [x] Cross-verify signed ordinary mail links and compare first use, duplicate use, trusted redirects and foreign or same-owner browser sessions ([test](../../conformance/email-verification-session.mjs#L7))
      - [x] Serialize concurrent browser verification across memory and three SQL engines, keeping native verification and application credentials sessionless ([test](../../adapters/sqlstore/email_verification_session_test.go#L33))
      - [x] Enforce enrollment, bans, delegation, mailbox ownership and spent-proof policy from an independently mounted SQL node ([test](../../adapters/sqlstore/email_verification_session_test.go#L135))
      - [x] Authenticate the native HTTP client and remove a newly minted session when cookie publication fails ([test](../../client/email_verification_session_test.go#L16))
      - [x] Reject a proof that expires while waiting for the account lock on SQLite, PostgreSQL and MySQL ([test](../../adapters/sqlstore/email_verification_session_test.go#L291))
    - [ ] `expiresIn`
  - [ ] `emailAndPassword`
    - [x] `enabled` ([test](../../conformance/email-password-options.mjs#L77))
      - [x] Compare disabled email sign-in and closed registration with a pre-existing credential and a fresh browser ([test](../../conformance/email-password-options.mjs#L77))
    - [x] `disableSignUp` ([test](../../conformance/email-password-options.mjs#L77))
      - [x] Compare disabled email sign-in and closed registration with a pre-existing credential and a fresh browser ([test](../../conformance/email-password-options.mjs#L77))
    - [ ] `requireEmailVerification`
    - [x] `minPasswordLength` ([test](../../conformance/email-password-options.mjs#L18))
      - [x] Verify inclusive UTF-16 limits on registration, password changes and link recovery, and sign in with an existing shorter password ([test](../../conformance/email-password-options.mjs#L18))
    - [x] `maxPasswordLength` ([test](../../conformance/email-password-options.mjs#L18))
      - [x] Verify inclusive UTF-16 limits on registration, password changes and link recovery, and sign in with an existing shorter password ([test](../../conformance/email-password-options.mjs#L18))
    - [ ] `autoSignIn`
    - [ ] `sendResetPassword`
    - [x] `onPasswordReset` ([test](../../conformance/password-reset-hook.mjs#L8))
      - [x] Observe committed resets through the official client on both runtimes, including hook rejection and email-code verification ordering ([test](../../conformance/password-reset-hook.mjs#L8))
      - [x] Reject proof replay while the host callback is running across memory and three SQL engines ([test](../../adapters/sqlstore/password_reset_hook_test.go#L20))
      - [x] Bind post-callback mailbox verification to the same owner and address across a concurrent address change ([test](../../adapters/sqlstore/password_reset_hook_test.go#L194))
      - [x] Retain custom account adapters, forward native callback errors and contain a host panic after commit ([test](../../password_reset_hook_test.go#L14))
    - [ ] `revokeSessionsOnPasswordReset`
    - [ ] `resetPasswordTokenExpiresIn`
    - [x] `onExistingUserSignUp` ([test](../../conformance/core.test.mjs#L1461))
      - [x] Deliver the stored owner to the host while preserving private responses across both modes and ordinary 422 behavior in the released client ([test](../../conformance/core.test.mjs#L1461))
      - [x] Run the callback after storage releases the account, isolate errors and panics, and preserve owned request metadata ([test](../../adapters/sqlstore/existing_signup_test.go#L83))
      - [x] Use one committed owner for concurrent registrations across separate instances and storage connections ([test](../../adapters/sqlstore/existing_signup_test.go#L197))
    - [ ] `customSyntheticUser`
    - [x] `password` ([test](../../conformance/core.test.mjs#L1391))
      - [x] Open and replace host-encoded credentials from either runtime in the same account database ([test](../../conformance/core.test.mjs#L1391))
  - [ ] `socialProviders`
    - [ ] `clientId`
    - [ ] `clientSecret`
    - [ ] `clientKey`
    - [ ] `redirectURI`
    - [ ] `scope`
    - [ ] `mapProfileToUser`
    - [ ] `getAccountFields`
    - [ ] `disableSignUp`
    - [ ] `disableImplicitSignUp`
    - [ ] `overrideUserInfoOnSignIn`
    - [ ] `requireEmailVerification`
    - [ ] `prompt`
    - [ ] `responseMode`
    - [ ] `getUserInfo`
    - [ ] `refreshAccessToken`
    - [ ] `verifyIdToken`
    - [ ] `disableIdTokenSignIn`
    - [ ] `disableDefaultScope`
    - [ ] `authorizationEndpoint`
  - [ ] `plugins`
  - [ ] `user`
    - [ ] `modelName`
    - [ ] `fields`
    - [ ] `additionalFields`
      - [x] Declare portable user columns, inspect compatibility and migrate preexisting profiles alongside independent session declarations ([test](../../adapters/sqlstore/user_fields_test.go#L192))
      - [x] Apply public and host-owned fields on memory, SQLite, PostgreSQL and MySQL ([test](../../adapters/sqlstore/user_fields_test.go#L47))
      - [x] Apply declared user fields only on first-time email OTP registration and retain the original values during sign-in ([test](../../conformance/user-fields.mjs#L111))
      - [x] Keep browser state and raw provider claims separate from declared public, hidden and server-owned fields on social signup ([test](../../conformance/social-user-fields.mjs#L122))
    - [ ] `changeEmail`
    - [ ] `deleteUser`
  - [ ] `session`
    - [ ] `modelName`
    - [ ] `fields`
    - [ ] `expiresIn`
    - [ ] `updateAge`
    - [ ] `additionalFields`
      - [x] Exchange scalar session defaults and updates across runtimes through the released client, including private input and renamed columns ([test](../../conformance/session-fields.mjs#L22))
      - [x] Apply static scalar defaults and trusted-only overrides on memory and three SQL engines ([test](../../adapters/sqlstore/session_fields_test.go#L31))
      - [x] Migrate populated session tables with nullable fields, escaped defaults and preflight checks on all three engines ([test](../../adapters/sqlstore/session_fields_test.go#L233))
      - [x] Keep first-session issuance atomic when a required value must come from a trusted host ([test](../../adapters/sqlstore/session_fields_test.go#L436))
      - [x] Document public inputs and responses separately from physical names and private defaults ([test](../../plugins/openapi/session_fields_test.go#L16))
    - [ ] `storeSessionInDatabase`
    - [ ] `preserveSessionInDatabase`
    - [ ] `cookieCache`
      - [x] Enable compact browser snapshots with a fixed version and whole-second lifetime ([test](../../session_cache_compact_test.go#L367))
      - [x] Select a signed JWT or encrypted JWE and enforce the configured format and lifetime ([test](../../session_cache_jose_test.go#L75))
      - [x] Derive a per-session and user revision for each format, keeping native, administrative and JWT-authorized reads live on three SQL engines ([test](../../adapters/sqlstore/session_cache_test.go#L26))
  - [ ] `account`
    - [ ] `modelName`
    - [ ] `fields`
    - [x] `encryptOAuthTokens` ([test](../../adapters/sqlstore/oauth_encryption_test.go#L92))
      - [x] Encrypt provider access, refresh and ID tokens across key rotation and credential refresh ([test](../../adapters/sqlstore/oauth_encryption_test.go#L92))
    - [ ] `updateAccountOnSignIn`
    - [ ] `storeStateStrategy`
      - [ ] `"cookie"`
      - [ ] `"database"`
    - [ ] `storeAccountCookie`
    - [ ] `accountLinking`
      - [x] `enabled` ([test](../../conformance/social-link-policy.mjs#L50))
        - [x] Close new links across browser and direct grants while permitting new registration and subsequent sign-in with the same stable subject ([test](../../conformance/social-link-policy.mjs#L50))
        - [x] Refresh an existing mobile identity only under its live owner session and reject attachment of new and foreign identities ([test](../../oauth_signup_test.go#L212))
        - [x] Commit owned credential refresh without issuing another session across all three SQL engines ([test](../../adapters/sqlstore/social_test.go#L132))
      - [x] `disableImplicitLinking` ([test](../../conformance/social-link-policy.mjs#L5))
        - [x] Require an authenticated owner to link a trusted provider, preserve the stable owner, and accept subsequent logins ([test](../../conformance/social-link-policy.mjs#L5))
        - [x] Deny an automatic link even when a registered enterprise IdP has a verified matching domain ([test](../../adapters/sqlstore/sso_domain_test.go#L300))
        - [x] Keep new social registration available and leave no partial session on a same-email collision on all SQL engines ([test](../../adapters/sqlstore/social_test.go#L107))
        - [x] Use a mobile ID token to sign in only after the authenticated account owner explicitly links the provider ([test](../../oauth_signup_test.go#L129))
      - [ ] `trustedProviders`
      - [ ] `allowDifferentEmails`
      - [ ] `allowUnlinkingAll`
      - [ ] `updateUserInfoOnLink`
  - [ ] `verification`
    - [ ] `modelName`
    - [ ] `fields`
    - [ ] `disableCleanup`
    - [ ] `storeIdentifier`
    - [ ] `storeInDatabase`
  - [ ] `rateLimit`
    - [x] Select the production rate limit by default and honor an explicit override ([test](../../env_test.go#L122))
    - [ ] `enabled`
    - [ ] `window`
    - [ ] `max`
    - [ ] `customRules`
    - [ ] `storage`
    - [ ] `modelName`
  - [ ] `advanced`
    - [ ] `ipAddress`
    - [ ] `disableIpTracking`
    - [ ] `ipAddressHeaders`
    - [ ] `trustedProxies`
    - [ ] `useSecureCookies`
    - [ ] `disableCSRFCheck`
    - [ ] `disableOriginCheck`
    - [ ] `crossSubDomainCookies`
    - [ ] `cookies`
    - [ ] `defaultCookieAttributes`
    - [ ] `cookiePrefix`
    - [ ] `database`
    - [ ] `backgroundTasks`
    - [ ] `skipTrailingSlashes`
    - [ ] `generateId`
    - [ ] `defaultFindManyLimit`
    - [ ] `joins`
    - [ ] `validateSchema`
    - [ ] `backgroundTasks`
  - [ ] `logger`
    - [x] Report a verification-mail delivery failure to the selected logger while preserving the new account and session ([test](../../conformance/core.test.mjs#L1307))
    - [x] `disabled` ([test](../../conformance/core.test.mjs#L1323))
      - [x] Silence one instance without suppressing error records from another ([test](../../conformance/core.test.mjs#L1323))
    - [ ] `disableColors`
    - [ ] `level`
      - [x] Use the configured handler severity threshold for events from core and plugin hooks ([test](../../logger_test.go#L46))
    - [ ] `"debug"`
    - [ ] `"info"`
    - [ ] `"warn"`
    - [x] `"error"` ([test](../../logger_test.go#L46))
      - [x] Record errors and suppress warnings with the standard error threshold ([test](../../logger_test.go#L46))
    - [x] `log` ([test](../../logger_test.go#L51))
      - [x] Route core and plugin diagnostics to a host JSON handler with application attributes ([test](../../logger_test.go#L51))
    - [ ] `message`
    - [ ] `...args`
  - [ ] `databaseHooks`
  - [ ] `onAPIError`
    - [x] Report the original error and already-resolved user before writing the localized HTTP response ([test](../../error_reporting_test.go#L88))
    - [ ] `throw`
    - [x] `onError` ([test](../../conformance/core.test.mjs#L1329))
      - [x] Wait for the host reporter and preserve the endpoint error when the reporter fails ([test](../../conformance/core.test.mjs#L1329))
      - [x] Contain reporter panics and keep callback errors and credentials out of client responses and logs ([test](../../error_reporting_test.go#L67))
    - [ ] `errorURL`
    - [ ] `customizeDefaultErrorPage`
    - [ ] `colors`
    - [ ] `background`
    - [ ] `foreground`
    - [ ] `primary`
    - [ ] `primaryForeground`
    - [ ] `mutedForeground`
    - [ ] `border`
    - [ ] `destructive`
    - [ ] `titleBorder`
    - [ ] `titleColor`
    - [ ] `gridColor`
    - [ ] `cardBackground`
    - [ ] `cornerBorder`
    - [ ] `size`
    - [ ] `radiusSm`
    - [ ] `radiusMd`
    - [ ] `radiusLg`
    - [ ] `textSm`
    - [ ] `text2xl`
    - [ ] `text4xl`
    - [ ] `text6xl`
    - [ ] `font`
    - [ ] `defaultFamily`
    - [ ] `monoFamily`
    - [ ] `disableTitleBorder`
    - [ ] `disableCornerDecorations`
    - [ ] `disableBackgroundGrid`
  - [ ] `hooks`
  - [x] `disabledPaths` ([test](../../disabled_paths_test.go#L14))
    - [x] Disable exact mount-relative HTTP paths before key extraction and request hooks, omit their fixed routes from OpenAPI and retain native Go calls ([test](../../disabled_paths_test.go#L14))
    - [x] Apply the same per-path HTTP setting to the SCIM wrapper and preserve neighboring resource operations ([test](../../plugins/scim/http_test.go#L117))
  - [ ] `telemetry`

## Security

- [ ] Security
  - [x] Password Hashing ([test](../../conformance/core.test.mjs#L1391))
    - [x] Open and replace host-encoded credentials from either runtime in the same account database ([test](../../conformance/core.test.mjs#L1391))
  - [ ] Secret Rotation
  - [ ] Session Management
    - [ ] Session Expiration
    - [ ] Session Revocation
  - [ ] CSRF Protection
    - [ ] Avoid simple requests
    - [ ] Origin Validation
    - [ ] Secure Cookie Settings
    - [ ] Fetch Metadata Protection for First-Login CSRF
    - [ ] No Mutations on GET Requests (with additional safeguards)
    - [ ] Your own routes that call `auth.api`
    - [ ] Disabling Security Checks
      - [ ] `disableCSRFCheck`
      - [ ] `disableOriginCheck`
      - [ ] Summary
        - [ ] `disableCSRFCheck`
        - [ ] `disableOriginCheck`
  - [ ] OAuth State and PKCE
  - [ ] Cookies
    - [ ] Customizing Cookies
  - [ ] Rate Limiting
  - [ ] IP Address Headers
  - [ ] Trusted Proxy Headers
  - [ ] Trusted Origins
    - [ ] Basic Usage
    - [ ] Wildcard Origins
      - [ ] Protocol-specific wildcards
        - [x] Complete the OAuth provider callback on the static auth host and return the browser to an allowed HTTPS application subdomain ([test](../../oauth_test.go#L198))
      - [ ] Protocol-agnostic wildcards
        - [x] Admit both HTTP and HTTPS for a scheme-independent hostname wildcard on their default ports ([test](../../conformance/trusted-origins.mjs#L41))
    - [ ] Custom Schemes
    - [ ] Dynamic origin list
      - [ ] Important
  - [ ] Outbound OAuth Requests
  - [ ] Email Enumeration Protection
  - [ ] Reporting Vulnerabilities

## Telemetry

- [ ] Telemetry
  - [ ] Why is telemetry collected?
  - [ ] What is being collected?
    - [ ] Anonymous identifier
    - [ ] Runtime
    - [ ] Environment
    - [ ] Framework (if detected)
    - [ ] Database (if detected)
    - [ ] System info
    - [ ] Package manager
    - [ ] Redacted auth config snapshot
    - [ ] CLI generate (`cli_generate`)
    - [ ] CLI migrate (`cli_migrate`)
  - [ ] How is my data protected?
    - [ ] No PII or secrets
    - [ ] No full config
    - [ ] Redaction by design
  - [ ] How can I enable it?
    - [ ] When is telemetry sent?
