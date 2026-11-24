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
  - [x] `appName` ([test](../../conformance/goapi/freshness_test.go#L68))
    - [x] Name the application as the default authenticator issuer ([test](../../conformance/goapi/freshness_test.go#L68))
  - [ ] `baseURL`
    - [x] Resolve public URL and mount path from explicit options and process settings ([test](../../env_test.go#L20))
    - [ ] Dynamic Base URL
      - [ ] `allowedHosts`
      - [ ] `protocol`
      - [ ] `fallback`
  - [x] `basePath` ([test](../../conformance/goapi/http_test.go#L58))
    - [x] Resolve public URL and mount path from explicit options and process settings ([test](../../env_test.go#L20))
    - [x] With BasePath /identity, the default /api/auth/ok returns 404 and /identity/ok serves ([test](../../conformance/goapi/http_test.go#L58))
  - [ ] `trustedOrigins`
    - [x] Combine configured origins and environment origins for callback validation ([test](../../env_test.go#L34))
    - [x] Asserts the BaseURL origin is trusted by default, alongside the configured and AUTH_TRUSTED_ORIGINS entries, through CallbackURL ([test](../../conformance/goapi/trusted_origins_test.go#L26))
    - [x] Static Origins ([test](../../conformance/goapi/http_test.go#L71))
      - [x] A sign-up with an Origin taken from the static TrustedOrigins list succeeds over HTTP ([test](../../conformance/goapi/http_test.go#L71))
    - [ ] Dynamic Origins
      - [ ] On a direct `auth.api` call with a static `baseURL`
    - [ ] Wildcard Support
      - [x] Compare cookie-authenticated mutations and absolute login callback decisions for HTTP(S) wildcard origins on both servers ([test](../../conformance/trusted-origins.mjs#L76))
      - [ ] Pattern Syntax
        - [x] Separate hostname and port matching and restrict numeric address patterns to IPv4 ([test](../../conformance/goapi/trusted_origins_test.go#L11))
        - [x] `?` ([test](../../conformance/trusted-origins.mjs#L43))
          - [x] On both servers, the pattern preview-?.example.test:84?? accepts one character in the host and port, and rejects two characters for one `?` ([test](../../conformance/trusted-origins.mjs#L43))
        - [x] `*` ([test](../../conformance/goapi/trusted_origins_test.go#L27))
          - [x] The pattern https://*.apps.example matches subdomains at any depth and ignores the path ([test](../../conformance/goapi/trusted_origins_test.go#L27))
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
    - [x] `AUTH_SECRET` ([test](../../env_test.go#L30))
      - [x] Asserts that AUTH_SECRET is read into Options.Secret when no explicit secret is set ([test](../../env_test.go#L30))
    - [x] `process.env.AUTH_SECRET` ([test](../../env_test.go#L84))
      - [x] An instance configured only by the AUTH_SECRET environment variable signs session cookies ([test](../../env_test.go#L84))
  - [ ] `secrets`
    - [x] Sign with the active key and accept cookies from a retained key ([test](../../env_test.go#L80))
    - [x] Accept an email proof signed by a retained key and reject it after retirement ([test](../../env_test.go#L141))
  - [ ] `database`
  - [ ] `secondaryStorage`
  - [ ] `emailVerification`
    - [x] `sendVerificationEmail` ([test](../../conformance/goapi/account_test.go#L47))
      - [x] The configured SendVerificationEmail sender receives exactly one link for the account owner from /send-verification-email ([test](../../conformance/goapi/account_test.go#L47))
    - [x] `sendOnSignUp` ([test](../../conformance/social-user-fields.mjs#L246))
      - [x] On both servers, unset follows requireEmailVerification (mail sent), false suppresses mail and true sends it ([test](../../conformance/social-user-fields.mjs#L246))
    - [x] `sendOnSignIn` ([test](../../conformance/social-user-fields.mjs#L251))
      - [x] On both servers, a repeated sign-in with an unverified address sends a new verification mail only when sendOnSignIn is enabled ([test](../../conformance/social-user-fields.mjs#L251))
    - [ ] `autoSignInAfterVerification`
      - [x] Cross-verify signed ordinary mail links and compare first use, duplicate use, trusted redirects and foreign or same-owner browser sessions ([test](../../conformance/email-verification-session.mjs#L7))
      - [x] Serialize concurrent browser verification across memory and three SQL engines, keeping native verification and application credentials sessionless ([test](../../adapters/sqlstore/email_verification_session_test.go#L33))
      - [x] Enforce enrollment, bans, delegation, mailbox ownership and spent-proof policy from an independently mounted SQL node ([test](../../adapters/sqlstore/email_verification_session_test.go#L135))
      - [x] Authenticate the native HTTP client and remove a newly minted session when cookie publication fails ([test](../../client/email_verification_session_test.go#L16))
      - [x] Reject a proof that expires while waiting for the account lock on SQLite, PostgreSQL and MySQL ([test](../../adapters/sqlstore/email_verification_session_test.go#L291))
      - [x] Compare original, earlier and ambiguous millisecond profile revisions against an actual signed link’s whole-second issue time ([test](../../conformance/email-verification-session.mjs#L95))
    - [ ] `expiresIn`
  - [ ] `emailAndPassword`
    - [x] `enabled` ([test](../../conformance/email-password-options.mjs#L77))
      - [x] Compare disabled email sign-in and closed registration with a pre-existing credential and a fresh browser ([test](../../conformance/email-password-options.mjs#L77))
    - [x] `disableSignUp` ([test](../../conformance/email-password-options.mjs#L77))
      - [x] Compare disabled email sign-in and closed registration with a pre-existing credential and a fresh browser ([test](../../conformance/email-password-options.mjs#L77))
    - [x] `requireEmailVerification` ([test](../../conformance/goapi/account_lifecycle_test.go#L15))
      - [x] An unverified sign-up gets no token, and sign-in fails with EMAIL_NOT_VERIFIED ([test](../../conformance/goapi/account_lifecycle_test.go#L15))
    - [x] `minPasswordLength` ([test](../../conformance/email-password-options.mjs#L18))
      - [x] Verify inclusive UTF-16 limits on registration, password changes and link recovery, and sign in with an existing shorter password ([test](../../conformance/email-password-options.mjs#L18))
    - [x] `maxPasswordLength` ([test](../../conformance/email-password-options.mjs#L18))
      - [x] Verify inclusive UTF-16 limits on registration, password changes and link recovery, and sign in with an existing shorter password ([test](../../conformance/email-password-options.mjs#L18))
    - [x] `autoSignIn` ([test](../../conformance/goapi/account_lifecycle_test.go#L54))
      - [x] With DisableAutoSignIn, registration returns no session token, while a later manual sign-in succeeds ([test](../../conformance/goapi/account_lifecycle_test.go#L54))
    - [x] `sendResetPassword` ([test](../../conformance/goapi/account_test.go#L76))
      - [x] SendResetPassword receives exactly one link for a registered address, with the same response as for an unknown address ([test](../../conformance/goapi/account_test.go#L76))
    - [x] `onPasswordReset` ([test](../../conformance/password-reset-hook.mjs#L8))
      - [x] Observe committed resets through the official client on both runtimes, including hook rejection and email-code verification ordering ([test](../../conformance/password-reset-hook.mjs#L8))
      - [x] Reject proof replay while the host callback is running across memory and three SQL engines ([test](../../adapters/sqlstore/password_reset_hook_test.go#L20))
      - [x] Bind post-callback mailbox verification to the same owner and address across a concurrent address change ([test](../../adapters/sqlstore/password_reset_hook_test.go#L194))
      - [x] Retain custom account adapters, forward native callback errors and contain a host panic after commit ([test](../../conformance/goapi/password_reset_hook_test.go#L14))
    - [x] `revokeSessionsOnPasswordReset` ([test](../../conformance/goapi/account_test.go#L92))
      - [x] With RevokeSessionsOnPasswordReset set, the previous browser session is rejected after a reset, while a new sign-in with the new password succeeds ([test](../../conformance/goapi/account_test.go#L92))
    - [x] `resetPasswordTokenExpiresIn` ([test](../../conformance/goapi/account_test.go#L142))
      - [x] With PasswordResetTokenTTL set to one nanosecond, the issued reset link is rejected with INVALID_TOKEN ([test](../../conformance/goapi/account_test.go#L142))
    - [x] `onExistingUserSignUp` ([test](../../conformance/core.test.mjs#L1457))
      - [x] Deliver the stored owner to the host while preserving private responses across both modes and ordinary 422 behavior in the released client ([test](../../conformance/core.test.mjs#L1457))
      - [x] Run the callback after storage releases the account, isolate errors and panics, and preserve owned request metadata ([test](../../adapters/sqlstore/existing_signup_test.go#L83))
      - [x] Use one committed owner for concurrent registrations across separate instances and storage connections ([test](../../adapters/sqlstore/existing_signup_test.go#L197))
    - [ ] `customSyntheticUser`
    - [x] `password` ([test](../../conformance/core.test.mjs#L1391))
      - [x] Open and replace host-encoded credentials from either runtime in the same account database ([test](../../conformance/core.test.mjs#L1391))
  - [ ] `socialProviders`
    - [x] `clientId` ([test](../../providers/catalog_test.go#L79))
      - [x] For every catalog provider, the configured client ID reaches the token exchange through real /sign-in/social and /callback requests ([test](../../providers/catalog_test.go#L79))
    - [x] `clientSecret` ([test](../../providers/catalog_test.go#L80))
      - [x] For every catalog provider, the configured client secret is sent in the token exchange, by basic auth or form fields as the provider requires ([test](../../providers/catalog_test.go#L80))
    - [x] `clientKey` ([test](../../providers/catalog_test.go#L174))
      - [x] For TikTok, the configured key is sent as client_key, not client_id, in both the authorization URL and the token form ([test](../../providers/catalog_test.go#L174))
    - [ ] `redirectURI`
    - [x] `scope` ([test](../../conformance/social-signup.mjs#L60))
      - [x] On both servers, the configured provider scopes appear in the authorization URL ([test](../../conformance/social-signup.mjs#L60))
    - [x] `mapProfileToUser` ([test](../../conformance/social-user-fields.mjs#L110))
      - [x] Go's Resolve returns an OAuthProfile with AdditionalFields ([test](../../conformance/social-user-fields.mjs#L110))
    - [x] `getAccountFields` ([test](../../conformance/apple-native.mjs#L87))
      - [x] Map signed provider account fields across both servers, preserve credentials and explicitly reauthorize an existing link ([test](../../conformance/apple-native.mjs#L87))
      - [x] Map browser grants on first links and verified email linking, keep identity bindings and reject invalid updates atomically ([test](../../conformance/account-fields.mjs#L25))
    - [x] `disableSignUp` ([test](../../conformance/goapi/oauth_signup_test.go#L132))
      - [x] A provider with DisableSignUp declines new-account creation even when sign-up is explicitly requested, for both browser and ID-token sign-in ([test](../../conformance/goapi/oauth_signup_test.go#L132))
    - [x] `disableImplicitSignUp` ([test](../../conformance/goapi/oauth_signup_test.go#L118))
      - [x] With DisableImplicitSignUp, a new account is refused unless requestSignUp is sent, and created when it is ([test](../../conformance/goapi/oauth_signup_test.go#L118))
    - [x] `overrideUserInfoOnSignIn` ([test](../../conformance/social-user-fields.mjs#L145))
      - [x] Refresh a returning profile with either server, preserve protected fields and use the new mailbox verification status ([test](../../conformance/social-user-fields.mjs#L145))
    - [x] `requireEmailVerification` ([test](../../conformance/social-user-fields.mjs#L200))
      - [x] Withhold sessions for unverified social accounts, honor mail delivery settings and accept confirmation by either server ([test](../../conformance/social-user-fields.mjs#L200))
    - [ ] `prompt`
    - [ ] `responseMode`
    - [x] `getUserInfo` ([test](../../conformance/goapi/oauth_test.go#L177))
      - [x] A custom Resolve function fetches user info from the provider with the issued access token ([test](../../conformance/goapi/oauth_test.go#L177))
    - [x] `refreshAccessToken` ([test](../../adapters/sqlstore/oauth_encryption_test.go#L117))
      - [x] A custom Refresh function receives the stored refresh token, and its returned tokens replace the stored credentials on three SQL engines ([test](../../adapters/sqlstore/oauth_encryption_test.go#L117))
    - [ ] `verifyIdToken`
    - [x] `disableIdTokenSignIn` ([test](../../conformance/apple-native.mjs#L51))
      - [x] Decline signed client ID tokens for sign-in and account linking while preserving browser authorization ([test](../../conformance/apple-native.mjs#L51))
    - [ ] `disableDefaultScope`
    - [x] `authorizationEndpoint` ([test](../../conformance/goapi/oauth_test.go#L21))
      - [x] A provider whose Config.Endpoint.AuthURL points at a local server sends the browser to that endpoint, and the code flow completes with PKCE and nonce ([test](../../conformance/goapi/oauth_test.go#L21))
  - [x] `plugins` ([test](../../conformance/goapi/plugins_test.go#L14))
    - [x] Configured plugins mount endpoints under the auth path, get origin and callback checks, and dispatch once ([test](../../conformance/goapi/plugins_test.go#L14))
  - [ ] `user`
    - [ ] `modelName`
    - [ ] `fields`
    - [ ] `additionalFields`
      - [x] Declare portable user columns, inspect compatibility and migrate preexisting profiles alongside independent session declarations ([test](../../adapters/sqlstore/user_fields_test.go#L192))
      - [x] Apply public and host-owned fields on memory, SQLite, PostgreSQL and MySQL ([test](../../adapters/sqlstore/user_fields_test.go#L47))
      - [x] Apply declared user fields only on first-time email OTP registration and retain the original values during sign-in ([test](../../conformance/user-fields.mjs#L111))
      - [x] Keep browser state and raw provider claims separate from declared public, hidden and server-owned fields on social signup ([test](../../conformance/social-user-fields.mjs#L140))
      - [x] Write phone registration profiles once across competing nodes, preserve owner values, and keep verification credentials and flags out of stored profile columns ([test](../../adapters/sqlstore/phone_registration_fields_test.go#L148))
      - [x] Accept date input with an explicit time zone, persist trusted updates and clear optional timestamps on four stores ([test](../../adapters/sqlstore/date_fields_test.go#L17))
      - [x] Compute server-owned profile defaults on creation and roll back invalid generated values across four stores ([test](../../adapters/sqlstore/computed_fields_test.go#L17))
    - [x] `changeEmail` ([test](../../conformance/goapi/account_lifecycle_test.go#L94))
      - [x] With ChangeEmailEnabled and SendChangeEmailConfirmation, POST /change-email sends the confirmation to the current inbox, the new inbox is then verified, and the change persists ([test](../../conformance/goapi/account_lifecycle_test.go#L94))
    - [x] `deleteUser` ([test](../../conformance/goapi/account_lifecycle_test.go#L116))
      - [x] With DeleteUserEnabled and SendDeleteAccountVerification, POST /delete-user mails an owner-bound link, another user cannot redeem it, and the owner's redemption deletes the account and its session ([test](../../conformance/goapi/account_lifecycle_test.go#L116))
  - [ ] `session`
    - [ ] `modelName`
    - [ ] `fields`
    - [x] `expiresIn` ([test](../../authtest/server_test.go#L85))
      - [x] Options.SessionTTL set to 22h: the issued session's ExpiresAt minus CreatedAt equals exactly 22h ([test](../../authtest/server_test.go#L85))
    - [x] `updateAge` ([test](../../session_refresh_test.go#L123))
      - [x] Over HTTP get-session, TestSessionRefreshWindow shows no refresh 1ms before the default one-day update age, a refresh exactly at it that extends expiry by the TTL, and no second refresh within the window ([test](../../session_refresh_test.go#L123))
    - [ ] `additionalFields`
      - [x] Exchange scalar session defaults and updates across runtimes through the released client, including private input and renamed columns ([test](../../conformance/session-fields.mjs#L22))
      - [x] Apply static scalar defaults and trusted-only overrides on memory and three SQL engines ([test](../../adapters/sqlstore/session_fields_test.go#L31))
      - [x] Migrate populated session tables with nullable fields, escaped defaults and preflight checks on all three engines ([test](../../adapters/sqlstore/session_fields_test.go#L233))
      - [x] Keep first-session issuance atomic when a required value must come from a trusted host ([test](../../adapters/sqlstore/session_fields_test.go#L436))
      - [x] Document public inputs and responses separately from physical names and private defaults ([test](../../plugins/openapi/session_fields_test.go#L16))
      - [x] Read date-valued session and profile attributes written by either runtime through the same session ([test](../../conformance/date-fields.mjs#L5))
      - [x] Issue separate session defaults and honor trusted fixture overrides without a second callback ([test](../../adapters/sqlstore/computed_fields_test.go#L89))
    - [ ] `storeSessionInDatabase`
    - [ ] `preserveSessionInDatabase`
    - [x] `cookieCache` ([test](../../conformance/session-cache-compact.mjs#L33))
      - [x] Enable compact browser snapshots with a fixed version and whole-second lifetime ([test](../../session_cache_compact_test.go#L367))
      - [x] Select a signed JWT or encrypted JWE and enforce the configured format and lifetime ([test](../../session_cache_jose_test.go#L75))
      - [x] Derive a per-session and user revision for each format, keeping native, administrative and JWT-authorized reads live on three SQL engines ([test](../../adapters/sqlstore/session_cache_test.go#L26))
      - [x] With SessionCookieCache enabled, each runtime accepts the other's signed snapshot cookie, honors maxAge and disableCookieCache, chunks large cookies, and clears them on sign-out (compact and JWT strategies) ([test](../../conformance/session-cache-compact.mjs#L33))
  - [ ] `account`
    - [ ] `modelName`
    - [ ] `fields`
    - [x] `encryptOAuthTokens` ([test](../../adapters/sqlstore/oauth_encryption_test.go#L92))
      - [x] Encrypt provider access, refresh and ID tokens across key rotation and credential refresh ([test](../../adapters/sqlstore/oauth_encryption_test.go#L92))
    - [x] `updateAccountOnSignIn` ([test](../../conformance/social-user-fields.mjs#L267))
      - [x] Preserve or renew provider credentials on returning sign-ins while applying profile changes and issuing sessions ([test](../../conformance/social-user-fields.mjs#L267))
      - [x] Preserve the account timestamp, claim single-use grants and retain omitted expiry values on three SQL engines ([test](../../adapters/sqlstore/oauth_account_update_test.go#L11))
      - [x] Keep the original encryption key version on sign-in and rotate credentials through explicit refresh ([test](../../adapters/sqlstore/oauth_encryption_test.go#L113))
    - [ ] `storeStateStrategy`
      - [ ] `"cookie"`
      - [x] `"database"` ([test](../../conformance/goapi/oauth_test.go#L151))
        - [x] Social sign-in sets an oauth_state binding cookie and stores the flow ([test](../../conformance/goapi/oauth_test.go#L151))
    - [ ] `storeAccountCookie`
    - [ ] `accountLinking`
      - [x] `enabled` ([test](../../conformance/social-link-policy.mjs#L50))
        - [x] Close new links across browser and direct grants while permitting new registration and subsequent sign-in with the same stable subject ([test](../../conformance/social-link-policy.mjs#L50))
        - [x] Refresh an existing mobile identity only under its live owner session and reject attachment of new and foreign identities ([test](../../conformance/goapi/oauth_signup_test.go#L228))
        - [x] Commit owned credential refresh without issuing another session across all three SQL engines ([test](../../adapters/sqlstore/social_test.go#L132))
      - [x] `disableImplicitLinking` ([test](../../conformance/social-link-policy.mjs#L5))
        - [x] Require an authenticated owner to link a trusted provider, preserve the stable owner, and accept subsequent logins ([test](../../conformance/social-link-policy.mjs#L5))
        - [x] Deny an automatic link even when a registered enterprise IdP has a verified matching domain ([test](../../adapters/sqlstore/sso_domain_test.go#L300))
        - [x] Keep new social registration available and leave no partial session on a same-email collision on all SQL engines ([test](../../adapters/sqlstore/social_test.go#L107))
        - [x] Use a mobile ID token to sign in only after the authenticated account owner explicitly links the provider ([test](../../conformance/goapi/oauth_signup_test.go#L145))
      - [ ] `trustedProviders`
      - [ ] `allowDifferentEmails`
      - [x] `allowUnlinkingAll` ([test](../../conformance/goapi/database_user_hooks_test.go#L342))
        - [x] With AllowUnlinkingAll true, POST /unlink-account removes the user's only credential account and its delete hooks run ([test](../../conformance/goapi/database_user_hooks_test.go#L342))
      - [ ] `updateUserInfoOnLink`
  - [ ] `verification`
    - [ ] `modelName`
    - [ ] `fields`
    - [ ] `disableCleanup`
    - [ ] `storeIdentifier`
    - [ ] `storeInDatabase`
  - [ ] `rateLimit`
    - [x] Select the production rate limit by default and honor an explicit override ([test](../../env_test.go#L122))
    - [x] `enabled` ([test](../../conformance/goapi/http_test.go#L145))
      - [x] With RateLimit enabled, the fourth sign-in request in the window gets 429 with X-Retry-After ([test](../../conformance/goapi/http_test.go#L145))
    - [ ] `window`
    - [x] `max` ([test](../../adapters/sqlstore/oauth_browser_authorization_test.go#L206))
      - [x] In the "host" case, an empty plugin rule falls back to RateLimitDefault{Max: 3}, and the fourth HTTP request returns 429 with X-Retry-After ([test](../../adapters/sqlstore/oauth_browser_authorization_test.go#L206))
    - [x] `customRules` ([test](../../ratelimit_test.go#L10))
      - [x] RateLimitRules: an exact route rule is enforced (429 on the third request, retry after 2s), a trailing /* wildcard with a nil rule exempts routes, and invalid patterns are rejected ([test](../../ratelimit_test.go#L10))
    - [x] `storage` ([test](../../adapters/sqlstore/ratelimit_test.go#L18))
      - [x] RateLimitStorage backed by the SQL store shares counters across two auth instances on SQLite, PostgreSQL and MySQL, and the HTTP handler returns 429 from the shared counter ([test](../../adapters/sqlstore/ratelimit_test.go#L18))
    - [ ] `modelName`
  - [ ] `advanced`
    - [ ] `ipAddress`
    - [x] `disableIpTracking` ([test](../../ip_test.go#L49))
      - [x] With ClientIP.DisableTracking and rate limiting on, no client IP is resolved and the per-IP limiter never rejects repeated sign-in requests ([test](../../ip_test.go#L49))
    - [ ] `ipAddressHeaders`
    - [x] `trustedProxies` ([test](../../ip_test.go#L10))
      - [x] ClientIP.TrustedProxies CIDR ranges: forwarded hops are read right to left skipping trusted proxies, headers from untrusted peers are ignored, malformed chains give no IP, and invalid prefixes are rejected ([test](../../ip_test.go#L10))
    - [x] `useSecureCookies` ([test](../../cookies_test.go#L101))
      - [x] UseSecureCookies forces or removes Secure (and the __Secure- name) regardless of BaseURL scheme, and reserved prefixes that need Secure are rejected ([test](../../cookies_test.go#L101))
    - [x] `disableCSRFCheck` ([test](../../conformance/goapi/request_switches_test.go#L43))
      - [x] Turn off the origin and Fetch Metadata checks on state-changing requests ([test](../../conformance/goapi/request_switches_test.go#L43))
    - [x] `disableOriginCheck` ([test](../../conformance/goapi/request_switches_test.go#L51))
      - [x] Accept untrusted redirect targets while still checking request origins and refusing control characters ([test](../../conformance/goapi/request_switches_test.go#L51))
    - [x] `crossSubDomainCookies` ([test](../../conformance/goapi/cookie_scope_http_test.go#L17))
      - [x] With CrossSubDomainCookies Domain .example.com, a sibling host shares the authenticated browser session and logout expires it on both hosts ([test](../../conformance/goapi/cookie_scope_http_test.go#L17))
    - [x] `cookies` ([test](../../conformance/goapi/cookie_options_test.go#L52))
      - [x] Override one cookie's name and attributes by its base name ([test](../../conformance/goapi/cookie_options_test.go#L52))
      - [x] Refuse overrides a browser would reject or that hide a cookie from the auth endpoints, each with its reason ([test](../../conformance/goapi/cookie_options_test.go#L74))
      - [x] Expire admin_session with the scope it was set with, give trust_device its own attributes and keep the One Tap nonce host-only at Path=/ ([test](../../cookies_test.go#L204))
    - [x] `defaultCookieAttributes` ([test](../../conformance/goapi/cookie_options_test.go#L19))
      - [x] Apply default attributes to every cookie before the per-cookie overrides ([test](../../conformance/goapi/cookie_options_test.go#L19))
    - [x] `cookiePrefix` ([test](../../cookies_test.go#L26))
      - [x] CookiePrefix names the session and OAuth state cookies (__Secure-company.*), and an instance with another prefix cannot read them ([test](../../cookies_test.go#L26))
    - [ ] `database`
    - [ ] `backgroundTasks`
    - [x] `skipTrailingSlashes` ([test](../../conformance/goapi/request_switches_test.go#L36))
      - [x] Serve paths with trailing slashes as the paths without them ([test](../../conformance/goapi/request_switches_test.go#L36))
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
      - [x] Use the configured handler severity threshold for events from core and plugin hooks ([test](../../conformance/goapi/logger_test.go#L46))
    - [ ] `"debug"`
    - [ ] `"info"`
    - [ ] `"warn"`
    - [x] `"error"` ([test](../../conformance/goapi/logger_test.go#L46))
      - [x] Record errors and suppress warnings with the standard error threshold ([test](../../conformance/goapi/logger_test.go#L46))
    - [x] `log` ([test](../../conformance/goapi/logger_test.go#L51))
      - [x] Route core and plugin diagnostics to a host JSON handler with application attributes ([test](../../conformance/goapi/logger_test.go#L51))
    - [x] `message` ([test](../../conformance/goapi/logger_test.go#L56))
      - [x] The host JSON handler receives the exact core and plugin message text for each record: the sign-up verification delivery failure and the last-login-method save failure ([test](../../conformance/goapi/logger_test.go#L56))
    - [x] `...args` ([test](../../adapters/sqlstore/oauth_id_token_test.go#L249))
      - [x] The OAuth ID-token warning passes the ignored reserved claim names to the host handler as a structured attribute, and the test checks that no private callback value appears in the output (SQLite, PostgreSQL, MySQL) ([test](../../adapters/sqlstore/oauth_id_token_test.go#L249))
  - [ ] `databaseHooks`
    - [x] Configure user and session create hooks, and refuse hook configurations an enabled feature would bypass ([test](../../conformance/goapi/database_hooks_test.go#L297))
    - [x] Configure session update and delete hooks, and refuse configurations an enabled feature would bypass ([test](../../conformance/goapi/database_session_hooks_test.go#L249))
    - [x] Configure user update hooks for profile updates, email changes and verification ([test](../../conformance/goapi/database_user_hooks_test.go#L126))
    - [x] Configure account hooks for credential and linked account writes ([test](../../conformance/goapi/database_user_hooks_test.go#L246))
  - [ ] `onAPIError`
    - [x] Report the original error and already-resolved user before writing the localized HTTP response ([test](../../conformance/goapi/error_reporting_test.go#L88))
    - [ ] `throw`
    - [x] `onError` ([test](../../conformance/core.test.mjs#L1329))
      - [x] Wait for the host reporter and preserve the endpoint error when the reporter fails ([test](../../conformance/core.test.mjs#L1329))
      - [x] Contain reporter panics and keep callback errors and credentials out of client responses and logs ([test](../../conformance/goapi/error_reporting_test.go#L67))
    - [x] `errorURL` ([test](../../error_page_test.go#L10))
      - [x] With Options.ErrorRedirectURL set, the mounted /api/auth/error endpoint returns 302 to the configured URL with the error code added and its own query kept ([test](../../error_page_test.go#L10))
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
  - [x] `hooks` ([test](../../conformance/goapi/endpoint_hooks_test.go#L22))
    - [x] Configure application before and after hooks for the mounted HTTP endpoints ([test](../../conformance/goapi/endpoint_hooks_test.go#L22))
  - [x] `disabledPaths` ([test](../../conformance/goapi/disabled_paths_test.go#L14))
    - [x] Disable exact mount-relative HTTP paths before key extraction and request hooks, omit their fixed routes from OpenAPI and retain native Go calls ([test](../../conformance/goapi/disabled_paths_test.go#L14))
    - [x] Apply the same per-path HTTP setting to the SCIM wrapper and preserve neighboring resource operations ([test](../../plugins/scim/http_test.go#L128))
  - [ ] `telemetry`

## Security

- [ ] Security
  - [x] Password Hashing ([test](../../conformance/core.test.mjs#L1391))
    - [x] Open and replace host-encoded credentials from either runtime in the same account database ([test](../../conformance/core.test.mjs#L1391))
  - [x] Secret Rotation ([test](../../adapters/sqlstore/oauth_encryption_test.go#L18))
    - [x] Stores provider credentials under key version 0 and still reads them after Secrets puts a new version first ([test](../../adapters/sqlstore/oauth_encryption_test.go#L18))
  - [ ] Session Management
    - [x] Session Expiration ([test](../../session_refresh_test.go#L46))
      - [x] With default options, a read does not refresh the session before one day ([test](../../session_refresh_test.go#L46))
    - [x] Session Revocation ([test](../../conformance/goapi/http_test.go#L48))
      - [x] Over HTTP, revoke-other-sessions makes the older login's cookie return 401 ([test](../../conformance/goapi/http_test.go#L48))
  - [ ] CSRF Protection
    - [ ] Avoid simple requests
    - [ ] Origin Validation
    - [ ] Secure Cookie Settings
    - [x] Fetch Metadata Protection for First-Login CSRF ([test](../../conformance/goapi/http_test.go#L109))
      - [x] Without cookies: a cross-site navigation sign-up gets 403 CROSS_SITE_NAVIGATION_LOGIN_BLOCKED, and a sign-in with an untrusted Origin gets 403 INVALID_ORIGIN ([test](../../conformance/goapi/http_test.go#L109))
    - [x] No Mutations on GET Requests (with additional safeguards) ([test](../../conformance/goapi/oauth_test.go#L151))
      - [x] The GET OAuth callback that creates a session sends a nonce and PKCE to the provider ([test](../../conformance/goapi/oauth_test.go#L151))
    - [ ] Your own routes that call `auth.api`
    - [ ] Disabling Security Checks
      - [x] `disableCSRFCheck` ([test](../../conformance/goapi/request_switches_test.go#L43))
        - [x] Turn off the origin, Fetch Metadata and cross-site navigation checks together ([test](../../conformance/goapi/request_switches_test.go#L43))
      - [x] `disableOriginCheck` ([test](../../conformance/goapi/request_switches_test.go#L51))
        - [x] Accept untrusted callback and redirect URLs; unlike the reference, request origins are still checked ([test](../../conformance/goapi/request_switches_test.go#L51))
      - [ ] Summary
        - [x] `disableCSRFCheck` ([test](../../conformance/goapi/request_switches_test.go#L43))
          - [x] Turn off only the CSRF protections ([test](../../conformance/goapi/request_switches_test.go#L43))
        - [ ] `disableOriginCheck`
          - [x] Turn off redirect URL validation; CSRF protection stays on until DisableCSRFCheck is also set, by design ([test](../../conformance/goapi/request_switches_test.go#L57))
  - [ ] OAuth State and PKCE
  - [ ] Cookies
    - [x] With an HTTPS base URL, the sign-up session cookie is Secure, HttpOnly, SameSite=Lax, Path=/ and persistent ([test](../../conformance/goapi/http_test.go#L73))
    - [ ] Customizing Cookies
  - [ ] Rate Limiting
  - [ ] IP Address Headers
  - [ ] Trusted Proxy Headers
  - [ ] Trusted Origins
    - [ ] Basic Usage
    - [ ] Wildcard Origins
      - [x] Protocol-specific wildcards ([test](../../conformance/trusted-origins.mjs#L38))
        - [x] Complete the OAuth provider callback on the static auth host and return the browser to an allowed HTTPS application subdomain ([test](../../conformance/goapi/oauth_test.go#L198))
        - [x] Under https://*.shop.example.test, HTTPS subdomains at any depth are accepted ([test](../../conformance/trusted-origins.mjs#L38))
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
