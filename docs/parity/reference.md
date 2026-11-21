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
    - [x] Resolve public URL and mount path from explicit options and process settings ([test](../../env_test.go#L19))
    - [ ] Dynamic Base URL
      - [ ] `allowedHosts`
      - [ ] `protocol`
      - [ ] `fallback`
  - [ ] `basePath`
    - [x] Resolve public URL and mount path from explicit options and process settings ([test](../../env_test.go#L19))
  - [ ] `trustedOrigins`
    - [x] Combine configured origins and environment origins for callback validation ([test](../../env_test.go#L33))
    - [ ] Static Origins
    - [ ] Dynamic Origins
      - [ ] On a direct `auth.api` call with a static `baseURL`
    - [ ] Wildcard Support
      - [ ] Pattern Syntax
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
    - [x] Give an explicit signing secret precedence over environment defaults ([test](../../env_test.go#L41))
    - [ ] `AUTH_SECRET`
    - [ ] `process.env.AUTH_SECRET`
  - [ ] `secrets`
    - [x] Sign with the active key and accept cookies from a retained key ([test](../../env_test.go#L79))
    - [x] Accept an email proof signed by a retained key and reject it after retirement ([test](../../env_test.go#L140))
  - [ ] `database`
  - [ ] `secondaryStorage`
  - [ ] `emailVerification`
    - [ ] `sendVerificationEmail`
    - [ ] `sendOnSignUp`
    - [ ] `sendOnSignIn`
    - [ ] `autoSignInAfterVerification`
    - [ ] `expiresIn`
  - [ ] `emailAndPassword`
    - [ ] `enabled`
    - [ ] `disableSignUp`
    - [ ] `requireEmailVerification`
    - [ ] `minPasswordLength`
    - [ ] `maxPasswordLength`
    - [ ] `autoSignIn`
    - [ ] `sendResetPassword`
    - [ ] `onPasswordReset`
    - [ ] `revokeSessionsOnPasswordReset`
    - [ ] `resetPasswordTokenExpiresIn`
    - [ ] `onExistingUserSignUp`
    - [ ] `customSyntheticUser`
    - [ ] `password`
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
    - [ ] `changeEmail`
    - [ ] `deleteUser`
  - [ ] `session`
    - [ ] `modelName`
    - [ ] `fields`
    - [ ] `expiresIn`
    - [ ] `updateAge`
    - [ ] `additionalFields`
    - [ ] `storeSessionInDatabase`
    - [ ] `preserveSessionInDatabase`
    - [ ] `cookieCache`
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
      - [ ] `enabled`
      - [ ] `disableImplicitLinking`
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
    - [x] Select the production rate limit by default and honor an explicit override ([test](../../env_test.go#L121))
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
    - [ ] `disabled`
    - [ ] `disableColors`
    - [ ] `level`
    - [ ] `"debug"`
    - [ ] `"info"`
    - [ ] `"warn"`
    - [ ] `"error"`
    - [ ] `log`
    - [ ] `message`
    - [ ] `...args`
  - [ ] `databaseHooks`
  - [ ] `onAPIError`
    - [ ] `throw`
    - [ ] `onError`
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
  - [ ] `disabledPaths`
  - [ ] `telemetry`

## Security

- [ ] Security
  - [ ] Password Hashing
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
      - [ ] Protocol-agnostic wildcards
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
