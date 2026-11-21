# Last login method

[Feature index](../README.md)

## Interfaces

- [ ] Last login method endpoints, types and options
  - [x] `LastLoginMethodClientConfig` ([test](../../../conformance/lastlogin-browser.test.mjs#L6))
    - [x] Use a custom preference name and set the domain when clearing it ([test](../../../conformance/lastlogin-browser.test.mjs#L6))
  - [x] `lastLoginMethodClient` ([test](../../../conformance/lastlogin-browser.test.mjs#L6))
    - [x] Read, match and clear the browser preference, including a custom cookie domain ([test](../../../conformance/lastlogin-browser.test.mjs#L6))
  - [ ] `LastLoginMethodOptions`
    - [ ] `cookieName`
      - [x] Apply the host cookie namespace and HTTPS security to the default browser preference ([test](../../../plugins/lastlogin/lastlogin_test.go#L47))
    - [x] `maxAge` ([test](../../../plugins/lastlogin/lastlogin_test.go#L41))
      - [x] Respect a custom preference lifetime in the emitted browser cookie ([test](../../../plugins/lastlogin/lastlogin_test.go#L41))
    - [x] `customResolveMethod` ([test](../../../adapters/sqlstore/lastlogin_test.go#L94))
      - [x] Override the method for a sign-in and fall back to the default when the resolver returns empty ([test](../../../adapters/sqlstore/lastlogin_test.go#L94))
    - [ ] `storeInDatabase`
      - [x] Share a successful sign-in method across sessions on all three SQL backends and in memory ([test](../../../adapters/sqlstore/lastlogin_test.go#L94))
    - [x] `beforeStoreCookie` ([test](../../../plugins/lastlogin/lastlogin_test.go#L39))
      - [x] Require consent independently of successful authentication ([test](../../../plugins/lastlogin/lastlogin_test.go#L39))
    - [ ] `schema`
  - [ ] `lastLoginMethod`

## Last Login Method

- [ ] Last Login Method
  - [ ] Usage
    - [ ] Getting the Last Used Method
      - [x] Record the most recent email sign-in method subject to consent ([test](../../../plugins/lastlogin/lastlogin_test.go#L15))
      - [x] Read and clear a custom Unicode method in a native TLS cookie jar without ending the session ([test](../../../client/lastlogin_test.go#L15))
    - [ ] UI Integration Example
  - [ ] Database Persistence
    - [ ] Enable database storage
      - [x] Expose the stored sign-in method when the configured plugin issues a session ([test](../../../adapters/sqlstore/lastlogin_test.go#L89))
    - [ ] Run database migration
    - [x] Access database field ([test](../../../conformance/core.test.mjs#L28))
      - [x] Expose the stored method through the browser client on both runtimes ([test](../../../conformance/core.test.mjs#L28))
    - [ ] Database Schema
      - [x] Generate the canonical columns on SQLite, PostgreSQL and MySQL, including combined plugin selections ([test](../../../conformance/schema.test.mjs#L105))
      - [ ] `lastLoginMethodUserTableFields.lastLoginMethod`
    - [ ] Custom Schema Configuration
  - [ ] Configuration Options
    - [ ] Server Options
      - [ ] cookieName
      - [ ] Note
      - [ ] maxAge
      - [ ] storeInDatabase
      - [ ] customResolveMethod
      - [ ] beforeStoreCookie
      - [ ] Example
      - [ ] schema
    - [ ] Client Options
      - [ ] cookieName
      - [ ] domain
    - [ ] Default Method Resolution
      - [ ] Email authentication
      - [ ] OAuth providers
      - [ ] OAuth callbacks
      - [ ] Sign up methods
      - [ ] `/callback/:id`
      - [ ] `/sign-in/email`
      - [ ] `/sign-up/email`
      - [ ] `/one-tap/callback`
      - [ ] `/siwe/verify`
      - [ ] `/passkey/verify-authentication`
      - [ ] `/magic-link/verify`
      - [ ] `/sign-in/email-otp`
  - [ ] Cross-Domain Support
    - [ ] Cross-subdomain setups
    - [ ] Cross-origin setups
  - [ ] GDPR Compliance
  - [ ] Advanced Examples
    - [ ] Custom Provider Tracking
    - [ ] Usage with Expo
