# Last login method

[Feature index](../README.md)

## Interfaces

- [ ] Last login method endpoints, types and options
  - [ ] `LastLoginMethodClientConfig`
  - [ ] `lastLoginMethodClient`
  - [ ] `LastLoginMethodOptions`
    - [ ] `cookieName`
      - [x] Apply the host cookie namespace and HTTPS security to the default browser preference ([test](../../../plugins/lastlogin/lastlogin_test.go#L47))
    - [ ] `maxAge`
    - [ ] `customResolveMethod`
    - [ ] `storeInDatabase`
    - [ ] `beforeStoreCookie`
    - [ ] `schema`
  - [ ] `lastLoginMethod`

## Last Login Method

- [ ] Last Login Method
  - [ ] Usage
    - [ ] Getting the Last Used Method
      - [x] Record the most recent email sign-in method subject to consent ([test](../../../plugins/lastlogin/lastlogin_test.go#L15))
    - [ ] UI Integration Example
  - [ ] Database Persistence
    - [ ] Enable database storage
    - [ ] Run database migration
    - [ ] Access database field
    - [ ] Database Schema
      - [x] Generate the canonical columns on SQLite, PostgreSQL and MySQL, including combined plugin selections ([test](../../../conformance/schema.test.mjs#L66))
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
