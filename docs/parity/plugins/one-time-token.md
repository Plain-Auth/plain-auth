# One time token

[Feature index](../README.md)

## Interfaces

- [ ] One time token endpoints, types and options
  - [ ] `oneTimeTokenClient`
  - [ ] `GET /one-time-token/generate`
    - [x] Require a live session and honor server-only generation ([test](../../../adapters/sqlstore/onetimetoken_test.go#L157))
  - [ ] `POST /one-time-token/verify`
    - [x] Limit concurrent redemption across independent servers to one successful response ([test](../../../adapters/sqlstore/onetimetoken_test.go#L150))
    - [x] Transfer the same session in both directions using the official client ([test](../../../conformance/core.test.mjs#L340))
  - [ ] `OneTimeTokenOptions`
    - [ ] `expiresIn`
      - [x] Persist the configured transfer lifetime ([test](../../../adapters/sqlstore/onetimetoken_test.go#L165))
    - [ ] `disableClientRequest`
      - [x] Allow direct host generation and deny HTTP generation ([test](../../../adapters/sqlstore/onetimetoken_test.go#L157))
    - [ ] `generateToken`
      - [x] Pass the authenticated user and session to the token generator ([test](../../../client/onetimetoken_test.go#L29))
    - [ ] `disableSetSessionCookie`
      - [x] Return the original session while suppressing the cookie ([test](../../../adapters/sqlstore/onetimetoken_test.go#L168))
    - [ ] `storeToken`
      - [x] Use the configured hasher on generation and verification ([test](../../../client/onetimetoken_test.go#L73))
    - [ ] `setOttHeaderOnNewSession`
      - [x] Send and expose Set-Ott on creation and exclude ordinary profile updates ([test](../../../adapters/sqlstore/onetimetoken_test.go#L112))
  - [ ] `oneTimeToken`

## One-Time Token Plugin

- [ ] One-Time Token Plugin
  - [ ] Usage
    - [ ] 1. Generate a Token
      - [ ] `GET /one-time-token/generate`
    - [ ] 2. Verify the Token
      - [ ] `POST /one-time-token/verify`
        - [ ] Parameter `token`
  - [ ] Options
    - [ ] `disableClientRequest`
    - [ ] `expiresIn`
    - [ ] `generateToken`
    - [ ] `storeToken`
    - [ ] `plain`
    - [ ] `hashed`
    - [ ] `custom-hasher`
