# One time token

[Feature index](../README.md)

## Interfaces

- [ ] One time token endpoints, types and options
  - [x] `oneTimeTokenClient` ([test](../../../conformance/transfer-options.mjs#L46))
    - [x] Generate from the signed-in client, verify in a separate client and reject a replay ([test](../../../conformance/transfer-options.mjs#L46))
  - [ ] `GET /one-time-token/generate`
    - [x] Require a live session and honor server-only generation ([test](../../../adapters/sqlstore/onetimetoken_test.go#L157))
    - [x] Generate from a direct signed-in session using the configured host callback and the current HTTP request ([test](../../../conformance/transfer-options.mjs#L37))
  - [ ] `POST /one-time-token/verify`
    - [x] Limit concurrent redemption across independent servers to one successful response ([test](../../../adapters/sqlstore/onetimetoken_test.go#L150))
    - [x] Transfer the same session in both directions using the official client ([test](../../../conformance/core.test.mjs#L378))
    - [x] Burn the proof under a current direct-owner policy even after a separate node installs administration ([test](../../../adapters/sqlstore/onetimetoken_policy_test.go#L54))
    - [x] Limit concurrent redemptions on a shared in-memory store to one owner session ([test](../../../adapters/memory/onetimetoken_test.go#L54))
  - [ ] `OneTimeTokenOptions`
    - [ ] `expiresIn`
      - [x] Persist the configured transfer lifetime ([test](../../../adapters/sqlstore/onetimetoken_test.go#L165))
    - [ ] `disableClientRequest`
      - [x] Allow direct host generation and deny HTTP generation ([test](../../../adapters/sqlstore/onetimetoken_test.go#L157))
    - [x] `generateToken` ([test](../../../client/onetimetoken_context_test.go#L92))
      - [x] Pass the authenticated user and session to the token generator ([test](../../../client/onetimetoken_test.go#L29))
      - [x] Pass the original user, session and initiating HTTP request to the host generator ([test](../../../client/onetimetoken_context_test.go#L92))
    - [x] `disableSetSessionCookie` ([test](../../../conformance/transfer-options.mjs#L45))
      - [x] Return the original session while suppressing the cookie ([test](../../../adapters/sqlstore/onetimetoken_test.go#L168))
      - [x] Return the original login while leaving the receiving browser signed out ([test](../../../conformance/transfer-options.mjs#L45))
    - [x] `storeToken` ([test](../../../conformance/transfer-options.mjs#L41))
      - [x] Use the configured hasher on generation and verification ([test](../../../client/onetimetoken_test.go#L73))
      - [x] Select plain, SHA-256 or a host-defined storage encoding and redeem across implementations ([test](../../../conformance/transfer-options.mjs#L41))
    - [x] `setOttHeaderOnNewSession` ([test](../../../conformance/transfer-options.mjs#L35))
      - [x] Send and expose Set-Ott on creation and exclude ordinary profile updates ([test](../../../adapters/sqlstore/onetimetoken_test.go#L112))
      - [x] Expose the configured token on a new login and issue an independent token on request ([test](../../../conformance/transfer-options.mjs#L35))
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
    - [x] `generateToken` ([test](../../../client/onetimetoken_context_test.go#L88))
      - [x] Pass the owning session and request metadata to the chosen generator ([test](../../../client/onetimetoken_context_test.go#L88))
    - [x] `storeToken` ([test](../../../conformance/transfer-options.mjs#L41))
      - [x] Verify configured at-rest transfer keys and redeem the original session on a peer ([test](../../../conformance/transfer-options.mjs#L41))
    - [x] `plain` ([test](../../../conformance/transfer-options.mjs#L41))
      - [x] Verify configured at-rest transfer keys and redeem the original session on a peer ([test](../../../conformance/transfer-options.mjs#L41))
    - [x] `hashed` ([test](../../../conformance/transfer-options.mjs#L41))
      - [x] Verify configured at-rest transfer keys and redeem the original session on a peer ([test](../../../conformance/transfer-options.mjs#L41))
    - [x] `custom-hasher` ([test](../../../conformance/transfer-options.mjs#L41))
      - [x] Verify configured at-rest transfer keys and redeem the original session on a peer ([test](../../../conformance/transfer-options.mjs#L41))
