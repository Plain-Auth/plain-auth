# Anonymous

[Feature index](../README.md)

## Interfaces

- [ ] Anonymous endpoints, types and options
  - [x] `anonymousClient` ([test](../../../conformance/core.test.mjs#L787))
    - [x] The public browser client creates, upgrades, reads and removes guest identities on both servers ([test](../../../conformance/core.test.mjs#L787))
  - [x] `POST /sign-in/anonymous` ([test](../../../conformance/core.test.mjs#L787))
    - [x] Create a guest without a password, with a usable session and the guest flag ([test](../../../adapters/sqlstore/anonymous_test.go#L141))
    - [x] The public browser client creates, upgrades, reads and removes guest identities on both servers ([test](../../../conformance/core.test.mjs#L787))
  - [x] `POST /delete-anonymous-user` ([test](../../../adapters/sqlstore/anonymous_test.go#L170))
    - [x] Remove the authenticated guest and revoke its sessions ([test](../../../adapters/sqlstore/anonymous_test.go#L170))
    - [x] Protect permanent accounts from the guest deletion route ([test](../../../adapters/sqlstore/anonymous_test.go#L163))
  - [ ] `anonymous`
  - [ ] `AnonymousSession`
  - [ ] `UserWithAnonymous`
  - [ ] `AnonymousOptions`
    - [x] `emailDomainName` ([test](../../../adapters/sqlstore/anonymous_test.go#L123))
      - [x] Assign generated guest addresses to the configured domain ([test](../../../adapters/sqlstore/anonymous_test.go#L123))
    - [x] `onLinkAccount` ([test](../../../adapters/sqlstore/anonymous_test.go#L152))
      - [x] Roll back application-record writes and withhold the new session when a transfer callback fails ([test](../../../adapters/sqlstore/anonymous_test.go#L152))
    - [x] `disableDeleteAnonymousUser` ([test](../../../adapters/sqlstore/anonymous_test.go#L261))
      - [x] Retain a linked guest, block explicit deletion and deliver one callback across concurrent requests ([test](../../../adapters/sqlstore/anonymous_test.go#L261))
    - [x] `generateName` ([test](../../../adapters/sqlstore/anonymous_test.go#L81))
      - [x] Obtain guest display names from the initiating HTTP request ([test](../../../adapters/sqlstore/anonymous_test.go#L81))
    - [x] `generateRandomEmail` ([test](../../../client/anonymous_test.go#L45))
      - [x] Accept host-generated guest addresses and reject invalid values ([test](../../../client/anonymous_test.go#L45))
    - [ ] `schema`

## Anonymous

- [ ] Anonymous
  - [ ] Usage
    - [ ] Sign In Anonymously
      - [x] Start a guest identity through the browser or native client ([test](../../../conformance/core.test.mjs#L787))
      - [ ] `POST /sign-in/anonymous`
    - [ ] Link Account
      - [x] Wait for MFA completion before transferring guest data ([test](../../../adapters/sqlstore/anonymous_test.go#L215))
      - [x] Carry a guest through a provider redirect without the primary cookie ([test](../../../adapters/sqlstore/anonymous_oauth_test.go#L98))
      - [x] Complete guest handoff with the official Google One Tap client ([test](../../../conformance/core.test.mjs#L669))
      - [x] Transfer only after a verified WebAuthn assertion ([test](../../../adapters/sqlstore/passkey_test.go#L222))
      - [x] Link after local verification of the email OTP ([test](../../../adapters/sqlstore/anonymous_test.go#L184))
      - [x] Link a guest after the email sign-in link is verified ([test](../../../adapters/sqlstore/anonymous_test.go#L192))
    - [ ] Delete Anonymous User
      - [x] Distinguish guest deletion from sign-out ([test](../../../adapters/sqlstore/anonymous_test.go#L176))
      - [ ] `POST /delete-anonymous-user`
      - [ ] Notes:
  - [ ] Options
    - [ ] `emailDomainName`
    - [ ] `generateRandomEmail`
      - [ ] Notes:
    - [ ] `onLinkAccount`
    - [ ] `disableDeleteAnonymousUser`
    - [ ] `generateName`
  - [ ] Schema
    - [x] Generate the canonical columns on SQLite, PostgreSQL and MySQL, including combined plugin selections ([test](../../../conformance/schema.test.mjs#L105))
    - [ ] `anonymousUserTableFields.isAnonymous`
