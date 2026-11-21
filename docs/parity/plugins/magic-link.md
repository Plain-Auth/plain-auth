# Magic link

[Feature index](../README.md)

## Interfaces

- [ ] Magic link endpoints, types and options
  - [ ] `magicLinkClient`
  - [ ] `POST /sign-in/magic-link`
    - [x] Deliver a private link and request metadata through the configured sender ([test](../../../adapters/sqlstore/magiclink_test.go#L73))
  - [ ] `GET /magic-link/verify`
    - [x] Promote mailbox ownership and revoke credentials that preceded verification ([test](../../../adapters/sqlstore/magiclink_test.go#L174))
    - [x] Consume shared hashed links in Go and the reference runtime with the official client ([test](../../../conformance/core.test.mjs#L335))
    - [x] Deny a delivered link after the target email is reassigned ([test](../../../adapters/sqlstore/magiclink_test.go#L158))
  - [ ] `MagicLinkOptions`
    - [ ] `expiresIn`
      - [x] Persist the configured link lifetime ([test](../../../adapters/sqlstore/magiclink_test.go#L238))
    - [ ] `allowedAttempts`
    - [ ] `sendMagicLink`
      - [x] Deliver the intended mailbox, private token and request metadata ([test](../../../adapters/sqlstore/magiclink_test.go#L73))
    - [ ] `disableSignUp`
      - [x] Reject registration for an unknown mailbox during verification ([test](../../../adapters/sqlstore/magiclink_test.go#L182))
    - [ ] `rateLimit`
      - [x] Apply the configured per-endpoint request budget ([test](../../../adapters/sqlstore/magiclink_test.go#L195))
    - [ ] `generateToken`
      - [x] Deliver the value from the configured generator ([test](../../../adapters/sqlstore/magiclink_test.go#L234))
    - [ ] `storeToken`
      - [x] Consume raw and custom-hashed keys on SQLite ([test](../../../adapters/sqlstore/magiclink_test.go#L243))
  - [ ] `magicLink`

## Magic link

- [ ] Magic link
  - [ ] Usage
    - [ ] Sign In with Magic Link
      - [ ] `POST /sign-in/magic-link`
        - [ ] Parameter `email`
        - [ ] Parameter `name` (optional)
        - [ ] Parameter `callbackURL` (optional)
        - [ ] Parameter `newUserCallbackURL` (optional)
        - [ ] Parameter `errorCallbackURL` (optional)
        - [ ] Parameter `metadata` (optional)
    - [ ] Verify Magic Link
      - [ ] `GET /magic-link/verify`
        - [ ] Parameter `token`
        - [ ] Parameter `callbackURL` (optional)
        - [ ] Parameter `newUserCallbackURL` (optional)
        - [ ] Parameter `errorCallbackURL` (optional)
  - [ ] Configuration Options
    - [ ] sendMagicLink
    - [ ] `email`
    - [ ] `url`
    - [ ] `token`
    - [ ] `metadata`
    - [ ] expiresIn
    - [ ] allowedAttempts
    - [ ] disableSignUp
    - [ ] rateLimit
    - [ ] generateToken
    - [ ] storeToken
    - [ ] `"plain"`
    - [ ] `"hashed"`
    - [ ] `{ type: "custom-hasher", hash: (token: string) => Promise<string> }`
