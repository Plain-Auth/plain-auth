# Test utils

[Feature index](../README.md)

## Interfaces

- [ ] Test utils endpoints, types and options
  - [ ] `testUtils`
  - [ ] `LoginResult`
  - [ ] `TestAuthOptions`
    - [ ] `userId`
    - [ ] `session`
  - [ ] `TestCookie`
  - [ ] `TestHelpers`
  - [ ] `TestUtilsOptions`
    - [ ] `captureOTP`

## Test Utils

- [ ] Test Utils
  - [ ] Can I include this in production?
    - [ ] TypeScript caveat
  - [ ] Usage
    - [ ] Factories
      - [x] createUser ([test](../../../authtest/fixtures_test.go#L26))
        - [x] Construct a unique unsaved user with editable fields and creation time ([test](../../../authtest/fixtures_test.go#L26))
        - [x] Check factory defaults and that neither factory writes a database record ([test](../../../conformance/auth-test-helpers.test.mjs#L35))
      - [x] createOrganization ([test](../../../authtest/fixtures_test.go#L35))
        - [x] Construct a unique unsaved organization with editable fields and creation time ([test](../../../authtest/fixtures_test.go#L35))
        - [x] Check factory defaults and that neither factory writes a database record ([test](../../../conformance/auth-test-helpers.test.mjs#L35))
    - [ ] Database Helpers
      - [x] saveUser ([test](../../../authtest/server_test.go#L71))
        - [x] Save a user fixture with no linked account or issued login on the four supported stores ([test](../../../authtest/server_test.go#L71))
      - [x] deleteUser ([test](../../../authtest/server_test.go#L133))
        - [x] Remove the fixture and revoke its sessions on another instance ([test](../../../authtest/server_test.go#L133))
      - [ ] saveOrganization
      - [ ] deleteOrganization
      - [ ] addMember
    - [ ] Auth Helpers
      - [ ] login
        - [x] Issue an authenticated session with the configured lifetime and owner ([test](../../../authtest/server_test.go#L85))
      - [ ] getAuthHeaders
        - [x] Generate independent authenticated request headers for a stored user ([test](../../../authtest/server_test.go#L111))
      - [ ] getCookies
        - [x] Supply a signed browser cookie and optionally override its domain ([test](../../../authtest/server_test.go#L118))
        - [x] `name` ([test](../../../authtest/server_test.go#L82))
          - [x] Use the issued session cookie’s name when a browser fixture logs in ([test](../../../authtest/server_test.go#L82))
        - [x] `value` ([test](../../../authtest/server_test.go#L82))
          - [x] Use the issued session cookie’s value when a browser fixture logs in ([test](../../../authtest/server_test.go#L82))
        - [x] `domain` ([test](../../../authtest/server_test.go#L82))
          - [x] Use the issued session cookie’s domain when a browser fixture logs in ([test](../../../authtest/server_test.go#L82))
        - [x] `path` ([test](../../../authtest/server_test.go#L82))
          - [x] Use the issued session cookie’s path when a browser fixture logs in ([test](../../../authtest/server_test.go#L82))
        - [x] `httpOnly` ([test](../../../authtest/server_test.go#L82))
          - [x] Use the issued session cookie’s httpOnly when a browser fixture logs in ([test](../../../authtest/server_test.go#L82))
        - [x] `secure` ([test](../../../authtest/server_test.go#L82))
          - [x] Use the issued session cookie’s secure when a browser fixture logs in ([test](../../../authtest/server_test.go#L82))
        - [x] `sameSite` ([test](../../../authtest/server_test.go#L82))
          - [x] Use the issued session cookie’s sameSite when a browser fixture logs in ([test](../../../authtest/server_test.go#L82))
    - [ ] OTP Capture
      - [x] getOTP ([test](../../../authtest/fixtures_test.go#L42))
        - [x] Capture email and SMS codes in the test process while forwarding the message to its sender ([test](../../../authtest/fixtures_test.go#L42))
        - [x] Isolate concurrent recorder access, return the latest code and preserve delivery errors ([test](../../../authtest/fixtures_test.go#L121))
  - [ ] Options
    - [ ] `captureOTP`
  - [ ] Examples
    - [ ] Integration Test (Vitest)
    - [ ] E2E Test (Playwright)
    - [x] OTP Verification Test ([test](../../../authtest/fixtures_test.go#L92))
      - [x] Read the code from a local recorder and verify the account through the public client ([test](../../../authtest/fixtures_test.go#L92))
      - [x] Redeem the captured proof on the pinned runtime ([test](../../../conformance/auth-test-helpers.test.mjs#L44))
