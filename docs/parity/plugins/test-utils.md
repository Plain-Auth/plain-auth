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
      - [ ] saveUser
      - [ ] deleteUser
      - [ ] saveOrganization
      - [ ] deleteOrganization
      - [ ] addMember
    - [ ] Auth Helpers
      - [ ] login
      - [ ] getAuthHeaders
      - [ ] getCookies
        - [ ] `name`
        - [ ] `value`
        - [ ] `domain`
        - [ ] `path`
        - [ ] `httpOnly`
        - [ ] `secure`
        - [ ] `sameSite`
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
