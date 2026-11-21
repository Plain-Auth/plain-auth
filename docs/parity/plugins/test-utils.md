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
      - [ ] createUser
      - [ ] createOrganization
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
      - [ ] getOTP
  - [ ] Options
    - [ ] `captureOTP`
  - [ ] Examples
    - [ ] Integration Test (Vitest)
    - [ ] E2E Test (Playwright)
    - [ ] OTP Verification Test
