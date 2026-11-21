# Have I Been Pwned

[Feature index](../README.md)

## Interfaces

- [ ] Have I Been Pwned endpoints, types and options
  - [x] `isPasswordCompromised` ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L31))
    - [x] Query a padded five-character hash range, compare suffixes locally and handle invalid responses ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L31))
  - [x] `HaveIBeenPwnedOptions` ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L194))
    - [x] Configure enabled state, path selection and the public error message ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L194))
    - [x] `customPasswordCompromisedMessage` ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L116))
      - [x] Return the chosen breach message and preserve the stable error code ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L116))
    - [x] `paths` ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L203))
      - [x] Use the default route set, replace it with custom paths or turn off all paths with an empty list ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L203))
    - [x] `enabled` ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L194))
      - [x] Skip the range service when disabled and enable screening by default ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L194))
  - [ ] `haveIBeenPwned`
    - [x] Reject compromised credentials through the public JavaScript client ([test](../../../conformance/core.test.mjs#L301))

## Have I Been Pwned

- [ ] Have I Been Pwned
  - [ ] Usage
    - [x] Reject a breached password in native and HTTP credential-setting operations ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L85))
    - [x] Custom password flows ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L31))
      - [x] Query a padded five-character hash range, compare suffixes locally and handle invalid responses ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L31))
  - [ ] Options
    - [x] `enabled` ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L194))
      - [x] Skip the range service when disabled and enable screening by default ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L194))
    - [x] `customPasswordCompromisedMessage` ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L116))
      - [x] Return the chosen breach message and preserve the stable error code ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L116))
  - [x] Security Notes ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L31))
    - [x] Query a padded five-character hash range, compare suffixes locally and handle invalid responses ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L31))

## Credential-setting paths

- [ ] Apply default checks inside each credential-setting flow
  - [x] `/sign-up/email` ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L85))
    - [x] Screen the proposed password and preserve the existing account state on rejection ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L85))
  - [x] `/change-password` ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L85))
    - [x] Screen the proposed password and preserve the existing account state on rejection ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L85))
  - [x] `/reset-password` ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L85))
    - [x] Screen the proposed password and preserve the existing account state on rejection ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L85))
  - [ ] `/email-otp/reset-password`
  - [ ] `/phone-number/reset-password`
  - [ ] `/admin/create-user`
  - [ ] `/admin/set-user-password`
