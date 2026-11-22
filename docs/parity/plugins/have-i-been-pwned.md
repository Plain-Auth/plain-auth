# Have I Been Pwned

[Feature index](../README.md)

## Interfaces

- [x] Have I Been Pwned endpoints, types and options ([test](../../../conformance/password-screening.mjs#L24))
  - [x] Install the policy and verify the default range checks across registration, recovery and administration ([test](../../../conformance/password-screening.mjs#L24))
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
  - [x] `haveIBeenPwned` ([test](../../../conformance/password-screening.mjs#L24))
    - [x] Reject compromised credentials through the public JavaScript client ([test](../../../conformance/core.test.mjs#L311))
    - [x] Apply the installed policy to all seven default paths and allow ordinary sign-in ([test](../../../conformance/password-screening.mjs#L24))

## Have I Been Pwned

- [x] Have I Been Pwned ([test](../../../conformance/password-screening.mjs#L24))
  - [x] Use the installed policy across personal and administrator credential changes with a local padded range service ([test](../../../conformance/password-screening.mjs#L24))
  - [x] Usage ([test](../../../conformance/password-screening.mjs#L24))
    - [x] Reject a breached password in native and HTTP credential-setting operations ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L85))
    - [x] Verify public error responses, preservation of credentials and successful clean retries ([test](../../../conformance/password-screening.mjs#L24))
    - [x] Custom password flows ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L31))
      - [x] Query a padded five-character hash range, compare suffixes locally and handle invalid responses ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L31))
  - [x] Options ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L194))
    - [x] Set the enabled state, path filter and custom rejection message ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L194))
    - [x] `enabled` ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L194))
      - [x] Skip the range service when disabled and enable screening by default ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L194))
    - [x] `customPasswordCompromisedMessage` ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L116))
      - [x] Return the chosen breach message and preserve the stable error code ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L116))
  - [x] Security Notes ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L31))
    - [x] Query a padded five-character hash range, compare suffixes locally and handle invalid responses ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L31))

## Credential-setting paths

- [x] Apply default checks inside each credential-setting flow ([test](../../../conformance/password-screening.mjs#L24))
  - [x] Exercise all seven default writes through the browser client on both runtimes ([test](../../../conformance/password-screening.mjs#L24))
  - [x] `/sign-up/email` ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L85))
    - [x] Screen the proposed password and preserve the existing account state on rejection ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L85))
  - [x] `/change-password` ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L85))
    - [x] Screen the proposed password and preserve the existing account state on rejection ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L85))
  - [x] `/reset-password` ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L85))
    - [x] Screen the proposed password and preserve the existing account state on rejection ([test](../../../plugins/pwnedpassword/pwnedpassword_test.go#L85))
  - [x] `/email-otp/reset-password` ([test](../../../conformance/password-screening.mjs#L87))
    - [x] Reject a breached password and accept a clean retry with the same email code ([test](../../../conformance/password-screening.mjs#L87))
  - [x] `/phone-number/reset-password` ([test](../../../conformance/password-screening.mjs#L95))
    - [x] Reject a breached password and accept a clean retry with the same SMS code ([test](../../../conformance/password-screening.mjs#L95))
  - [x] `/admin/create-user` ([test](../../../conformance/password-screening.mjs#L101))
    - [x] Reject a breached initial credential before creating the user, then allow a clean password ([test](../../../conformance/password-screening.mjs#L101))
  - [x] `/admin/set-user-password` ([test](../../../conformance/password-screening.mjs#L104))
    - [x] Preserve a member's password on rejection and verify an administrator can replace it with a clean one ([test](../../../conformance/password-screening.mjs#L104))
