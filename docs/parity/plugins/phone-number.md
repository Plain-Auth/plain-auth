# Phone number

[Feature index](../README.md)

## Interfaces

- [ ] Phone number endpoints, types and options
  - [ ] `phoneNumberClient`
  - [ ] `phoneNumber`
  - [ ] `POST /sign-in/phone-number`
  - [ ] `POST /phone-number/send-otp`
  - [ ] `POST /phone-number/verify`
  - [ ] `POST /phone-number/request-password-reset`
  - [ ] `POST /phone-number/reset-password`
  - [ ] `UserWithPhoneNumber`
  - [ ] `PhoneNumberOptions`
    - [ ] `otpLength`
    - [ ] `sendOTP`
    - [ ] `verifyOTP`
    - [ ] `sendPasswordResetOTP`
    - [ ] `expiresIn`
    - [ ] `phoneNumberValidator`
    - [ ] `requireVerification`
    - [ ] `callbackOnVerification`
    - [ ] `signUpOnVerification`
    - [ ] `schema`
    - [ ] `allowedAttempts`

## Phone Number

- [ ] Phone Number
  - [ ] Usage
    - [ ] Send OTP for Verification
      - [ ] `POST /phone-number/send-otp`
        - [ ] Parameter `phoneNumber`
    - [ ] Verify Phone Number
      - [ ] `POST /phone-number/verify`
        - [ ] Parameter `phoneNumber`
        - [ ] Parameter `code`
        - [ ] Parameter `disableSession` (optional)
        - [ ] Parameter `updatePhoneNumber` (optional)
    - [ ] Consume an OTP on the Server
    - [ ] Allow Sign-Up with Phone Number
    - [ ] Sign In with Phone Number
      - [ ] `POST /sign-in/phone-number`
        - [ ] Parameter `phoneNumber`
        - [ ] Parameter `password`
        - [ ] Parameter `rememberMe` (optional)
    - [ ] Update Phone Number
    - [ ] Remove Phone Number
    - [ ] Disable Session Creation
    - [ ] Request Password Reset
      - [ ] `POST /phone-number/request-password-reset`
        - [ ] Parameter `phoneNumber`
      - [ ] `POST /phone-number/reset-password`
        - [ ] Parameter `otp`
        - [ ] Parameter `newPassword`
  - [ ] Options
    - [ ] `otpLength`
    - [ ] `sendOTP`
    - [ ] `expiresIn`
    - [ ] `callbackOnVerification`
    - [ ] `sendPasswordResetOTP`
    - [ ] `phoneNumberValidator`
    - [ ] `verifyOTP`
    - [ ] `signUpOnVerification`
      - [ ] `getTempEmail`
      - [ ] `getTempName`
    - [ ] `requireVerification`
  - [ ] Schema
    - [ ] User Table
      - [x] Upgrade populated user tables, allow missing numbers, and enforce one owner per telephone number on three SQL engines ([test](../../../adapters/sqlstore/phone_schema_test.go#L10))
      - [x] Preserve a verified phone across migration replay and store an explicit false flag on reassignment ([test](../../../adapters/sqlstore/phone_schema_test.go#L57))
      - [ ] `phoneNumberUserTableFields.phoneNumber`
      - [ ] `phoneNumberUserTableFields.phoneNumberVerified`
    - [ ] OTP Verification Attempts
