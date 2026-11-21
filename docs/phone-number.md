# Phone numbers

The phone-number plugin verifies possession of a telephone number, attaches it to an account and supports sign-in and password recovery. Install the `phone-number` database profile with the other profiles your application uses. Memory storage supports development and tests. SQLite, PostgreSQL and MySQL persist the number, verification flag and one-time proofs.

```go
import (
    "context"
    "regexp"

    "github.com/Stonewrit/stonewrit-auth"
    "github.com/Stonewrit/stonewrit-auth/plugins/phonenumber"
)

var international = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

func configurePhone(send func(context.Context, phonenumber.Message) error) (stonewrit.Plugin, error) {
    return phonenumber.New(phonenumber.Options{
        SendOTP:              send,
        SendPasswordResetOTP: send,
        RequireVerification:  true,
        Validate: func(_ context.Context, number string) (bool, error) {
            return international.MatchString(number), nil
        },
    })
}
```

Add the returned plugin to `stonewrit.Options.Plugins`. Supply a sender that accepts a context, delivers the code over SMS and returns delivery failures. `Message.Purpose` distinguishes telephone verification from password recovery. Applications choose their canonical number format. The plugin uses the submitted number as its identifier and accepts up to 255 UTF-8 characters. The example accepts a restricted international format.

## Verification and account access

All routes below accept JSON and are relative to the auth mount, normally `/api/auth`.

| Operation | Inputs and behavior |
| --- | --- |
| `POST /phone-number/send-otp` | Send `phoneNumber`. A successful delivery returns `{"message":"code sent"}`. |
| `POST /phone-number/verify` | Send `phoneNumber` and `code`. The response contains `status`, `user` and `token`. Use `disableSession: true` to receive a null token. An enrolled account signing in can receive a two-factor challenge. |
| `POST /phone-number/verify` with `updatePhoneNumber: true` | A direct owner session can attach a verified, available number. The response returns the same session token. |
| `POST /update-user` | Send `{"phoneNumber":null}` to remove the number and clear its verification flag. Setting a number requires verification. |
| `POST /sign-in/phone-number` | Send `phoneNumber`, `password`, and optionally `rememberMe`. Successful sign-in issues a session or starts the account's second-factor challenge. |
| `POST /phone-number/request-password-reset` | Send `phoneNumber`. Returns `{"status":true}` for registered and unknown numbers. With `RequireVerification`, only a verified owner receives the code. |
| `POST /phone-number/reset-password` | Send `phoneNumber`, `otp` and `newPassword`. A valid reset creates or replaces the password. Enable `RevokeSessionsOnPasswordReset` to revoke the owner's existing sessions. |

To enable first-use registration, set `SignUpOnVerification` to a `phonenumber.SignUpOptions` with a deterministic, unique `GetTempEmail` and an optional `GetTempName`. Use an application-controlled address namespace for generated account identifiers. The number becomes the default name and the generated email begins unverified. An existing account with a matching generated email retains its own identity. Core `DisableSignUp` also applies to first-use phone registration. `OnVerification` receives the verified user after the database commits. Enrollment and session policy still apply on later sign-in.

The Go HTTP client exposes `SendPhoneNumberOTP`, `VerifyPhoneNumber`, `SignInPhoneNumber`, `RequestPhonePasswordReset` and `ResetPhonePassword`. For an application-owned server workflow, call `auth.ConsumePhoneNumberOTP(ctx, number, code)`. Success spends the code without creating a user, issuing a session or running the account verification callback. This operation is available only in Go.

## Proof storage and delivery

Codes default to six decimal digits and expire after five minutes. `OTPLength` and `ExpiresIn` configure these values. `AllowedAttempts` takes an optional integer pointer. By default, three incorrect entries each return `INVALID_OTP`. The fourth attempt consumes the proof and returns `TOO_MANY_ATTEMPTS`, even if the code matches. An explicit zero blocks the first verification attempt. A new send replaces the prior verification code. Password-reset codes have a separate lifetime and attempt counter. All processes using the supported SQL adapters serialize changes to a given proof. A reset issued to one owner cannot change a different owner's password after reassignment.

The SQL adapters store the proof in `verification.value` as the original digits followed by a colon and the failed-attempt count. The number appears in the verification identifier. A companion, expiring record binds the issuance to the current owner. Restrict database, replica and backup access and apply encryption at rest. Keep phone numbers, codes, session tokens and provider message bodies out of request logs and traces. Run verification over HTTPS and configure rate limits for your deployment. [Rate limiting](authentication.md#set-limits-for-an-application)

A custom `VerifyOTP` can delegate verification to your SMS provider. Each acceptance is bound to the locally issued code generation, expiry and attempt budget. Resending while the provider is responding invalidates its earlier decision. Provider verification remains synchronous with the request. Delivery is application-owned and the automated tests use local message capture.

The native and browser fixtures cover the default account fields and verified owner workflow. Custom schema mappings, arbitrary extra signup fields and administrative assignment of unverified phone numbers are outside the tested HTTP contract. [Account and policy tests](../adapters/sqlstore/phone_accounts_test.go) · [Storage and proof tests](../adapters/sqlstore/phone_test.go) · [Browser-client comparison](../conformance/phone-contract.mjs)
