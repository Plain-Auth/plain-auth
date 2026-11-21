# Email one-time passwords

Use a mailbox code to verify an address, sign in, register an account, recover a password or change a verified address. The SQL adapters store challenges in the existing verification table. The memory adapter holds proofs for the lifetime of its store. Configure the sender to deliver each code to the message's email address.

```go
plugin, err := emailotp.New(emailotp.Options{
	StoreOTP: "encrypted",
	Send: func(ctx context.Context, m emailotp.Message) error {
		return mailer.SendCode(ctx, m.Email, string(m.Type), m.OTP)
	},
})
if err != nil {
	return err
}
opts.Plugins = append(opts.Plugins, plugin)
```

Import `plugins/emailotp` from this module. Each HTTP route accepts JSON under the application's auth mount.

| POST route | Fields | Result |
| --- | --- | --- |
| `/email-otp/send-verification-otp` | `email`, `type` | Requests a code and returns `{"success":true}`. Types are `email-verification`, `sign-in` and `forget-password`. |
| `/email-otp/check-verification-otp` | `email`, `type`, `otp` | Checks a registered mailbox's code and preserves a successful proof for its final action. |
| `/email-otp/verify-email` | `email`, `otp` | Confirms the current account's email, preserves its credential and returns `status`, `user` and a null `token` by default. Enable `AutoSignInAfterVerification` to issue a session. |
| `/sign-in/email-otp` | `email`, `otp`, optional `name` and `image` | Registers or authenticates the mailbox owner. The response contains the user and token, and the client receives a session cookie. |
| `/email-otp/request-password-reset` or `/forget-password/email-otp` | `email` | Requests a recovery code for an existing mailbox. |
| `/email-otp/reset-password` | `email`, `otp`, `password` | Applies the host's credential policy and sets the password. `RevokeSessionsOnPasswordReset` revokes existing sessions when enabled. |
| `/email-otp/request-email-change` | `newEmail`, optional `otp` from the current mailbox | An authenticated user requests a code for the new address. |
| `/email-otp/change-email` | `newEmail`, `otp` | Verifies the new mailbox and retains the authenticated account and session. |

A sign-in code can create a verified account. Set `DisableSignUp` in the plugin to restrict sign-in to existing users. Recovery and verification return the same successful request response for unknown addresses and skip delivery. Signing in to a previously unverified account removes credentials and sessions created before the mailbox owner proved control.

Set `SendVerificationOnSignUp` in the plugin to send a code when registering a password account. `OverrideDefaultEmailVerification` routes the host's address-verification mail through this plugin, including verification-gated sign-up. An application that also enables the core email-change workflow can keep its existing mail-link sender for that workflow.

## Expiry, retries and resends

Codes default to six random decimal digits, five minutes of validity and three failed comparisons. Configure `Length`, `ExpiresIn`, `AllowedAttempts` and optionally `GenerateOTP` to customize issuance. Each endpoint uses a three-request-per-minute limit per peer when the host's limiter is enabled. `RateLimit` overrides that endpoint budget. The database enforces the per-code attempt limit across instances.

`StoreOTP` accepts `plain` (default), `hashed` (SHA-256) and `encrypted` (authenticated encryption under the instance secret). The default `ResendStrategy` is `rotate`. Setting it to `reuse` extends the validity of an unexpired, recoverable code and preserves its accumulated failed attempts. Hashed codes rotate on resend. Invalid attempts return `INVALID_OTP`. The next submission after the budget is exhausted returns `TOO_MANY_ATTEMPTS` and removes the proof. An expired stored code returns `OTP_EXPIRED`.

Go callers can use `Auth.SendEmailOTP`, `CheckEmailOTP`, `VerifyEmailOTP`, `SignInEmailOTP` and `ResetPasswordEmailOTP`. The HTTP client provides the same operations plus `RequestPasswordResetEmailOTP` and retains the login cookie in its jar. The server consumes a successful proof and commits the requested account or session change in one transaction.

## Change an address

Set `ChangeEmail: emailotp.ChangeOptions{Enabled: true, VerifyCurrentEmail: true}` to require mailbox proofs at both addresses. The signed-in user requests an `email-verification` code for their current address, then submits that code with the new address to `request-email-change`. The server consumes the current proof as it issues the new proof. A registered destination receives the standard request response and no mail. Submit the code from the new address to `change-email` using the same account. Setting `VerifyCurrentEmail` to false allows the signed-in user to begin directly with the new address.

A change proof is bound to its issuing user and original email. The SQL adapter validates the active session during the update. The native client provides `RequestEmailChangeOTP` and `ChangeEmailOTP`.

## Trusted server access

`Auth.CreateEmailOTP(ctx, email, purpose)` generates a fresh proof and returns the raw code to application code without delivering mail. `Auth.ReadEmailOTP(ctx, email, purpose)` returns a pointer to a recoverable code, or nil after expiry or when no code exists. A hashed code produces an error on read. Both operations are available only inside the Go process.

To supply your own storage transform, configure either `Hash` or both `Encrypt` and `Decrypt`. A recoverable transform supports `ResendStrategy: "reuse"`. Configure one storage strategy per instance. Keep transform implementations and key material consistent across servers sharing proofs.
