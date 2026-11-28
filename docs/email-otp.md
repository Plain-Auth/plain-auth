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
| `/sign-in/email-otp` | `email`, `otp`, optional `name`, `image` and configured profile fields | Registers or authenticates the mailbox owner. The response contains the user and token, and the client receives a session cookie. |
| `/email-otp/request-password-reset` or `/forget-password/email-otp` | `email` | Requests a recovery code for an existing mailbox. |
| `/email-otp/reset-password` | `email`, `otp`, `password` | Applies the host's credential policy and sets the password. `RevokeSessionsOnPasswordReset` revokes existing sessions when enabled. |
| `/email-otp/request-email-change` | `newEmail`, optional `otp` from the current mailbox | An authenticated user requests a code for the new address. |
| `/email-otp/change-email` | `newEmail`, `otp` | Verifies the new mailbox and retains the authenticated account and session. |

A sign-in code can create a verified account. Set `DisableSignUp` in the plugin to restrict sign-in to existing users. Recovery and verification return the same successful request response for unknown addresses and skip delivery. Over HTTP a failed delivery is logged and gets that same response, including `/send-verification-email` with `OverrideDefaultEmailVerification`; a direct `SendEmailOTP` call returns the sender's error. Signing in to a previously unverified account removes credentials and sessions created before the mailbox owner proved control.

Set `SendVerificationOnSignUp` in the plugin to send a code when registering a password account. `OverrideDefaultEmailVerification` routes the host's address-verification mail through this plugin, including verification-gated sign-up. With both set, the sign-up code is that verification mail, sent once; another runtime ignores the plugin option then and sends nothing unless its core option asks. Setting the core `SendVerificationOnSignUp` to false as well stops `New` with an error, since the two disagree. [Override tests](../conformance/goapi/emailotp_signup_test.go) An application that also enables the core email-change workflow can keep its existing mail-link sender for that workflow.

## Registration profile fields

When a verified mailbox first signs in, `POST /sign-in/email-otp` accepts writable `UserAdditionalFields` at the top level beside `email` and `otp`. The direct Go method and HTTP client use the same input type.

```go
result, err := client.SignInEmailOTP(ctx, plainauth.EmailOTPSignInInput{
    Email: email, OTP: code, Name: "Jo",
    AdditionalFields: map[string]any{"locale": "fr", "newsletter": false},
})
```

The registration path applies configured defaults, column aliases and the host-owned input policy. Public fields appear under `result.User` and are available from the current session. Hidden values stay in storage. The wire property `otp` is reserved for the submitted proof. A valid proof is spent if required profile data is missing or invalid. Request a fresh code after correcting the registration data.

A returning user can send only their email and code. Sign-in reads their stored profile and ignores registration input. Use the authenticated profile update endpoint to change writable fields. Custom adapters that enable email OTP signup and configured user fields implement `EmailOTPRegistrationStore`. The built-in memory and SQL adapters commit the new profile, session and successful proof consumption together. If session storage fails and the transaction rolls back, the code can be retried within its original lifetime. [Additional user fields](user-fields.md)

## Expiry, retries and resends

Codes default to six random decimal digits, five minutes of validity and three failed comparisons. Configure `Length`, `ExpiresIn`, `AllowedAttempts` and optionally `GenerateOTP` to customize issuance. Each endpoint uses a three-request-per-minute limit per peer when the host's limiter is enabled. `RateLimit` overrides that endpoint budget. The database enforces the per-code attempt limit across instances.

`StoreOTP` accepts `plain` (default), `hashed` (SHA-256) and `encrypted` (authenticated encryption under the instance secret). Code identifiers keep the address and are not affected by [`StoreVerificationIdentifier`](databases.md#verification-identifiers). The default `ResendStrategy` is `rotate`: each resend mails a new code with a fresh attempt budget, and the earlier code is refused. [Resend tests](../adapters/sqlstore/emailotp_resend_test.go) Setting it to `reuse` resends an unexpired, recoverable code with a fresh validity and its accumulated failed attempts. Hashed codes rotate on resend. Invalid attempts return `INVALID_OTP`. The next submission after the budget is exhausted returns `TOO_MANY_ATTEMPTS` and removes the proof. An expired stored code returns `OTP_EXPIRED`.

[Verification database hooks](hooks.md#verification-hooks) run create hooks when a code is stored. Before every guess they run the delete before hooks. Afterwards they run the delete after hooks when a code is spent or removed, and the update after hooks when a wrong guess is counted. A declined code answers as sent, with nothing stored or mailed. A declined guess is refused before the code is compared and is not counted. Update and delete hooks need a store implementing `plainauth.EmailOTPFinder`, as the SQL and memory stores do.

Go callers can use `Auth.SendEmailOTP`, `CheckEmailOTP`, `VerifyEmailOTP`, `SignInEmailOTP` and `ResetPasswordEmailOTP`. The HTTP client provides the same operations plus `RequestPasswordResetEmailOTP` and retains the login cookie in its jar. With the default verification policy, the server consumes a successful proof and commits the requested account or session change in one transaction. With account verification callbacks enabled, it first consumes the code, runs the before hook, commits the exact owner’s address change, and runs the after hook. An after-hook error preserves the address change and stops session issuance. [Email verification callbacks](account.md#verify-an-address-with-application-callbacks)

## Change an address

Set `ChangeEmail: emailotp.ChangeOptions{Enabled: true, VerifyCurrentEmail: true}` to require mailbox proofs at both addresses. The signed-in user requests an `email-verification` code for their current address, then submits that code with the new address to `request-email-change`. The server consumes the current proof as it issues the new proof. A registered destination receives the standard request response and no mail. Submit the code from the new address to `change-email` using the same account. Setting `VerifyCurrentEmail` to false allows the signed-in user to begin directly with the new address.

A change proof is bound to its issuing user and original email. The SQL adapter validates the active session during the update. The native client provides `RequestEmailChangeOTP` and `ChangeEmailOTP`.

## Trusted server access

`Auth.CreateEmailOTP(ctx, email, purpose)` generates a fresh proof and returns the raw code to application code without delivering mail. A verification create hook that declines the code makes it return a code that was never stored. `Auth.ReadEmailOTP(ctx, email, purpose)` returns a pointer to a recoverable code, or nil after expiry or when no code exists. A hashed code produces an error on read. Both operations are available only inside the Go process.

To supply your own storage transform, configure either `Hash` or both `Encrypt` and `Decrypt`. A recoverable transform supports `ResendStrategy: "reuse"`. Configure one storage strategy per instance. Keep transform implementations and key material consistent across servers sharing proofs.
