# Account management and recovery

An authenticated user can update their name or profile image, verify their current password, and change it. Configure mail delivery to offer password recovery and email verification. The application owns the sender address, message text, and delivery service.

The email/password profile accepts configured application fields at signup and on authenticated updates. [Additional user fields](user-fields.md)

## Mail delivery

Set either sender on `Options`. Each callback receives the request context and a `MailLink` containing the destination user, a complete URL, and the token. `link.Request` is a copy of the HTTP request that caused the mail, without its body, for reading headers such as the client's locale; it is nil for a direct Go call. Deliver the URL only to the address on `link.User.Email`.

Over HTTP a sender's error is logged with a fixed message, without its text, and the endpoint answers as if the mail went out: a reset request still returns its generic message, an unverified sign-in still returns `EMAIL_NOT_VERIFIED`, and account deletion and email change still succeed. A failure therefore reveals nothing about the address. `/send-verification-email` is the exception: it waits for the sender and reports its error, unless the email OTP plugin's `OverrideDefaultEmailVerification` sends a code instead, which follows the email OTP rule. A direct Go call, such as `RequestPasswordReset`, returns the sender's error. With [`BackgroundTasks`](authentication.md#run-work-after-the-response) these sends run after the response. [Delivery tests](../conformance/goapi/background_tasks_test.go) For example, an application with an existing `mailer` can set the following options.

```go
opts.SendResetPassword = func(ctx context.Context, link plainauth.MailLink) error {
	return mailer.Send(ctx, link.User.Email, "Reset your password", link.URL)
}
opts.SendVerificationEmail = func(ctx context.Context, link plainauth.MailLink) error {
	return mailer.Send(ctx, link.User.Email, "Verify your email", link.URL)
}
opts.RevokeSessionsOnPasswordReset = true
```

Both links expire after an hour by default. Set `PasswordResetTokenTTL` or `EmailVerificationTokenTTL` to change that duration. The built-in SQL adapters implement `AccountStore`, including transactionally consuming a reset token and committing the replacement credential.

## HTTP operations

Paths below are relative to the configured auth base path. Authenticated browser writes must send the session cookie and a trusted origin.

| Method and path | Request | Result |
| --- | --- | --- |
| `POST /update-user` | Optional `name` and `image` fields. Set `image` to JSON null to clear it. | Changes the signed-in user's profile. Without a session it answers 401 before judging the fields. `name` and `image` must be strings, and an update with no field to change answers 400 `No fields to update`. |
| `POST /verify-password` | `password` | Returns `{"status":true}` when it matches the current user's credential. |
| `POST /change-password` | `currentPassword`, `newPassword`, optional `revokeOtherSessions` | Returns the user and a nullable token. Revoking sessions also replaces the caller's session cookie. |
| `POST /request-password-reset` | `email`, optional trusted `redirectTo` | Sends mail for a registered address and returns a generic acknowledgment. |
| `GET /reset-password/{token}` | Trusted `callbackURL` query parameter | Redirects the browser to the application with `token` or `error` in the query. |
| `POST /reset-password` | `newPassword` and the token in the body or query | Replaces the password and consumes the token. |
| `POST /send-verification-email` | `email`, optional trusted `callbackURL` | Sends a verification link. A signed-in request must name its own address. |
| `GET /verify-email` | `token`, optional trusted `callbackURL` | Marks the original account's current address verified. Redirects when a callback is supplied, with `error` set on failure: `TOKEN_EXPIRED`, `INVALID_TOKEN`, or `USER_NOT_FOUND` once no account holds the address. A link must name its owner and an expiry; Plain Auth never issues one without, and refuses one as `INVALID_TOKEN`. An email-change link whose account was deleted also answers `INVALID_TOKEN`. |

For a browser reset form, pass its URL as `redirectTo` when requesting the email. Read the delivered token from the callback query and submit it with the new password. A successful reset preserves existing sessions by default. Set `RevokeSessionsOnPasswordReset` to revoke them during the reset transaction.

`GET /reset-password/{token}` needs `callbackURL` exactly once; an empty value sends the browser to the error page. Opening it does not spend the token. A link whose account was deleted answers `INVALID_TOKEN`, like any dead link, rather than revealing that the account existed. For an account without a password, `change-password` and `delete-user` with a password answer 400 `CREDENTIAL_ACCOUNT_NOT_FOUND`, while `verify-password` answers `INVALID_PASSWORD` as for a wrong password. A password change that revokes other sessions from a browser that signed in without "remember me" keeps that browser's one-day session lifetime instead of extending it. [Password endpoint tests](../conformance/goapi/password_endpoints_test.go)

### Sign in after verifying an email

Set `Options.AutoSignInAfterVerification = true` to sign in a browser when it first verifies an ordinary email link. With an authenticated browser session for the same account, verification reissues its current token. A browser without a session, or with a direct session for a different account, receives a session for the verified account. The other account keeps its existing session. A subsequent click can redirect to the requested trusted callback or return `{"status":true,"user":null}` without issuing another credential. The Go HTTP client retains the cookie in its jar after `client.VerifyEmail(ctx, token)`. Server-side `Auth.VerifyEmail(ctx, token)` only verifies the address. [Browser interoperability](../conformance/email-verification-session.mjs) · [Native client](../client/email_verification_session_test.go)

The adapter locks the current owner, checks the exact normalized mailbox, and consumes the signed proof in the same transaction as the first session decision. The memory, SQLite, PostgreSQL and MySQL adapters implement `EmailVerificationSessionStore`. Custom adapters need this interface only when automatic sign-in is enabled. Deploy this policy on every node that issues verification sessions to obtain the single-winner guarantee. Each successful first verification retains a digest of the proof through its expiry. [Concurrent verification and policy tests](../adapters/sqlstore/email_verification_session_test.go)

An active ban or enrolled second factor permits mailbox verification alone. Requests carrying application or bearer credentials, delegated sessions, or invalid browser credentials also receive verification alone. The user can then complete their normal sign-in. A link for an address that has changed owners is rejected. The link records the profile’s millisecond revision. If the profile changes, the link can verify the still-current address and the user signs in normally. Some signed links carry only a whole-second issue time. If the account’s creation and update timestamps differ and its last update falls inside that second, the link verifies the address and the user signs in normally. That rule also covers accounts whose database sampled the two initial timestamps a millisecond apart. If verification is explicitly reset, an unexpired receipt blocks the spent proof and sibling proofs issued in or before the second when verification succeeded. A later request can deliver a fresh link. A cache callback failure during cookie publication keeps the email verified and removes the newly created session. This option applies to ordinary email links. Email-code verification and email-change confirmation have their own session policies.

### Observe a completed password reset

Set `Options.OnPasswordReset` to run a synchronous host callback after email-link, email-code or phone-code recovery. It receives the winning account and request context. The mounted HTTP endpoint also passes a copy of the request URL and headers with an empty body. Direct calls to `ResetPassword`, `ResetPasswordEmailOTP` and `ResetPhonePassword` pass a nil request.

```go
opts.OnPasswordReset = func(ctx context.Context, user plainauth.User, request *http.Request) error {
    return sendPasswordChangedNotice(ctx, user.Email)
}
```

The callback runs after the new credential and requested database session revocation have committed. By this time the proof is spent. A second instance cannot run the hook again by replaying the proof, even while the first callback is still running. A callback error reaches the caller, and the new password stays in effect. A process interruption after the commit can prevent the callback from running. Applications that require durable delivery need their own delivery tracking. [Transaction and replay tests](../adapters/sqlstore/password_reset_hook_test.go)

For an email-code reset, the callback sees the mailbox’s previous verification state. On success the adapter marks that same mailbox verified if needed. A callback failure leaves an unverified mailbox unverified. If the account changes its address during the callback, the library declines to apply the old mailbox proof to the new address. Link and phone resets preserve the email verification state. The phone recovery path supplies the bound phone number and its stored verification flag. [Paired HTTP lifecycle tests](../conformance/password-reset-hook.mjs)

The built-in SQL and memory adapters support all three callbacks. Custom email-code adapters that enable this callback must implement `EmailOTPResetHookStore` to separate the committed reset from subsequent email verification. A custom `PhoneAccountStore` returns the proof owner in `PhoneAccountResult.User` after a successful password reset. [Custom adapter tests](../conformance/goapi/password_reset_hook_test.go)

## Session lifetime

Persistent sessions last seven days by default. After the first 24 hours, an HTTP session lookup extends the expiry to seven days from that lookup and reissues the cookie. Set `SessionTTL` and `SessionUpdateAge` to adjust these intervals. A signed `dont_remember` marker keeps a browser-session login from sliding.

Use `GET /get-session?disableRefresh=true` for a read without renewal. In Go, `GetSession` reads the session without extending it. Set `DisableSessionRefresh` to keep the original expiry for every login.

With `DeferSessionRefresh` enabled, an ordinary `GET /get-session` on a persistent session includes `needsRefresh`. For the standard session endpoint, send a same-origin `POST /get-session` when it is true to perform the renewal. Installing the custom-session plugin replaces that endpoint with a GET-only projection. The SQL stores compare the saved expiry during renewal so that a concurrent sign-out can revoke the session. A custom store can opt into this behavior by implementing `SessionRefreshStore`.

## Registration and verification policy

Set `DisableSignUp` to close email registration. Set `DisableAutoSignIn` to create the account without issuing a session. `RequireEmailVerification` also withholds the first session and makes password sign-in require a verified address. In either mode that withholds the first session, re-registering an existing address returns a generic response with a null token.

With verification required, configure `SendVerificationEmail` to deliver the sign-up link. `SendVerificationOnSignUp` can explicitly enable or disable delivery on registration. `SendVerificationOnSignIn` sends another link when a correct password is presented for an unverified account.

## Changing an address

With `ChangeEmailEnabled`, a signed-in client can post `{"newEmail":"new@example.org","callbackURL":"/settings"}` to `/change-email`. Configure `SendVerificationEmail` to deliver the new inbox's link. For accounts with a verified address, `SendChangeEmailConfirmation` adds an initial link sent to the current inbox. Each link names the owner and the address they held when the change started. The final confirmation preserves the previous verification flag. `UpdateEmailWithoutVerification` allows an unverified account to adopt an unverified new address immediately.

A change that lands, at once or when a signed-in browser opens the final link, re-issues that browser's session cookies, so a [cached session view](authentication.md) shows the new address straight away. A link opened without a session stores the address and starts no session. An address another account already holds answers `{"status":true}` exactly like a free one, sends no mail and changes nothing, so the route does not reveal who is registered. The free address still waits for its mail to be sent; set `Options.BackgroundTasks` to send it after the response and remove that timing difference. Without `SendVerificationEmail`, a change that needs a link answers 400 `Verification email isn't enabled` for any address. Impersonated sessions and delegated credentials receive 403 `OWNER_SESSION_REQUIRED`, so only the owner can move the login address. If `SendVerificationEmail` is removed after a confirmation link was sent, that link answers 400 `VERIFICATION_EMAIL_NOT_ENABLED` instead of reporting progress that can never complete. [Change email tests](../conformance/goapi/change_email_test.go)

## Deleting an account

Enable `DeleteUserEnabled` to expose `POST /delete-user`. The default flow accepts a fresh session, or the correct current password in the `password` field. With `SendDeleteAccountVerification` configured, the service mails a confirmation link. The link expires after 24 hours by default, configurable through `DeleteTokenTTL`. The `GET /delete-user/callback` request must carry both the token and an active session belonging to that user. Deletion removes the user, accounts, sessions and outstanding core mail-link records.

A deletion link is spent the first time anyone opens it. An expired link, or one opened by another signed-in account, answers 404 `INVALID_TOKEN` without running `BeforeDeleteUser` or any deletion hook, and the owner must request a new one. Opening it without a session answers 404 `FAILED_TO_GET_USER_INFO` and leaves it usable. The callback needs a `token`; an empty one is refused like an unknown one rather than treated as a deletion without a link. With `DeleteUserEnabled` off, every deletion route answers 404 `NOT_FOUND` to any caller. A custom store spends links first by implementing `DeletionTokenStore`; without it, the link is checked while deleting. [Deletion tests](../conformance/goapi/delete_user_test.go)

`BeforeDeleteUser` runs before the deletion with the user and a copy of the request, and an error, such as an `APIError`, cancels it and is returned to the caller. `AfterDeleteUser` runs once the user is gone. Both receive a nil request for a direct Go call. To observe every session and account the deletion removes, use [database hooks](hooks.md#run-code-around-database-writes).

A trusted Go caller can use `SetPassword(ctx, headers, newPassword)` to attach the first password to an account signed in through another provider. The HTTP API does not expose this operation.

## Verify an address with application callbacks

Set `Options.BeforeEmailVerification` and `Options.AfterEmailVerification` independently. Each function receives a context, the stored core user profile, and a request. The profile includes the ID, name, mailbox, verification flag, image, and timestamps. Mounted endpoints pass a private copy of the request URL and headers with an empty body. The verification token is removed from the query string and request URI. Headers can still contain sensitive cookies or authorization credentials. Direct Go calls pass a nil request. An error stops that request. HTTP callers receive a generic server error for a private callback failure.

| Verification | Before | After |
| --- | --- | --- |
| First use of an ordinary verification link | Current unverified profile | Committed verified profile |
| Another visit to a verified address link | Skipped | Skipped |
| Verification with an email code | Current profile, including an already verified profile | Committed verified profile |
| Change by link, previously verified owner | Skipped on both legs | New address after the final confirmation |
| Change by link, previously unverified owner | Skipped | Skipped |
| Change with a new-address code | Current account at its old address | The same account at its new, verified address |

For ordinary links, a before-hook error leaves verification pending and the same link can be retried until expiry. Email verification and change codes are spent before the before hook. A rejected code operation needs a fresh code. An after-hook error leaves the mailbox change committed. Each route waits for the after hook before issuing or refreshing browser credentials. Code-based sign-in and password recovery follow their own callback policies. [Browser compatibility tests](../conformance/email-verification-observers.mjs)

The built-in adapters release locks before calling application code. Simultaneous link requests can both inspect the unverified profile in their before hooks. Use that hook for repeatable checks. Only the request that commits ordinary verification runs the after hook. A process interruption between the commit and the callback can interrupt delivery. An expiring, single-use receipt binds each delayed OTP change or session grant to its original proof, owner and proposed operation. Callback failures discard the corresponding receipt. When granting a session after a callback, Plain Auth rechecks the verified account, session authority and applicable sign-in restrictions. Custom adapters that enable these callbacks implement `EmailVerificationObserverStore` and, when using the email-code plugin, `EmailOTPVerificationObserverStore`. [Storage and concurrency tests](../adapters/sqlstore/email_verification_observers_test.go)
