# Hooks

Hooks run your code inside Plain Auth's request handling and writes:

- [Endpoint hooks](#reject-or-rewrite-a-request) run around the mounted HTTP endpoints, so you can adjust one endpoint without writing your own. A before hook can reject a request, rewrite what the endpoint reads, or answer it directly. An after hook can read and replace the endpoint's outcome, read the session it issued and set cookies.
- [Database hooks](#run-code-around-database-writes) run around the writes that create users and sessions, for HTTP requests and Go calls alike.

Set `Options.Hooks` for the application. A plugin sets `Plugin.Hooks` to reuse hooks across applications. Options hooks run first, then each plugin's hooks in plugin order.

## Reject or rewrite a request

```go
opts.Hooks = plainauth.EndpointHooks{
    Before: []plainauth.EndpointHook{{
        Match: func(c *plainauth.HookContext) bool { return c.Path == "/sign-up/email" },
        Run: func(c *plainauth.HookContext) error {
            email, _ := c.Body["email"].(string)
            if !strings.HasSuffix(email, "@example.com") {
                return &plainauth.APIError{Status: 400, Code: "BAD_REQUEST", Message: "Email must end with @example.com"}
            }
            if name, ok := c.Body["name"].(string); ok {
                c.Body["name"] = strings.TrimSpace(name)
            }
            return nil
        },
    }},
}
```

`Match` selects the endpoints a hook runs for; leave it nil to run for every endpoint. `Path` is the route relative to the auth mount, with `:name` segments such as `/reset-password/:token` or `/callback/:id`; `Params` holds their values.

A before hook runs after the request passes disabled paths, rate limits, the origin check and body decoding. Requests rejected by those checks run no hooks.

- **Reject:** return an error. It is written as the response and neither the endpoint nor the after hooks run.
- **Rewrite:** edit `c.Body`, `c.Request.Header` or the query in `c.Request.URL`. `c.Request` is a copy, so the host's request is never changed. The endpoint checks rewritten input like caller input, so a bad value gets `400 VALIDATION_ERROR`, and callback URLs are checked again against the trusted origins.
- **Answer:** call `c.Respond(result)`. The remaining before hooks, the endpoint and the after hooks are skipped. A result is written as JSON unless it is a `plainauth.Redirect`, `HTMLPage`, `XMLDocument` or `EmptyResponse`.

```go
c.Respond(map[string]any{"message": "Hello World"})
c.Respond(plainauth.Redirect("/sign-up/name"))
```

Use `c.Redirect(callback)` instead of a literal `Redirect` when the target comes from the request; it checks the target against the trusted origins.

## Read or replace the outcome

```go
opts.Hooks.After = []plainauth.EndpointHook{{
    Run: func(c *plainauth.HookContext) error {
        switch {
        case strings.HasPrefix(c.Path, "/sign-up"):
            // Send a welcome notification.
        case c.Path == "/sign-in/email" && c.Err != nil:
            // Count a failed sign-in.
        }
        return nil
    },
}}
```

After hooks run once the endpoint returns, before the response is written.

- **`c.Result` and `c.Err`** hold the outcome so far: the endpoint's value or its error, as changed by earlier after hooks. Assign either to replace it.
- **Returned errors:** an `APIError` or `OAuthError` replaces the outcome, and the remaining after hooks still run and see it.
- **Status:** the response uses the final error's status, or the endpoint's success status.
- **`c.ResponseHeader`** holds the headers set so far by the endpoint and earlier hooks, including its `Set-Cookie` lines. Add headers there.

An endpoint error that is not an `APIError` or `OAuthError` ends the request with a 500 before any after hook runs.

## Read the new session

```go
opts.Hooks.After = []plainauth.EndpointHook{{
    Match: func(c *plainauth.HookContext) bool { return strings.HasPrefix(c.Path, "/sign-up") },
    Run: func(c *plainauth.HookContext) error {
        session, err := c.NewSession()
        if err != nil || session == nil {
            return err
        }
        notify("user-register", session.User.Name)
        return nil
    },
}}
```

`c.NewSession()` returns the session whose cookie this response issues, with its user, or nil when it issues none, for example after a failed sign-in or a sign-out.

An after hook that turns a successful sign-in into an error should call `c.DeleteSessionCookie()`. It drops the session cookies, the new session's multi-session cookie and the `Set-Auth-Token` header the response would issue, and expires the browser's session cookies instead, so the error response signs nobody in. [Rejected sign-in tests](../conformance/goapi/delete_session_cookie_test.go)

## Set and read cookies

```go
c.SetCookie(c.Auth.SignedCookie("theme", "dark", 3600))
theme, ok := c.Auth.SignedCookieValue(c.Request, "theme")
```

- `c.Auth.Cookie(name, value, maxAge)` builds a cookie with the instance's prefix and attributes: `Path=/`, `HttpOnly`, `SameSite=Lax`, `Secure` for an HTTPS base URL and the shared domain when cross-subdomain cookies are on. `c.Auth.Cookie("session_token", "", 0).Name` is the session cookie's name.
- `c.Auth.SignedCookie` signs the value with the instance secret, in the same format as the session cookie. `c.Auth.SignedCookieValue` verifies it against the current and previous secrets and reports false for a missing or tampered cookie. Hooks never read the secret itself.
- `c.SetCookie` adds the cookie to the response, and `c.Request.Cookie(name)` reads an unsigned one.

## Hash passwords

`c.Auth.HashPassword(ctx, password)` and `c.Auth.VerifyPasswordHash(ctx, hash, password)` use the instance's `Options.PasswordHash` and `Options.PasswordVerify`, or the built-in scrypt format, within the same limit on concurrent hashing as sign-in.

## Plugin middleware, requests and responses

A plugin has three more extension points, which run only for HTTP requests:

```go
plainauth.Plugin{
    ID: "maintenance",
    Middleware: []plainauth.Middleware{{
        Path: "/organization/**",
        Run: func(c *plainauth.HookContext) error {
            c.Respond(plainauth.HTMLPage("<p>Back soon</p>"))
            return nil
        },
    }},
    OnRequest: func(c plainauth.RequestContext) error {
        c.Request.Header.Set("X-Tenant", tenantFor(c.Request.Host))
        return nil
    },
    OnResponse: func(c *plainauth.ResponseContext) {
        c.Header.Set("X-Request-ID", requestID(c.Request))
    },
}
```

- **`Middleware`** runs before the endpoint hooks for routes whose mount-relative path matches `Path`.
  - In a pattern, `*` or `:name` matches one segment and a final `**` matches the rest, so `/**` matches every route.
  - Broader patterns run first: `/**`, then `/x/**`, then `/x/*`, then exact paths. Within a level they run in plugin order.
  - It can reject, rewrite or answer a request like a before hook.
- **`OnRequest`** runs for every mounted request before routing, after the disabled-path check.
  - Return an error to interrupt the request with that error's response.
  - `c.Request` is a copy the hook may edit; header and query changes reach the endpoint. The route is not resolved again.
  - Use `Middleware` with `/**` to answer with something other than an error.
- **`OnResponse`** runs once for every response to a request that passed `OnRequest`, including errors, unknown routes and rate limits, before anything is written. It may change `c.Status`, `c.Header` and `c.Body`.
  - When any plugin sets `OnResponse`, responses are buffered until the hooks finish.
  - Every plugin's `OnResponse` runs, in plugin order, and each sees the changes of the ones before.

## Run code around database writes

```go
opts.DatabaseHooks.User.Create = plainauth.OperationHooks[plainauth.UserRecord]{
    Before: func(ctx context.Context, u *plainauth.UserRecord, c *plainauth.HookContext) error {
        if strings.HasSuffix(u.Email, "@example.com") {
            u.EmailVerified = true
        }
        u.Fields["plan"] = "free"
        return nil
    },
    After: func(ctx context.Context, u plainauth.UserRecord, c *plainauth.HookContext) error {
        return billing.CreateCustomer(ctx, u.ID, u.Email)
    },
}
```

`Options.DatabaseHooks` and `Plugin.DatabaseHooks` hold `Create`, `Update` and `Delete` hooks for `User`, `Session`, `Account` and `Verification`. Plugin hooks run first, in plugin order, then the Options hooks.

- **Before** runs just before the write. For a create or an update it receives the full row with the change applied, and may change the fields the write stores; changing any other field fails the write with a 500.
  - **Creating a user:** `Name`, `Email`, `Image`, `EmailVerified` and `Fields`, the `UserAdditionalFields` values by name.
  - **Creating a session:** `ExpiresAt`, `IPAddress`, `UserAgent` and `Fields`, the `SessionAdditionalFields` values by name.
  - **Updating a profile:** `Name`, `Image` and `Fields`. **Changing or verifying an email address:** nothing; a hook can only decline.
  - **Refreshing a session:** `ExpiresAt`. **Updating session fields:** `Fields`, limited to the fields a caller may set.
  - Edited values are checked like caller input; defaults for omitted fields apply after the hooks. A create hook may set server-only fields, and never sees a server-only value the caller tried to send.
  - For a delete, Before receives the row about to be removed; edits are ignored.
- **Return from Before** `plainauth.ErrSkipWrite` to cancel the write, an `APIError` to answer with that error, or another error to fail the write.
- **After** receives the stored row, or the removed one. Its error is returned to the caller; the change stays, but a session that has not been delivered yet is removed.
- **`c`** is the endpoint call that caused the write, or nil for a direct Go call such as `Auth.SignUpEmail`.

Hooks never run inside a database transaction, so they may read and write through the Auth and the store. When one operation stores several rows, every before hook runs before anything is written: a sign-up runs the user hooks, then the session hooks, then stores both, then runs the after hooks in the same order. A sign-up with an email that already exists takes the duplicate path without running any hook.

| Operation | User hooks | Session hooks | Skipped user | Skipped session |
| --- | --- | --- | --- | --- |
| `POST /sign-up/email`, `Auth.SignUpEmail` | Create | Create | 400 `FAILED_TO_CREATE_USER` | 400 `FAILED_TO_CREATE_SESSION` |
| Email and username password sign-in | | Create | | 401 `FAILED_TO_CREATE_SESSION` |
| `POST /sign-in/anonymous` | Create | Create | 500 `FAILED_TO_CREATE_USER` | 400 `COULD_NOT_CREATE_SESSION` |
| `POST /change-password` with `revokeOtherSessions` | | Create | | 500 `FAILED_TO_GET_SESSION` |
| Sessions plugins issue with `EndpointContext.IssueSession`, such as passkey and wallet sign-in | | Create | | 401 `FAILED_TO_CREATE_SESSION` |
| `Auth.BootstrapAdmin` | Create | | an error | |
| Browser social sign-in | Create | Create | redirect with `error=unable_to_create_user` | redirect with `error=unable_to_create_session` |
| ID-token social sign-in | Create | Create | 401 `OAUTH_LINK_ERROR` | 401 `OAUTH_LINK_ERROR` |
| `GET /magic-link/verify` | Create | Create | redirect with `error=failed_to_create_user` | redirect with `error=failed_to_create_session` |
| One Tap | Create | Create | 401 `UNAUTHORIZED` | 401 `UNAUTHORIZED` |
| Email codes, including the session after `/email-otp/verify-email` with `AutoSignInAfterVerification`; phone verification; SSO | Create | Create | 500 `FAILED_TO_CREATE_USER` | 500 `FAILED_TO_CREATE_SESSION` |
| Password sign-in with the two-factor plugin, for an account without a second factor or with a trusted device | | Create | | 401 `FAILED_TO_CREATE_SESSION` |
| `/two-factor/verify-totp`, `/verify-otp` and `/verify-backup-code`; `POST /device/token`; the sign-in after an email link with `AutoSignInAfterVerification` | | Create | | 500 `FAILED_TO_CREATE_SESSION` |

### Sign-ins the store decides

From the browser social sign-in row on, the store decides inside its transaction whether the sign-in creates a user and who owns the session. The user hooks run only when it creates one; a returning user runs only the session hooks. The session hooks receive the session with the owner the store chose. A social sign-in that requires a verified email stores the new user without a session, and runs only the user hooks.

To run the before hooks outside the transaction, the Auth runs the store's sign-in twice. A dry run records the user and session it would store and rolls back; the before hooks run on those rows; then the approved run stores them with the hooks' edits. If another request changes the data in between, for example by creating a user with the same email, the Auth starts again and signs in that user instead. A skipped sign-in stores nothing, and a magic link, email code, phone code or two-factor challenge stays usable.

- **Edits:** before hooks may change the user's `Name` and `Image`, and the session as usual. The store chose the email, whether it is verified and the additional fields, which decide how the sign-in continues, so `UserRecord.Fields` is empty and changing any of those fails the sign-in.
- **Errors:** a magic link answers a hook's `APIError` by redirecting to the error callback with its code and message.
- **Stores:** the SQL store supports these plans. The memory store does not, so `New` refuses create before hooks for these sign-ins with it; after hooks still run. A custom store supports them by implementing `plainauth.LoginPlanner` and calling the `LoginPlan` methods in its sign-in methods, as the [SQL store](../adapters/sqlstore/magiclink.go) does.

On sign-up, any other error from a user before hook answers 422 `FAILED_TO_CREATE_USER`. When sign-up hides existing emails, a 403 `APIError` from a user before hook gets the same response as an existing email.

User updates run these hooks:

| Operation | User hooks | Skipped write |
| --- | --- | --- |
| `POST /update-user`, `Auth.UpdateUser` | Update, with the new name, image and fields | Answers success; nothing changes |
| `POST /change-email` for an unverified address with `UpdateEmailWithoutVerification` | Update, with the new email | Answers success; the address stays |
| The email change link from `/change-email` | Update, with the new email | Answers success; the address stays |
| `GET /verify-email`, `Auth.VerifyEmail` for an unverified address | Update, with `EmailVerified` set | Answers success; the address stays unverified |

Deleting an account with `POST /delete-user`, `/delete-user/callback` or `Auth.DeleteUser` runs the session delete hooks for every session of the account, then the user delete hooks, then deletes them together and runs the after hooks in the same order. A skip from any before hook keeps the user and every session, and the request answers like a completed deletion.

Account hooks receive the `LinkedAccount` and may only observe or cancel the write; changing the account fails it with a 500.

| Operation | Account hooks | Skipped write |
| --- | --- | --- |
| `POST /sign-up/email`, `Auth.SignUpEmail` | Create, for the credential account; the after hook receives its stored ID | 400 `FAILED_TO_CREATE_USER`; nothing is stored |
| `Auth.SetPassword` | Create, for the credential account | 400 `FAILED_TO_UPDATE_USER` |
| `POST /change-password`, `Auth.ChangePassword` | Update, for the credential account | 400 `FAILED_TO_UPDATE_USER`; the old password keeps working |
| `POST /reset-password`, `Auth.ResetPassword` | Update for the credential account, or create when the account has none | 400 `FAILED_TO_UPDATE_USER`; the old password keeps working |
| `POST /unlink-account`, `Auth.UnlinkAccount` | Delete | Answers success; the account stays |
| Deleting an account | Delete, for each account, between the session and user hooks | The whole deletion is cancelled |

A declined password change fails rather than answering success, so nobody believes a password changed when it did not.

Session updates and deletes run these hooks:

| Operation | Session hooks | Skipped write |
| --- | --- | --- |
| Sliding refresh on `GET /get-session` | Update, with the new `ExpiresAt` | 401 `FAILED_TO_GET_SESSION`, and the browser's session cookie expires |
| `POST /update-session`, `Auth.UpdateSession` | Update, with the new `Fields` | 401 `FAILED_TO_GET_SESSION`, and the session cookie expires |
| `POST /sign-out`, `Auth.SignOut`, including every remembered multi-session login | Delete | The browser is signed out, but the session stays stored |
| `POST /revoke-session`, `/revoke-sessions`, `/revoke-other-sessions` | Delete, once per session | Every session stays |
| Removing an expired session the browser presents | Delete | The session stays stored |
| `POST /change-password` with `revokeOtherSessions` | Delete, for every session of the account | The password changes, every session stays and no new session is issued |
| A password reset link with `RevokeSessionsOnPasswordReset` | Delete, for every session of the account | The password resets and every session stays |
| A new multi-session login of an account already signed in on the browser | Delete, for the older login | The older login stays remembered |
| `POST /multi-session/revoke` | Delete | The login is forgotten by the browser but stays stored |

A delete reads its sessions first, so the hooks see only sessions that existed then. A session created between that read and the delete is removed without hooks. A skip from any before hook cancels the whole delete.

### Verification hooks

Verification hooks run when a password reset link, an account deletion link, a browser OAuth flow, a magic link, a one-time token, an email or phone code, a two-factor challenge, delivered code or remembered browser, a passkey challenge, a wallet sign-in nonce, an enterprise sign-in's state, a SAML logout binding or logout request, an SSO domain verification token or an OAuth authorization code is created, and when it is spent or removed, which counts as its delete. Renewing a session that carries a SAML logout binding counts as the binding's update. A wrong guess counted against a code or a two-factor challenge counts as its update:

| Operation | Verification hooks | Skipped write |
| --- | --- | --- |
| `POST /request-password-reset`, `Auth.RequestPasswordReset` | Create, `reset-password` | Answers success; nothing is stored or mailed |
| `POST /reset-password`, `Auth.ResetPassword` | Delete, before the account and session hooks | 400 `INVALID_TOKEN`; the link stays usable |
| `POST /delete-user` that mails a link | Create, `delete-account` | Answers "Verification email sent"; nothing is stored or mailed |
| `/delete-user/callback`, or `POST /delete-user` with a token | Delete, before the deletion hooks | 404 `INVALID_TOKEN`; the link stays usable |
| `POST /sign-in/social` and `/link-social` with the database state strategy | Create, `oauth-state` | 500 `STATE_GENERATION_ERROR` |
| `GET /oauth-popup/start` with the database state strategy | Create, `oauth-state` | The popup reports `popup_sign_in_failed` |
| The provider's callback | Delete | `state_mismatch`; the flow stays stored until it expires |
| `POST /sign-in/magic-link` | Create, `magic-link` | Answers `{"status":true}`; nothing is stored or mailed |
| `GET /magic-link/verify` | Delete, before the user and session hooks of the sign-in | Redirects with `INVALID_TOKEN`; the link stays usable |
| `GET /one-time-token/generate`, `Auth.GenerateOneTimeToken`, and the `Set-Ott` header | Create, `one-time-token` | The token is returned but was never stored, so it redeems nothing |
| `POST /one-time-token/verify`, `Auth.VerifyOneTimeToken` | Delete | 400 `Invalid token`; the token stays usable |
| `POST /email-otp/send-verification-otp`, `/email-otp/request-password-reset`, `/forget-password/email-otp`, `Auth.SendEmailOTP`, and the codes sent on sign-up or in place of a verification link | Create, `sign-in-otp`, `email-verification-otp` or `forget-password-otp` | Answers success; nothing is stored or mailed, and an earlier code stays |
| `Auth.CreateEmailOTP` | Create | The code is returned but was never stored, so it proves nothing |
| `POST /email-otp/request-email-change`, `Auth.RequestEmailChangeOTP` | Create, `change-email-otp`; with `VerifyCurrentEmail`, first a guess at the current address's `email-verification-otp` code | Answers success; nothing is stored, mailed or judged |
| A code submitted to `POST /email-otp/check-verification-otp`, `/email-otp/verify-email`, `/sign-in/email-otp`, `/email-otp/reset-password` or `/email-otp/change-email`, or to their `Auth` methods | Delete before every guess; then Delete after when the code is spent or removed, or Update after when a wrong guess is counted | 400 `INVALID_OTP`; nothing compares or counts the guess, and the code stays usable |
| `POST /phone-number/send-otp`, `Auth.SendPhoneNumberOTP`, and the code `POST /sign-in/phone-number` sends to an unverified number | Create, `phone-number-otp` | Answers as sent, or 401 `PHONE_NUMBER_NOT_VERIFIED`; nothing is stored or sent |
| `POST /phone-number/request-password-reset`, `Auth.RequestPhonePasswordReset` | Create, `phone-number-reset`, for any number | Answers `{"status":true}`; nothing is stored or sent |
| A code submitted to `POST /phone-number/verify` or `/phone-number/reset-password`, or to `Auth.VerifyPhoneNumber`, `Auth.ResetPhonePassword` or `Auth.ConsumePhoneNumberOTP` | As for an email code; the delete before hooks run before a custom `VerifyOTP` is asked | As for an email code |
| A password sign-in with the two-factor plugin that asks for a second factor, including a phone code sign-in that needs one, and their `Auth` methods | Create, `2fa` | Answers `twoFactorRedirect` with a challenge cookie that redeems nothing; every proof answers 401 `INVALID_TWO_FACTOR_COOKIE` |
| The same sign-in from a remembered browser | Delete, `trust-device`, for the presented grant, then Create, `trust-device`, for its replacement | The grant and its cookie stay, and the sign-in asks for the second factor instead |
| `POST /two-factor/send-otp` | Create, `2fa-otp`, before the code is sent | Answers `{"status":true}`; nothing is stored or sent, and an earlier code stays |
| A code submitted to `POST /two-factor/verify-totp`, `/two-factor/verify-backup-code` or `/two-factor/verify-otp` during sign-in | Delete before every guess, on the `2fa` challenge; then Delete after when the challenge is spent or a fifth wrong guess removes it, or Update after when a wrong guess is counted | 401 `INVALID_TWO_FACTOR_COOKIE`; nothing compares or counts the guess, and the challenge stays usable |
| A code submitted to `POST /two-factor/verify-otp`, during sign-in or signed in | First the same on the `2fa-otp` code | 400 `OTP_HAS_EXPIRED`; nothing compares or counts the guess, and the code stays usable |
| `trustDevice` on a proof during sign-in | Create, `trust-device`, before the guess is judged | A correct proof signs in without remembering the browser |
| `GET /passkey/generate-register-options`, `/passkey/generate-authenticate-options` | Create, `passkey-registration` or `passkey-authentication` | The options are returned and the challenge cookie expires; nothing was stored, so the ceremony answers 400 `CHALLENGE_NOT_FOUND` |
| `POST /passkey/verify-registration`, `/passkey/verify-authentication` | Delete, before the credential is checked and before `ValidateUserInfo` and the session hooks | 400 `CHALLENGE_NOT_FOUND`; the challenge and its cookie stay usable |
| `POST /siwe/nonce`, `/siwe/get-nonce` | Create, `siwe` | The nonce is returned but never stored, so a message signing it answers 401 `UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE` |
| `POST /siwe/verify` | Delete, before the message's domain, chain, time bounds and signature are checked and before `ValidateUserInfo` and the session hooks | 401 `UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE`; the nonce stays usable |
| `POST /sign-in/sso` with the database state strategy, for OIDC or SAML | Create, `oauth-state` | 500 `STATE_GENERATION_ERROR`, and no state cookie is set |
| `/sso/callback/{providerId}` and `/sso/callback` | Delete, before the provider's answer is checked or its code exchanged | Redirects to the error page with `state_mismatch`; the flow stays stored until it expires |
| A SAML response with `RelayState` at `POST /sso/saml2/sp/acs/{providerId}` | Delete, before the response's signature is checked | 400 `INVALID_OAUTH_STATE`; the flow stays stored until it expires |
| A SAML sign-in with `EnableSingleLogout` whose assertion names one SessionIndex | Create, `saml-logout-session`, after `ValidateUserInfo` and the user and session before hooks | The sign-in succeeds without single logout: `POST /sso/saml2/logout/{providerId}` answers 400, and an IdP logout request does not end the session |
| Renewing a session that carries a SAML logout binding | Update after, `saml-logout-session`, with the new expiry, before the session's update after hooks | No before hook runs; `New` refuses update before hooks with single logout |
| `POST /sso/saml2/logout/{providerId}` | Create, `saml-logout-request`, and Delete, `saml-logout-session`, in one pass | A declined request is never stored: the browser is signed out and sent to the IdP, but its LogoutResponse answers 400 `INVALID_LOGOUT_RESPONSE`. A declined binding stays stored, unusable, until it expires; the session ends anyway |
| The IdP's LogoutResponse at `GET /sso/saml2/sp/slo/{providerId}` | Delete, `saml-logout-request`, after its signature is checked | 400 `INVALID_LOGOUT_RESPONSE`; the request and its cookie stay usable until they expire |
| The IdP's LogoutRequest at `GET /sso/saml2/sp/slo/{providerId}` | Delete, `saml-logout-session`, for every binding it ends, in one pass, after its signature and replay checks | The binding stays stored, unusable; its session still ends |
| `POST /sso/register` with `DomainVerification` | Create, `sso-domain-verification` | The provider is registered as pending and the token returned, but never stored: `POST /sso/verify-domain` answers 404 `NO_PENDING_VERIFICATION` until a new token is requested |
| `POST /sso/request-domain-verification` that issues a new token | Create, `sso-domain-verification` | The token is returned but never stored; an earlier token and the provider's state stay as they were |
| `GET` or `POST /oauth2/authorize` that issues a code, including a resumed sign-in, account selection and `/oauth2/continue`, and an accepting `POST /oauth2/consent` | Create, `authorization-code`, after the client, session and consent checks | The client is sent a code that was never stored, so its exchange answers 400 `invalid_grant`; an accepted consent stays recorded |
| `POST /oauth2/token` with `grant_type=authorization_code` | Delete, after the client, redirect URI, scope, PKCE, user and session checks, before tokens are issued | 400 `invalid_grant` "invalid code"; the code stays usable |

A hook receives a `VerificationRecord` with the record's `ID`, its kind in `Identifier`, the owner in `UserID` and `ExpiresAt`. The owner is a link-social flow's signed-in user, empty for a sign-in, and a one-time token's session owner, empty when that session is gone and the token was stored by another runtime; a magic link proves an address, not an account, so it has none. A magic link's or one-time token's `ID` is derived from its stored key; it cannot redeem the record, but keep it private. The token and the flow's data, such as its PKCE verifier, are never passed in the record, but the endpoint's request in `HookContext` may carry the token it presents, so do not log that request whole. Hooks may observe or cancel the write; changing the record fails it with a 500. An error from an after hook fails the request with that error, never as a declined write, although the record was already stored or spent; the popup start reports it as `popup_sign_in_failed`. They run outside the store's transaction, on a read made just before the record is spent, so two requests racing for one link may both run their before hooks, but only the one that spends it runs the after hooks. A link that is expired or belongs to another account is refused or spent without hooks. For a magic link, the delete before hooks run once, before the sign-in's user and session before hooks, and the after hooks run before theirs; a skipped user or session, or a `ValidateUserInfo` refusal, keeps the link. A magic link spent by closed sign-up, and a one-time token whose session has ended or expired, run their after hooks before the refusal. Some refusals the store makes after the before hooks run no after hooks, although they remove the record: a magic link whose bound account was deleted or gave up the address, or whose address another account has taken since it was mailed, and one-time tokens that another runtime stored twice under one key. When a magic link or an email sign-in code proves an unverified account's address, the reset and deletion links and other records the store removes with the account's unproven access run no hooks. Sweeps of expired records, the links removed with a deleted account and the store's own bookkeeping rows run none, such as used authenticator time steps, application-key enrollments, wallet contact reservations and the wallet nonce history. Email verification and email change links are signed and never stored, so they run none, and only email and phone codes, two-factor challenges and delivered codes run update hooks, for a counted wrong guess, along with SAML logout bindings, whose renewal runs only the update after hooks. `OAuthStateCookie` stores no flow and runs none. A `Set-Ott` token's create hooks run on every session cookie the response publishes, and do not prove the header reached the client. [Verification hook tests](../conformance/goapi/database_verification_hooks_test.go), [magic link and one-time token hooks](../conformance/goapi/database_verification_plugin_hooks_test.go), [verification hooks on SQL engines](../adapters/sqlstore/verification_hooks_test.go)

An email code's record carries its kind in `Identifier`, which is `sign-in-otp`, `email-verification-otp`, `forget-password-otp` or `change-email-otp`, and its stored row's `ID`. Each send stores a new row, including a `reuse` resend, which stores the same code again with its failed attempts. The record never carries the code, its stored form, its attempt count or the address. Only an email change code names an owner: the signed-in user who asked for it. The request in `HookContext` carries the submitted `otp`, so do not log it whole.

Every guess at a live code runs the delete before hooks first, before anything compares the guess, including a guess at `/email-otp/check-verification-otp`. A declined guess is refused with 400 `INVALID_OTP`: nothing compares or counts it, and the code stays as it was. The store then judges only the code those hooks saw. When a new code was sent in between, or another runtime stored the code again, the store leaves that code alone and refuses the guess with `INVALID_OTP`, uncounted. What the store did decides the after hooks:

- the delete after hooks when it spent the code, or removed one that ran out of attempts or expired while the hooks ran;
- the update after hooks, with the same record, when it counted a wrong guess;
- none when it kept the code, as a successful check does.

A count has no before hook, so `New` refuses verification update before hooks with the email OTP, phone number and two-factor plugins. A code that has already expired when the guess arrives is removed without hooks. A code spent by a refusal runs its delete after hooks before the refusal: an unknown account, closed sign-up, invalid registration fields, an address already in use, or an address whose owner changed since the code was sent. A skipped email sign-in, or one `ValidateUserInfo` refuses, keeps its code. In a sign-in, the code's before hooks run once, before `ValidateUserInfo` and the user and session before hooks, and its after hooks run before theirs. A reset runs one guess: its before hooks run before the check that spares a wrong guess the password hashing, and its after hooks run after the reset and before `OnPasswordReset`. When a code's after hook fails after a sign-in, the session is removed; after a reset, the password stays changed and `OnPasswordReset` does not run. With `VerifyCurrentEmail`, an email change request judges the current address's code and stores the new one in one store call: the current code's delete before hooks run first, then the new code's create before hooks, and the current code's after hooks run before the new code's.

A send runs the create before hooks before the store decides whether to keep the code. A declined send answers as sent, with nothing stored or mailed, and an earlier code stays. A send the store withholds, to an address without an account or to a new address another account holds, runs no after hook. A create after hook's error or delay can therefore tell a caller whether an address has an account, so keep those hooks fast and infallible, or hand slow work to the background. Hook errors on the codes sent on sign-up are logged and not returned, and so are those on a code sent in place of a verification link over HTTP. A direct Go call that sends such a code, such as `Auth.SendVerificationEmail` or `Auth.SignInEmail` with `SendVerificationOnSignIn`, returns them, as it returns a sender's error. A send that replaces an earlier code, a send that clears the code of an address that gets no mail, and sweeps of expired codes, including the memory store's sweep on every email send, remove codes without hooks. [Email code hooks](../conformance/goapi/database_verification_code_hooks_test.go), [email code hooks on SQL engines](../adapters/sqlstore/email_code_hooks_test.go), [email code store decisions](../adapters/sqlstore/code_decisions_test.go)

Phone codes run the same hooks. A phone code's record carries `phone-number-otp` or `phone-number-reset` and its stored row's `ID`, and never the code, its attempt count or the number; it names no owner. The request in `HookContext` carries the submitted `code` or `otp`. A guess's delete before hooks run before a custom `VerifyOTP` is asked, so a declined guess never reaches your provider. With hooks or `VerifyOTP` set, the Auth judges the guess once those hooks approve it and commits a failing verdict right away, without the request's cancellation, so a client that goes away cannot keep its guess from being counted. A declined guess at a live code that has no attempts left answers `INVALID_OTP`. A code spent by a refused sign-up or link runs its delete after hooks before the refusal: a link without a session, a number someone else holds, a `ValidateUserInfo` refusal, invalid registration fields, or an owner that changed since the code was sent. A reset of a number no one holds spends its code the same way. A reset request stores a code for every number, so its create hooks run for unknown numbers too and reveal nothing. A declined send stores and texts nothing. An administrator's phone number change revokes the codes of the old and new numbers without hooks. [Phone code hooks](../conformance/goapi/database_verification_code_hooks_test.go), [phone code hooks on SQL engines](../adapters/sqlstore/phone_code_hooks_test.go)

Two-factor sign-in runs them too. A sign-in challenge's record carries `2fa`, a delivered code's `2fa-otp` and a remembered browser's `trust-device`, each with its stored row's `ID`, the account in `UserID` and `ExpiresAt`. None carries the challenge or grant key, the code, its stored form or an attempt count; a challenge's attempt counter is part of its record. The request in `HookContext` carries the `two_factor` and `trust_device` cookies and the submitted `code`, and a sign-in's carries the password, so do not log it whole.

A two-factor call decides inside the store's transaction. When a record's before hooks have yet to run, the call stops before it writes or compares anything, runs those hooks outside the transaction and runs again, bound to the records they saw; a call with nothing to ask, such as the sign-in of an account without a second factor, runs once. Every guess during sign-in runs the challenge's delete before hooks before anything compares it, and `/two-factor/verify-otp` first runs the delivered code's. A guess the account refuses anyway, at a locked account, for a method it lacks or for a code still being sent, runs none, and neither does a challenge or code that has already expired, which is refused or removed without hooks. A declined guess is refused uncompared and uncounted, with 401 `INVALID_TWO_FACTOR_COOKIE` for the challenge and 400 `OTP_HAS_EXPIRED` for the code, and both stay usable. A code sent again while the hooks ran is left alone, and the guess is refused with 400 `OTP_HAS_EXPIRED`, uncounted. After the change commits, the delete after hooks run for a challenge that a correct proof, `disableSession` or a fifth wrong guess spends, and for a code that is spent, runs out, expires while its hooks ran, or goes with its challenge; the update after hooks run, with the same record, for a counted wrong guess.

A sign-in that asks for the second factor runs the challenge's create hooks; a declined challenge is answered with a challenge cookie that redeems nothing. A sign-in from a remembered browser runs the delete hooks of the presented grant and the create hooks of its replacement; when either is declined, the grant and its cookie stay and the sign-in asks for the second factor. A proof with `trustDevice` runs the new grant's create before hooks before the guess is judged, so they also run for a wrong guess, and a declined grant signs in without remembering the browser. A send runs the code's create before hooks before the code is drawn, and its create after hooks once the code is stored and before your `Send` is called. Each record's before hooks run before the session's, at most once per request, and its after hooks run before the session's; a failed after hook removes a session that was not delivered. When another request changes the account meanwhile, for example a second sign-in from the same remembered browser, the call runs the hooks of the records its new outcome needs, and a sign-in that starts again runs the session before hooks again; records the first outcome approved then run no after hooks. A phone code sign-in that needs a second factor spends the phone code, with its after hooks, before the challenge's hooks run, so a declined challenge leaves that code spent.

These run no hooks: a delivered code that a new send replaces, or that is removed because `Send` failed or the code expired while it was sent; activating a code once it is sent; a delivered code removed with its challenge when an authenticator or backup code completes the sign-in or the challenge runs out; the challenges, codes and remembered browsers an account loses together when two-factor is enabled, activated, disabled or imported, when its password is changed, reset or set by an administrator, when an administrator revokes its sessions, when it is deleted, or when a magic link or email code proves an unverified account; and expired grants a new grant sweeps. Disabling the factor removes every remembered browser of the account, not only the current one. A challenge stays stored when its create after hook fails, and challenges are not swept. [Two-factor hooks on SQL engines](../adapters/sqlstore/twofactor_hooks_test.go), [two-factor hook outcomes](../twofactor_hooks_test.go)

A passkey challenge's record carries `passkey-registration` or `passkey-authentication` and an `ID` derived from its stored key, the row ID the SQL store gives it. It names the signed-in user it is for; a first-use registration's, whose account may not exist yet, and a signed-out sign-in's name none. It never carries the WebAuthn challenge, the ceremony's user data or the cookie's value, but the request in `HookContext` carries the signed challenge cookie, so do not log it whole. A verification spends the challenge first: its delete hooks run before the credential is checked and before `ValidateUserInfo` and the session hooks, so unlike a magic link or a code, a refusal, a skipped session or a failed check leaves it spent. A declined spend answers as an unknown challenge and keeps it and its cookie usable. A declined challenge returns its options with the challenge cookie expired. A cookie from the other ceremony and an expired challenge are refused without hooks, and expired challenges are swept without hooks. The options endpoints are public, so their create hooks run for anonymous callers; keep them fast. [Passkey hooks on SQL engines](../adapters/sqlstore/passkey_hooks_test.go)

A wallet nonce's record carries `siwe` and an `ID` derived from the nonce, also the SQL row ID, and names no owner: a nonce is bound to no wallet until a signed message redeems it. It never carries the nonce, but the request in `HookContext` carries the signed message, its signature and any email. Keep the `ID` private too, because a custom `GetNonce` with little entropy makes a nonce guessable from it. A verification spends the nonce first, as a passkey verification spends its challenge, so a refusal, a skipped session or a bad signature leaves it spent, and a declined spend answers as an unknown nonce and keeps it usable. A declined nonce is returned but never stored; a custom `GetNonce` value still enters the nonce history, so the generator cannot issue it again. An expired nonce is refused without hooks, a nonce another runtime stored twice is removed and refused without hooks, and expired nonces are swept without hooks. Contact email reservations and the nonce history are store bookkeeping and run none. The nonce endpoints are public, so keep their create hooks fast. [Wallet nonce hooks on SQL engines](../adapters/sqlstore/siwe_hooks_test.go)

An enterprise sign-in keeps its state in an `oauth-state` record, as a social sign-in does, with no owner. Its `ID` is the state the identity provider returns, as `state` or as the SAML `RelayState`, so the provider sees it; it redeems nothing without the browser's `sso_state` or `saml_state` cookie, but keep it private. A SAML sign-in's one record also carries its authentication request, so the sign-in runs one create and one delete. The callback and the SAML endpoint spend the record first, so an identity provider's error and a response with a bad signature still spend it, but only when the browser's state cookie came with them. A state without that cookie runs no hooks, and neither does an IdP-initiated response, which has no state. An after hook's error is answered as JSON. The assertion receipt that stops a replay is store bookkeeping and runs none. [Enterprise sign-in hooks on SQL engines](../adapters/sqlstore/sso_hooks_test.go), [SAML state hooks](../adapters/sqlstore/sso_saml_test.go)

With `SAMLOptions.EnableSingleLogout`, a SAML sign-in stores a `saml-logout-session` binding between its session and the IdP session. Its record carries the stored row's `ID`, the session's user in `UserID` and the session's expiry, including an expiry a session create hook set. It never carries the NameID, SessionIndex or session token. The sign-in writes it with the session, so its create before hooks run after `ValidateUserInfo` and the user and session before hooks, once even when the sign-in is planned, and its after hooks run after theirs. A failed binding hook fails the sign-in and removes the session that was not delivered. Renewing the session runs the binding's update after hooks with the new expiry. A declined renewal would let the binding expire before its session, so `New` refuses update before hooks with single logout.

`POST /sso/saml2/logout/{providerId}` runs, in one pass, the create before hooks of a `saml-logout-request`, which names no owner, and the binding's delete before hooks; their after hooks run in the same order once the logout commits. The IdP's LogoutResponse spends the request after its signature is checked. An IdP LogoutRequest runs the delete hooks of every binding it ends, after its signature and replay checks. These calls decide inside the store's transaction, so each stops before it writes, runs the hooks outside and runs again bound to what they saw; a record another request changed meanwhile is asked about again. The request in `HookContext` carries the SAML response, LogoutRequest or LogoutResponse, with the NameID, SessionIndex and RelayState, so do not log it whole. These run no hooks: the LogoutRequest replay receipt; sweeps of expired bindings and requests; a binding left behind when its session ends by sign-out, revocation or account deletion, which stays unusable until it expires. [SAML logout hooks on SQL engines](../adapters/sqlstore/sso_saml_hooks_test.go)

With `DomainVerification`, a new domain token's record carries `sso-domain-verification`, its row `ID` and its seven-day expiry. It proves a domain rather than an account, so it names no owner, and it never carries the token or its DNS name. Returning a live token runs none, and verification only reads it. The store decides the token inside its transaction, so a before hook does not see the provider a registration is storing. These run no hooks: a reissue's replacement of an earlier token; the token's removal when the SAML metadata changes or the provider or its creator is deleted; the domain proof and namespace rows, which are store bookkeeping. The request to `/sso/register` carries an OpenID Connect client secret, so do not log it whole. [SSO domain hooks on SQL engines](../adapters/sqlstore/sso_hooks_test.go)

An authorization code's record carries `authorization-code`, the stored row's `ID`, the user who approved it and its expiry. It never carries the code, its stored identifier or the authorization request's state, nonce, PKCE challenge, login hint or claims. The create hooks run once the store has checked the client, the session and consent, so a request that opens the consent page or is refused runs none, and a declined code at consent still records the consent and spends the prompt. The exchange's delete before hooks run after its client, redirect URI, scope, PKCE, user and session checks, before an ID token is signed or a refresh token drawn, and once even when the exchange does both. Its after hooks run once the code is spent and the tokens stored. When a delete after hook fails, the exchange fails with its error, and the stored tokens, which were never returned, are removed as for a replay. A refused exchange and an expired code run none. Two exchanges racing for one code may both run their before hooks; only the one that spends it runs the after hooks, and the other is answered as a replay, which removes the tokens linked to the code. The store decides each code inside its transaction, so the call stops before it writes, the hooks run outside, and the call runs again bound to the record they saw; a before hook therefore sees none of that call's rows, such as a consent it is recording. The request in `HookContext` carries the authorization request, or the code, verifier and client credentials, so do not log it whole. Consent prompts and DPoP proof reservations are store bookkeeping and run none. [OAuth code hooks on SQL engines](../adapters/sqlstore/oauth_code_hooks_test.go)

A plugin in its own package runs these hooks for the records it keeps with `EndpointContext.CreateVerification` and `EndpointContext.SpendVerification`, and sets `Plugin.ValidateVerificationStore` so that `New` refuses hooks its store cannot follow, such as delete hooks on a store that cannot read a record before spending it. Every hook sees the record the plugin builds, so give it a kind, a row ID or one derived from the stored key, an owner and an expiry, and never the token, code, nonce or challenge. [Plugin verification hooks](../conformance/goapi/database_verification_plugin_api_test.go)

A plugin whose store decides a record inside its own transaction makes the store call with `EndpointContext.GateVerifications` instead. The store asks `plainauth.VerificationGateFrom(ctx)` with `Create`, `Update` or `Delete` after every check that could refuse the call and just before each write, asks about all of the call's records before it stops, returns `plainauth.ErrVerificationPending` unchanged and commits nothing when told to stop, and dates new records from the gate's `Now`. The call runs again once the before hooks have run outside the transaction, and writes only the records they approved; a declined record is left as it was while the call commits the rest. The after hooks run once the call commits, in the order the store asked. A store that commits while a record awaits its hooks fails the request. [Store-decided verification hooks](../conformance/goapi/database_verification_gate_test.go)

Database hooks do not cover every flow yet. `New` refuses:

- user or session create before hooks with social sign-in, magic link, email OTP, phone number, One Tap, SSO, two-factor, device authorization or `AutoSignInAfterVerification`, when the store does not implement `LoginPlanner`;
- user or session create hooks with the admin plugin;
- user create hooks with passkey or wallet sign-in;
- session create hooks with `AutoSignInAfterVerification`, or the email OTP plugin's, when `BeforeEmailVerification` or `AfterEmailVerification` is set;
- user update hooks with social sign-in, the magic link, email OTP, phone number, One Tap, SSO, admin, two-factor or last-login-method plugin, `AutoSignInAfterVerification`, `BeforeEmailVerification` or `AfterEmailVerification`;
- session update hooks with the organization or admin plugin;
- session delete hooks with the admin, anonymous, magic link, email OTP, SSO or two-factor plugin, or with `RevokeSessionsOnPasswordReset` and the phone number plugin, whose code resets find the account inside the store. A magic link or email sign-in code that proves an unverified account's address removes its sessions inside the store;
- user delete hooks with the admin or anonymous plugin;
- account hooks with social sign-in, One Tap, SSO, or the admin, wallet, magic link, email OTP or anonymous plugin, and account create and update hooks with phone number, which write accounts inside the store's transaction;
- any verification hook with SAML single logout or SSO domain verification on a store that does not implement `sso.VerificationGater`, any verification hook with the two-factor plugin on a store that does not implement `FactorRecordReporter`, and any verification hook with the OAuth provider's authorization code grant on a store that does not implement `oauthprovider.AuthorizationCodeGater`;
- verification update before hooks with the email OTP, phone number or two-factor plugin, which count a wrong guess as they judge it, or with SAML single logout, whose session renewal extends the logout binding inside the store. Use the delete before hooks, which run before every guess, and the update after hooks;
- verification delete hooks with `DeleteUserEnabled` on a store without `DeletionTokenFinder`, with the database OAuth state on a store without `OAuthFlowFinder`, with the magic link plugin on a store without `MagicLinkFinder`, or with the one-time token plugin on a store without `OneTimeTokenFinder`, verification update and delete hooks with the email OTP plugin on a store without `EmailOTPFinder`, or with the phone number plugin on a store without `PhoneOTPReporter`, verification delete hooks with the passkey plugin on a store without `passkey.ChallengeFinder` or with the wallet plugin on a store without `siwe.NonceFinder`, and verification create before hooks with a wallet `GetNonce` on a store without `siwe.NonceHistoryStore`. The SQL stores implement all of these; the memory store keeps no OAuth flows, passkeys, wallets, SSO providers or OAuth codes and implements the other five.

The SCIM handler refuses a host with any database hook, and `Auth.HasDatabaseHooks` lets your own wrapping handler do the same.

## Decide which users to admit

`Options.ValidateUserInfo` is one gate for every way a user arrives. It runs before a user is created, outside any store transaction and before the user create database hooks:

```go
opts.ValidateUserInfo = func(ctx context.Context, v plainauth.UserInfoValidation) error {
    if !strings.HasSuffix(v.User.Email, "@company.example") {
        return &plainauth.APIError{Code: "email_not_allowed", Message: "Only company emails are allowed"}
    }
    return nil
}
```

`v.Action` is `create-user` before a user is stored, `link-account` before a provider identity joins an existing user, through `/link-social` or a sign-in that links by email, and `sign-in` before an existing user signs in again through a provider. `v.Method` names the way in: `email-password`, `oauth`, `sso-oidc`, `sso-saml`, `magic-link`, `email-otp`, `phone-number`, `anonymous`, `siwe`, `passkey`, `scim`, or `admin` for `POST /admin/create-user`, `Auth.AdminCreateUser` and `Auth.BootstrapAdmin`. For `oauth` and the SSO methods, `v.Provider` is the provider ID and `v.Profile` its raw profile or SAML attributes, and `v.User` carries the provider's fresh name, email and image, with the existing user's ID for a link or a sign-in. Otherwise `v.User` holds the user about to be stored and its additional-field input. `v.Request` is a copy of the request without its body, or nil for a direct Go call. A returning magic-link or email-code user is not checked again.

Return nil to admit the user. A returned `*plainauth.APIError` refuses it with a 403 carrying its code and message, and a browser sign-in or link returns to its error callback, or the error page, with `error` and `error_description`. The message is sent to the client, so keep details out of it. Any other error, an `APIError` without a code, or a panic refuses with `403 validation_failed`. When `RequireEmailVerification` or `DisableAutoSignIn` keeps sign-ups private, a refused email sign-up answers like an existing email.

Social and SSO sign-ins, One Tap, magic links and email codes decide inside the store's transaction whether to create the user, so the gate runs between a dry run and the real sign-in, as the create before hooks do, and needs a store implementing `plainauth.LoginPlanner`. A refused magic link, email code or ID token is not spent. Behind the OAuth proxy, the production instance carries the raw profile to the preview. JSON numbers in `v.Profile` are `json.Number` on every path.

Plugins and wrapping handlers that create users themselves can run the same gate with `Auth.ValidateUserInfo`. An administrator's new user is checked after the actor's permission and the email are, and a new wallet user is checked with the email it gets: the held contact, or the wallet email when the contact is no longer free. The SCIM handler checks every user a directory creates with `POST /scim/v2/Users`, also one that POST reactivates or links again, and answers a refusal with a SCIM 403 whose detail is the message. `PUT` and `PATCH` updates are not checked. A refused phone sign-up spends its code. [Gate tests](../conformance/goapi/user_validation_test.go)

## Errors and panics

Return a `*plainauth.APIError` to choose the status, code and message. Any other error from an endpoint hook, and any panic, ends the request with a generic `500 INTERNAL_SERVER_ERROR`. A panic is logged with its source (`user` or `plugin:<id>`).

## Use the request context

`HookContext` embeds the plugin `EndpointContext`, so a hook has the same helpers as a plugin endpoint:

- `c.Session()` returns the caller's current session, or nil.
- `c.CallbackURL`, `c.PublicURL`, `c.ErrorPageURL` and `c.Redirect` resolve URLs for this request, with the origins `TrustedOriginsForRequest` adds and the host `DynamicBaseURL` resolves. `c.RequestOrigin` returns the origin of the host the request reached, which may not be allowed.
- `c.Auth` is the instance, with `Logger`, `RunInBackground`, `RunInBackgroundOrAwait` and the typed account and session methods. Its `PublicURL` and `CallbackURL` use the static configuration, which is the fallback with `DynamicBaseURL`.
- `c.Store()` is the configured store.
- On `"/callback/:id"`, `plainauth.OAuthAdditionalData(c.Request.Context())` returns the [`additionalData`](social.md#pass-application-data-through-the-flow) the browser sent when it started the flow.
- `c.RequestMetadata()` is a body-free copy of the request for background work. Bind it to the task's context with `WithContext`, since the request's own context ends with the response.

Hooks run only for HTTP requests. Direct Go calls such as `Auth.SignUpEmail` run no endpoint hooks; wrap those call sites in your own code.

See the [hook API](../hooks.go), the [middleware API](../middleware.go), the [database hook API](../database_hooks.go), and the tests for [endpoint hooks](../conformance/goapi/endpoint_hooks_test.go), [middleware](../conformance/goapi/plugin_middleware_test.go), [database hooks](../conformance/goapi/database_hooks_test.go) and [database hooks on SQL engines](../adapters/sqlstore/database_hooks_test.go).
