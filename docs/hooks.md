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

An after hook that turns a successful sign-in into an error should call `c.DeleteSessionCookie()`. It drops the session cookies the response would issue and expires the browser's session cookies instead, so the error response signs nobody in.

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

`Options.DatabaseHooks` and `Plugin.DatabaseHooks` hold `Create`, `Update` and `Delete` hooks for `User`, `Session` and `Account`. Plugin hooks run first, in plugin order, then the Options hooks.

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

To run the before hooks outside the transaction, the Auth runs the store's sign-in twice. A dry run records the user and session it would store and rolls back; the before hooks run on those rows; then the approved run stores them with the hooks' edits. If another request changes the data in between, for example by creating a user with the same email, the Auth starts again and signs in that user instead. A skipped sign-in stores nothing, and a magic link, email code or phone code stays usable.

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
| A new multi-session login of an account already signed in on the browser | Delete, for the older login | The older login stays remembered |
| `POST /multi-session/revoke` | Delete | The login is forgotten by the browser but stays stored |

A delete reads its sessions first, so the hooks see only sessions that existed then. A session created between that read and the delete is removed without hooks. A skip from any before hook cancels the whole delete.

Database hooks do not cover every flow yet. `New` refuses:

- user or session create before hooks with social sign-in, magic link, email OTP, phone number, One Tap, SSO, two-factor, device authorization or `AutoSignInAfterVerification`, when the store does not implement `LoginPlanner`;
- user or session create hooks with the admin plugin;
- user create hooks with passkey or wallet sign-in;
- session create hooks with `AutoSignInAfterVerification`, or the email OTP plugin's, when `BeforeEmailVerification` or `AfterEmailVerification` is set;
- user update hooks with social sign-in, the magic link, email OTP, phone number, One Tap, SSO, admin, two-factor or last-login-method plugin, `AutoSignInAfterVerification`, `BeforeEmailVerification` or `AfterEmailVerification`;
- session update hooks with the organization or admin plugin;
- session delete hooks with the admin, anonymous, magic link, SSO or two-factor plugin, or `RevokeSessionsOnPasswordReset`;
- user delete hooks with the admin or anonymous plugin;
- account hooks with social sign-in, One Tap, SSO, or the admin, wallet, magic link or anonymous plugin, and account create and update hooks with `SendResetPassword`, email OTP or phone number, which write accounts inside the store's transaction.

The SCIM handler refuses a host with any database hook, and `Auth.HasDatabaseHooks` lets your own wrapping handler do the same.

## Errors and panics

Return a `*plainauth.APIError` to choose the status, code and message. Any other error from an endpoint hook, and any panic, ends the request with a generic `500 INTERNAL_SERVER_ERROR`. A panic is logged with its source (`user` or `plugin:<id>`).

## Use the request context

`HookContext` embeds the plugin `EndpointContext`, so a hook has the same helpers as a plugin endpoint:

- `c.Session()` returns the caller's current session, or nil.
- `c.Auth` is the instance, with `Logger`, `PublicURL`, `CallbackURL` and the typed account and session methods.
- `c.Store()` is the configured store.
- `c.RequestMetadata()` is a body-free copy of the request for background work.

Hooks run only for HTTP requests. Direct Go calls such as `Auth.SignUpEmail` run no endpoint hooks; wrap those call sites in your own code.

See the [hook API](../hooks.go), the [middleware API](../middleware.go), the [database hook API](../database_hooks.go), and the tests for [endpoint hooks](../conformance/goapi/endpoint_hooks_test.go), [middleware](../conformance/goapi/plugin_middleware_test.go), [database hooks](../conformance/goapi/database_hooks_test.go) and [database hooks on SQL engines](../adapters/sqlstore/database_hooks_test.go).
