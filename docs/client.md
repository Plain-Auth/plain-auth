# Go HTTP client

Create one client per user session. An origin uses the default `/api/auth` mount. To use a custom mount, supply its full URL. The client keeps the session cookies returned by the auth server and sends them on subsequent requests.

```go
import (
    "context"

    "github.com/Plain-Org/plain-auth"
    "github.com/Plain-Org/plain-auth/client"
)

func login(ctx context.Context, endpoint, email, password string) (*plainauth.SessionResult, error) {
    c, err := client.New(endpoint, nil)
    if err != nil {
        return nil, err
    }
    result, err := c.SignInEmail(ctx, client.SignInRequest{Email: email, Password: password})
    if err != nil {
        return nil, err
    }
    if result.TwoFactorRedirect {
        code, err := readAuthenticatorCode() // application UI
        if err != nil {
            return nil, err
        }
        if _, err := c.VerifyTOTP(ctx, code); err != nil {
            return nil, err
        }
    }
    return c.GetSession(ctx)
}
```

`GetSession` returns `nil, nil` when the caller has no active session. A signed-in guest has a session and an `isAnonymous` user field. Typed methods also cover email signup, listing sessions, revoking one session, revoking other sessions, revoking all sessions and signing out. When an endpoint returns an HTTP error, `errors.As` exposes the numeric status along with the server’s error code and message. Caller cancellation passes through the supplied context.

Use `c.Do(ctx, method, route, input, output)` for JSON plugin and account endpoints. Routes begin with a slash and are relative to the auth mount. Pass a Go struct or map as input and a pointer to decode the response, or use `nil` for either argument.

To configure timeouts, transport or persistent cookie storage, pass an `*http.Client` as the second argument to `client.New`. Clients get separate in-memory cookies by default. A supplied jar is shared with its owner. Redirects require an explicit same-origin redirect policy. The client retains the server's JSON redirect flag and callback URL for the application to handle.

## Read an application-defined session

If your server configures a custom session view, pass a Go type matching its JSON fields. The same client sends its existing cookies and accepts any renewal cookies.

```go
type SessionView struct {
    Viewer string `json:"viewer"`
}
view, err := client.GetSessionView[SessionView](ctx, c)
if err != nil {
    return err
}
if view != nil {
    fmt.Println(view.Viewer)
}
```

Pass `client.SessionReadOptions{DisableRefresh: true}` to `client.GetSessionViewWithOptions[T](ctx, c, options)` to read the view without extending the session. `DisableCookieCache` requests a fresh store read from a server that supports a browser data cache. False flags are omitted from the query. [Go query-control tests](../client/session_view_test.go)

An unauthenticated read returns `nil, nil`. A failed HTTP request or a response that cannot decode into the requested type returns an error. If the server also projects remembered accounts, use `client.ListDeviceSessionViews[SessionView](ctx, c)`. The default device list returns standard sessions through `c.ListDeviceSessions(ctx)`. [Custom session server setup](plugins.md#return-an-application-defined-session-view) · [Go client tests](../client/session_view_test.go)

## Use a bearer token

Register `bearer.New(bearer.Options{RequireSignature: true})` on the server. On the client, capture the signed credential from the successful login response. If the account uses MFA, capture it from the successful verification response after completing the challenge.

```go
var login client.EmailResult
headers, err := browser.DoWithHeaders(ctx, "POST", "/sign-in/email",
    client.SignInRequest{Email: email, Password: password}, &login)
if err != nil {
    return err
}
if login.TwoFactorRedirect {
    code, err := readAuthenticatorCode() // application UI for an enrolled authenticator
    if err != nil {
        return err
    }
    headers, err = browser.DoWithHeaders(ctx, "POST", "/two-factor/verify-totp",
        map[string]string{"code": code}, nil)
    if err != nil {
        return err
    }
}
device, err := browser.WithBearerToken(headers.Get("Set-Auth-Token"))
if err != nil {
    return err
}
session, err := device.GetSession(ctx)
```

The returned client sends `Authorization: Bearer <token>` to the configured origin and uses no cookies. Reuse it for a device, or create a view for a single request. The original client keeps its own login. Sign-out revokes the bearer session. An ordinary Go HTTP request to your service can send the same Authorization header. Treat the token as a secret. [TLS client test](../client/bearer_test.go)

## Select the endpoint from the environment

`client.New("", nil)` reads the public auth URL from `AUTH_URL`. Set it to `https://app.example.org` for the default `/api/auth` mount, or include a path such as `https://app.example.org/login` for a custom mount. An explicit constructor URL takes precedence. The destination is fixed at construction. [Environment configuration](environment.md#native-client-url)

## Account and credential methods

| Workflow | Client methods |
| --- | --- |
| Register or change a username and sign in | `SignUpEmail`, `SignInUsername`, `IsUsernameAvailable`, `UpdateUser` |
| Edit the profile or email | `UpdateUser`, `ChangeEmail`, `SendVerificationEmail`, `VerifyEmail` |
| Change a password or recover an account | `VerifyPassword`, `ChangePassword`, `RequestPasswordReset`, `ResetPassword` |
| Inspect linked identities or delete the account | `ListAccounts`, `UnlinkAccount`, `DeleteAccount` |
| Enroll an authenticator and replace recovery codes | `EnableTOTP`, `TOTPURI`, `VerifyTOTP`, `GenerateBackupCodes`, `DisableTOTP` |
| Create or delete a guest identity | `SignInAnonymous`, `DeleteAnonymousUser` |
| Request and poll for a device session | `RequestDeviceCode`, `PollDeviceToken` |
| Review and decide a device request | `VerifyDeviceCode`, `ApproveDeviceCode`, `DenyDeviceCode` |
| Complete sign-in with a recovery code | `VerifyBackupCode` |
| Administer accounts and sessions | `AdminCreateUser`, `AdminSetRole`, `AdminListUsers`, `AdminBanUser`, `AdminRevokeUserSessions`, `AdminImpersonate` and [other administrative methods](admin.md) |
| Manage teams, seats and active selections | `CreateTeam`, `UpdateTeam`, `RemoveTeam`, `ListOrganizationTeams`, `ListUserTeams`, `SetActiveTeam`, `ListTeamMembers`, `AddTeamMember`, `RemoveTeamMember` |

Use the same client for sign-in and second-factor verification so the challenge cookie reaches the verification handler. The [native client integration test](../client/account_test.go) exercises these methods through the mounted API, including recovery, email changes, and account deletion.
