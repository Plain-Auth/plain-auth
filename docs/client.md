# Go HTTP client

Create one client per user session. An origin uses the default `/api/auth` mount. To use a custom mount, supply its full URL. The client keeps the session cookies returned by the auth server and sends them on subsequent requests.

```go
import (
    "context"

    "github.com/Stonewrit/stonewrit-auth"
    "github.com/Stonewrit/stonewrit-auth/client"
)

func login(ctx context.Context, endpoint, email, password string) (*stonewrit.SessionResult, error) {
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

## Select the endpoint from the environment

`client.New("", nil)` reads the public auth URL from `AUTH_URL`. Set it to `https://app.example.org` for the default `/api/auth` mount, or include a path such as `https://app.example.org/login` for a custom mount. An explicit constructor URL takes precedence. The destination is fixed at construction. [Environment configuration](environment.md#native-client-url)

## Account and credential methods

| Workflow | Client methods |
| --- | --- |
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
