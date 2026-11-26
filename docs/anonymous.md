# Guest sessions

Let a visitor start a session before they have an account. Their user has a unique ID and an `isAnonymous` flag. Store guest-owned data against that ID so it can follow the visitor after they sign in.

Select the `anonymous` SQL schema profile and register `anonymous.New`. The in-memory store also supports guest sessions.

```go
guest, err := anonymous.New(anonymous.Options{})
if err != nil {
    return err
}
options.Plugins = append(options.Plugins, guest)
```

| Operation | HTTP route relative to the auth mount | Go client |
| --- | --- | --- |
| Start a guest session | `POST /sign-in/anonymous` | `SignInAnonymous(ctx)` |
| Inspect the current guest | `GET /get-session` | `GetSession(ctx)` |
| Revoke the current login | `POST /sign-out` | `SignOut(ctx)` |
| Remove the current guest and their sessions | `POST /delete-anonymous-user` | `DeleteAnonymousUser(ctx)` |

The default profile name is `Anonymous`. Guest email addresses use the reserved `anonymous.placeholder.invalid` domain. Guests have no password or provider credentials. `GenerateName` can derive a display name from the initiating request. `EmailDomainName` sets a custom domain. `GenerateRandomEmail` can supply a valid unique address; it takes precedence over `EmailDomainName`, which then applies only when the generator returns an empty string. The user controls neither the guest flag nor the identity to delete. A second guest sign-in on an active guest session returns an error.

Each refusal carries a code and message, for example 400 `DELETE_ANONYMOUS_USER_DISABLED` or 403 `USER_IS_NOT_ANONYMOUS`. If the store cannot delete the guest, `POST /delete-anonymous-user` answers 500 `FAILED_TO_DELETE_ANONYMOUS_USER`, keeps the guest signed in and passes the store's error to `OnAPIError`. The store removes a guest's sessions and user together, so the route never answers a separate code for sessions deleted ahead of the user. [Guest error tests](../client/anonymous_test.go)

## Transfer a guest's data

`OnLinkAccount` receives both authenticated user/session pairs and the HTTP request. The callback runs after the permanent identity has authenticated. It can move application records from the guest ID to the permanent user ID. The default removes the guest and their sessions after the callback succeeds.

For SQL stores, the callback receives the transaction that performs guest cleanup. Use `event.Tx` for writes that must commit with the transfer. The example uses PostgreSQL placeholders.

```go
guest, err := anonymous.New(anonymous.Options{
    OnLinkAccount: func(ctx context.Context, event anonymous.Link) error {
        _, err := event.Tx.ExecContext(ctx,
            "UPDATE cart SET user_id = $1 WHERE user_id = $2",
            event.NewUser.User.ID, event.AnonymousUser.User.ID)
        return err
    },
})
```

Returning an error rolls back SQL callback writes and guest cleanup. The handler revokes the unused permanent session and keeps the guest's browser session during an ordinary sign-in. A permanent account already created during sign-up can sign in again to retry the transfer. A second-factor challenge temporarily clears the primary cookie while it waits for verification. Queue external delivery in the same SQL transaction if it must follow the commit. Memory callbacks run with the store locked and receive a nil `Tx`. Keep those callbacks independent of the same store.

Guest handoff runs when a new authenticated session is issued through email/password, email OTP, magic links, phone codes and phone passwords, Google One Tap, passkeys and social login. A phone verification sent with `disableSession` or `updatePhoneNumber` issues no new session and keeps the guest signed in. A pending password/MFA challenge carries a protected guest reference until verification. Signing out during that challenge revokes the guest proof. An OAuth redirect may return without the guest's primary cookie. Its server-side state carries a protected reference, and the callback rechecks the original live session before transfer.

`DisableDeleteAnonymousUser` keeps the guest's user and sessions after handoff and disables explicit guest deletion. Concurrent upgrades of a retained guest can transfer its application data only once. Ordinary sign-out preserves the guest record while revoking its session. A removed or revoked guest session cannot authorize a subsequent transfer.

The [SQL contract tests](../adapters/sqlstore/anonymous_test.go) cover transactional handoff, callback failure, retention, account deletion and second-factor completion. The [feature checklist](parity/plugins/anonymous.md) tracks supported options.
