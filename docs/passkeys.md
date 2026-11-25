# Passkeys

A passkey gives a user a public-key credential for a relying party. By default, registration requires a fresh owner session. An application can explicitly enable first-use registration. On the next visit, the browser can discover the credential and sign the server’s challenge to establish a new session.

Enable the `passkey` schema and choose the exact browser origins allowed to use the relying party.

```go
ddl, err := schema.Generate("sqlite", []string{"passkey"})
if err != nil {
    return err
}
store, err := sqlstore.OpenWithSchema(ctx, "sqlite", "auth.db", ddl)
if err != nil {
    return err
}
defer store.Close()

keys, err := passkey.New(passkey.Options{
    RPID: "example.com",
    RPName: "Example",
    Origins: []string{"https://accounts.example.com"},
    RequireUserVerification: true,
})
if err != nil {
    return err
}
auth, err := plainauth.New(plainauth.Options{
    Store: store, BaseURL: "https://accounts.example.com", Secret: secret,
    Plugins: []plainauth.Plugin{keys},
})
```

Use an HTTPS browser origin. Local development supports HTTP on localhost. Use a domain name as the RP ID. If the UI and API use different origins, include the browser origin in the auth server’s trusted origins and in the passkey origins. Set the relying-party ID before enrolling keys. Changing it creates a different credential namespace.

## Register and sign in

All paths below are relative to the auth mount. Keep browser cookies on both requests in each ceremony.

| Operation | Request | Result |
| --- | --- | --- |
| Begin registration | GET `/passkey/generate-register-options` | Public-key creation options for the signed-in account or the provisional identity supplied by a first-use resolver, including registered credentials to exclude |
| Finish registration | POST `/passkey/verify-registration` with `response`, optional `name` and optional `createSession` | The stored credential and, if requested, its new user session |
| Begin login | GET `/passkey/generate-authenticate-options` | Public-key request options for discoverable login |
| Finish login | POST `/passkey/verify-authentication` with `response` | The authenticated user and session, plus a session cookie |
| List keys | GET `/passkey/list-user-passkeys` | The current user's credentials |
| Rename a key | POST `/passkey/update-passkey` with `id` and `name` | The updated `passkey` |
| Remove a key | POST `/passkey/delete-passkey` with `id` | A `status` confirmation |

In a browser, convert the JSON options into WebAuthn options and pass them to `navigator.credentials.create` or `navigator.credentials.get`. Send the resulting credential’s JSON representation as `response`. Rename and remove use the stored row’s `id`. The browser uses the separate `credentialID`. [WebAuthn API](https://www.w3.org/TR/webauthn-3/)

The signed HTTP-only challenge cookie and server-side verification record expire after five minutes by default. Each challenge permits one verification attempt. Signed-in registration binds the challenge to the requesting account and session. First-use registration saves the enrollment context and the identity returned by the resolver with the challenge. The verifier checks the RP ID, browser origin, user-presence flag and assertion signature. `RequireUserVerification` additionally requires authenticator user verification. The SQL store commits the counter adjustment and new session together. Authenticators with a positive counter must advance it. Authenticator counters that stay at zero are supported.

The optional `ChallengeLifetime` accepts a Go duration. Key management operates on the signed-in user's rows. Deleting the account removes its keys. SQLite, PostgreSQL and MySQL have local software-authenticator tests for this lifecycle.

[Verification database hooks](hooks.md#verification-hooks) run create hooks when options are generated and delete hooks when a verification spends the challenge, before the credential is checked and before `ValidateUserInfo` and the session hooks, so a verification that fails or is refused after that still spends it. A declined challenge returns its options with the challenge cookie expired, so the ceremony answers `CHALLENGE_NOT_FOUND`; a declined spend answers the same and keeps the challenge usable. Records name the ceremony as `passkey-registration` or `passkey-authentication` and the signed-in user, and never the challenge. A custom store implements `passkey.ChallengeFinder` for delete hooks and stores each challenge under `passkey.ChallengeRecordID(key)`, as the SQL store does. `New` still refuses user create hooks with this plugin. [Passkey hooks on SQL engines](../adapters/sqlstore/passkey_hooks_test.go)

## Passkey-first registration

Use passkey-first registration for an application that can identify an enrollment request before the user has a session. The resolver runs when the browser requests WebAuthn options. The supplied query `context` is client input. Validate an enrollment grant or invitation with your application and derive the provisional ID and display label from that result.

```go
options.Registration = passkey.RegistrationOptions{
    AllowWithoutSession: true,
    ResolveUser: func(c plainauth.EndpointContext, value *string) (passkey.RegistrationUser, error) {
        invite, err := invitations.Authorize(c.Request.Context(), value)
        if err != nil {
            return passkey.RegistrationUser{}, err
        }
        return passkey.RegistrationUser{
            ID: invite.ID, Name: invite.Email, DisplayName: invite.Name,
        }, nil
    },
    AfterVerification: func(c plainauth.EndpointContext, proof passkey.VerifiedRegistration) (passkey.RegistrationDecision, error) {
        invite, err := invitations.Authorize(c.Request.Context(), proof.Context)
        if err != nil {
            return passkey.RegistrationDecision{}, err
        }
        return passkey.RegistrationDecision{
            UserID: invite.AccountID,
            Name:   "Personal passkey",
            NewAccount: &passkey.RegistrationAccount{
                Email: invite.Email, Name: invite.Name,
            },
        }, nil
    },
}
```

Here `invitations.Authorize` is an application-owned lookup for a valid, unexpired grant. The verification callback receives the context saved with the challenge and the verified credential data. Its decision runs before persistence. Keep irreversible side effects outside the callback. The store inserts a newly provisioned user and its key together. Requesting `createSession: true` includes session creation in that transaction and emits the cookie only after commit. Existing-email, duplicate-key and session failures roll back provisioning. First-use account creation honors `DisableSignUp`. Provisioned email addresses start unverified.

To attach a credential to an **existing** user without a prior login, your callback must independently establish account ownership and explicitly return `AllowExistingAccount: true` and the authorized target `UserID`. For signed-in registration, the original direct session must remain active and fresh, and the final user must match that session. A supplied key name takes precedence over a label returned by the callback.

The Go SDK provides `BeginPasskeyRegistration` and `FinishPasskeyRegistration`, followed by `BeginPasskeyLogin` and `FinishPasskeyLogin`. Use a single client and its cookie jar throughout each ceremony. Pass the options to a WebAuthn authenticator and send its public credential response as JSON. The released browser client performs the same exchange with `passkey.addPasskey({ context, createSession: true })` and `signIn.passkey()`. [Native and three-engine tests](../adapters/sqlstore/passkey_first_test.go) · [Browser authenticator comparison](../conformance/passkey-first-browser.mjs)

## Credential identifiers

Credentials registered through a signed-in session retain their RP- and account-bound user handles. Passkey-first credentials use a random opaque handle. Their row ID carries that handle so assigning a final account ID after attestation preserves discoverable sign-in. The `credentialID` remains the authenticator’s independent credential ID. Neither value contains the user’s email. The browser comparison enrolls separate credentials with each server. Imported credentials require a matching stored user handle for discoverable login. The canonical MySQL schema limits the base64url credential ID to 255 characters.

Static or dynamic WebAuthn extension configuration and browser conditional UI remain on the [passkey checklist](parity/plugins/passkey.md).
