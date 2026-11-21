# Passkeys

A passkey gives a user a public-key credential for a relying party. Register it from a fresh session. On the next visit, the browser can discover the credential and sign the server’s challenge to establish a new session.

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
auth, err := frostauth.New(frostauth.Options{
    Store: store, BaseURL: "https://accounts.example.com", Secret: secret,
    Plugins: []frostauth.Plugin{keys},
})
```

Use an HTTPS browser origin. Local development also supports HTTP on localhost or a loopback IP. If the UI and API use different origins, include the browser origin in the auth server’s trusted origins and in the passkey origins. Set the relying-party ID before enrolling keys. Changing it creates a different credential namespace.

## Register and sign in

All paths below are relative to the auth mount. Keep browser cookies on both requests in each ceremony.

| Operation | Request | Result |
| --- | --- | --- |
| Begin registration | GET `/passkey/generate-register-options` | Public-key creation options for the signed-in account, including registered credentials to exclude |
| Finish registration | POST `/passkey/verify-registration` with `response` and an optional `name` | The stored credential |
| Begin login | GET `/passkey/generate-authenticate-options` | Public-key request options for discoverable login |
| Finish login | POST `/passkey/verify-authentication` with `response` | The authenticated user and session, plus a session cookie |
| List keys | GET `/passkey/list-user-passkeys` | The current user's credentials |
| Rename a key | POST `/passkey/update-passkey` with `id` and `name` | The updated `passkey` |
| Remove a key | POST `/passkey/delete-passkey` with `id` | A `status` confirmation |

In a browser, convert the JSON options into WebAuthn options and pass them to `navigator.credentials.create` or `navigator.credentials.get`. Send the resulting credential’s JSON representation as `response`. Rename and remove use the stored row’s `id`. The browser uses the separate `credentialID`. [WebAuthn API](https://www.w3.org/TR/webauthn-3/)

The signed HTTP-only challenge cookie and server-side verification record expire after five minutes by default. Each challenge permits one verification attempt. Registration also binds the challenge to the requesting account and session. The verifier checks the RP ID, browser origin, user-presence flag and assertion signature. `RequireUserVerification` additionally requires authenticator user verification. The SQL store commits the counter adjustment and new session together. Authenticators with a positive counter must advance it. Authenticator counters that stay at zero are supported.

The optional `ChallengeLifetime` accepts a Go duration. Key management operates on the signed-in user's rows. Deleting the account removes its keys. SQLite, PostgreSQL and MySQL have local software-authenticator tests for this lifecycle.

## Existing credentials

This implementation derives each account's opaque browser user handle from the RP ID and immutable account ID. The canonical MySQL schema limits the base64url credential ID to 255 characters. Pre-authentication enrollment, registration-time session creation, extension callbacks and browser conditional UI remain on the [passkey checklist](parity/plugins/passkey.md).
