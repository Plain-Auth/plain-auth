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

The signed HTTP-only challenge cookie and server-side verification record expire after five minutes by default. Each challenge permits one verification attempt. Any server instance sharing the store can finish a ceremony this library began. The challenge stores the WebAuthn session data, including the random user handle and the requested extensions, under a digest of the challenge cookie's nonce, and uses its own cookie, so a ceremony begun by another runtime answers `CHALLENGE_NOT_FOUND` here. The cookie is named `<CookiePrefix>.passkey_challenge`, with `__Secure-` for an HTTPS base URL. `Options.Cookies["passkey_challenge"].Name` renames it and gets the same name checks as every other cookie, so the plugin has no separate cookie-name setting. [Cookie name test](../adapters/sqlstore/passkey_options_test.go) Signed-in registration binds the challenge to the requesting account and session. First-use registration saves the enrollment context and the identity returned by the resolver with the challenge. The verifier checks the RP ID, browser origin, user-presence flag and assertion signature. `RequireUserVerification` additionally requires authenticator user verification. The SQL store commits the counter adjustment and new session together. Authenticators with a positive counter must advance it. Authenticator counters that stay at zero are supported.

The optional `ChallengeLifetime` accepts a Go duration. Key management operates on the signed-in user's rows. Deleting the account removes its keys. SQLite, PostgreSQL and MySQL have local software-authenticator tests for this lifecycle.

[Verification database hooks](hooks.md#verification-hooks) run create hooks when options are generated and delete hooks when a verification spends the challenge, before the credential is checked and before `ValidateUserInfo` and the session hooks, so a verification that fails or is refused after that still spends it. A declined challenge returns its options with the challenge cookie expired, so the ceremony answers `CHALLENGE_NOT_FOUND`; a declined spend answers the same and keeps the challenge usable. Records name the ceremony as `passkey-registration` or `passkey-authentication` and the signed-in user, and never the challenge. A custom store implements `passkey.ChallengeFinder` for delete hooks and stores each challenge under `passkey.ChallengeRecordID(key)`, as the SQL store does. `New` still refuses user create hooks with this plugin. [Passkey hooks on SQL engines](../adapters/sqlstore/passkey_hooks_test.go)

## Naming passkeys by authenticator

Every passkey row carries `aaguid`, the identifier of the authenticator model, which is stored at registration and returned by `GET /passkey/list-user-passkeys`. `passkey.AuthenticatorName(aaguid)` returns a provider name for 14 common authenticators, ignoring case and surrounding space. It returns `""` for an unknown or empty AAGUID and for the all-zero AAGUID that privacy-preserving platforms report; Apple devices do this under `none` attestation. `passkey.AuthenticatorNames()` returns a copy of the list to extend, so extending it never changes the names other callers see and never races with requests reading the list. A fuller list is kept at [passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids).

```go
options.Registration.AfterVerification = func(c plainauth.EndpointContext, proof passkey.VerifiedRegistration) (passkey.RegistrationDecision, error) {
    return passkey.RegistrationDecision{Name: passkey.AuthenticatorName(proof.AAGUID)}, nil
}

label := "Passkey"
if row.Name != nil {
    label = *row.Name
} else if row.AAGUID != nil && passkey.AuthenticatorName(*row.AAGUID) != "" {
    label = passkey.AuthenticatorName(*row.AAGUID)
}
```

`VerifiedRegistration.AAGUID` is the AAGUID in the stored form. A non-blank name the client sends still wins over the callback's label. [Naming tests](../adapters/sqlstore/passkey_naming_test.go)

## Authenticator selection

`AuthenticatorSelection` sets what registration options ask for on every request.

```go
keys, err := passkey.New(passkey.Options{
    RPID: "example.com", RPName: "Example", Origins: []string{"https://accounts.example.com"},
    AuthenticatorSelection: passkey.AuthenticatorSelection{
        Attachment:  protocol.CrossPlatform, // "platform", "cross-platform" or empty for both
        ResidentKey: protocol.ResidentKeyRequirementRequired,
    },
})
```

`Attachment` limits registration to platform authenticators, which are built into the device, or to cross-platform ones such as a security key. Empty allows both. A request's `authenticatorAttachment` query, `platform` or `cross-platform`, replaces it for that request; any other value, an empty value or a repeated key answers 400 `VALIDATION_ERROR` before the session is read, and no challenge is issued. The browser client sends the query with `passkey.addPasskey({ authenticatorAttachment: "platform" })`, and the Go client with `PasskeyRegistrationRequest.AuthenticatorAttachment`.

`ResidentKey` is `required`, `preferred` (the default) or `discouraged`. The options always carry `requireResidentKey`, true only for `required`. `RequireUserVerification` still chooses required or preferred user verification. Sign-in finds the account by the credential's user handle. Unless `ResidentKey` is required, an authenticator may create a credential that is not discoverable and returns no user handle, and that credential cannot sign in here. Discouraged makes this likely, and preferred allows it on authenticators that cannot store discoverable credentials. `New` refuses any other attachment or resident-key value. [Selection tests](../adapters/sqlstore/passkey_options_test.go)

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

## WebAuthn extensions

`Registration.Extensions` and `Authentication.Extensions` add WebAuthn extension inputs to the registration and sign-in options. Each is a `passkey.ExtensionsResolver`, which runs for every options request after the user and the passkeys are resolved, so the inputs can depend on the request or its session. Return a fixed value for static extensions.

```go
options.Registration.Extensions = func(plainauth.EndpointContext) (protocol.AuthenticationExtensions, error) {
    return protocol.AuthenticationExtensions{LargeBlob: protocol.LargeBlobInputs{Support: protocol.LargeBlobSupportPreferred}}, nil
}
options.Authentication.Extensions = func(c plainauth.EndpointContext) (protocol.AuthenticationExtensions, error) {
    return protocol.AuthenticationExtensions{UVM: true}, nil
}
```

Registration always asks for `credProps` as well, as the browser client's WebAuthn library does. An error from a resolver refuses the request, and no challenge is issued. The challenge records the requested extensions, so another server instance verifies against them, and a requirement such as large blob support `required` refuses a response that does not meet it. Client extension outputs, including ones the server did not request, are accepted and not acted on, so the browser client's own `extensions` option keeps working.

Inputs are checked against the ceremony, so a registration-only input such as `credProps` in `Authentication.Extensions`, or an authentication-only input such as `appid` at registration, fails the options request with a server error instead of reaching the browser, where another runtime passes it through. Leave `credProps` out of sign-in extensions. [Extension and callback tests](../adapters/sqlstore/passkey_options_test.go)

## Sign-in callback

`Authentication.AfterVerification` receives each assertion that passed verification as a `passkey.VerifiedAuthentication`: the stored passkey as it was before this sign-in, the verified go-webauthn credential with its new signature counter and flags, and the credential JSON the client sent, including `clientExtensionResults`. It runs after the challenge is spent and before the counter is saved and the session is issued, outside any store transaction. Return an error to refuse the sign-in. Nothing is saved: a `*plainauth.APIError` is the response, and any other error is logged and answered with 400 `AUTHENTICATION_FAILED`, as another refused assertion is.

```go
options.Authentication.AfterVerification = func(c plainauth.EndpointContext, v passkey.VerifiedAuthentication) error {
    if !v.Credential.Flags.UserVerified {
        return &plainauth.APIError{Status: 403, Code: "USER_VERIFICATION_REQUIRED", Message: "Verify your identity on the authenticator"}
    }
    return audit.Record(c.Request.Context(), v.Passkey.UserID, "passkey sign-in")
}
```

## Error codes

| Code | Status | When |
| --- | ---: | --- |
| `VALIDATION_ERROR` | 400 | An `authenticatorAttachment` query other than `platform` or `cross-platform`, or a rename without a name |
| `CHALLENGE_NOT_FOUND` | 400 | The challenge cookie is missing, expired, already spent or from another ceremony |
| `FAILED_TO_VERIFY_REGISTRATION` | 400 | The attestation does not verify |
| `PREVIOUSLY_REGISTERED` | 400 | The credential is already stored |
| `SESSION_REQUIRED` | 401 | A registration is finished without the session that began it |
| `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY` | 401 | The decision names another account, or an existing account without `AllowExistingAccount` |
| `RESOLVE_USER_REQUIRED` | 400 | A signed-out registration without `ResolveUser` |
| `RESOLVED_USER_INVALID` | 400 | `ResolveUser` returned no ID or name, or a new account's email is invalid |
| `USER_NOT_FOUND` | 500 | The decision names an account that does not exist |
| `UNABLE_TO_CREATE_SESSION` | 500 | A session create hook skipped the session |
| `AUTHENTICATION_FAILED` | 400, or 401 when the signature does not verify | The assertion is refused |
| `PASSKEY_NOT_FOUND` | 401 at sign-in, 404 on update and delete | No stored passkey has this credential, or the caller owns none with this ID |
| `UNAUTHORIZED` | 401 | List, update or delete without a session |

`New` refuses a configuration without `Origins`, so no request answers `ORIGIN_NOT_CONFIGURED`. A rename runs in one transaction, so `FAILED_TO_UPDATE_PASSKEY` never occurs. `REGISTRATION_CANCELLED`, `AUTH_CANCELLED` and `UNKNOWN_ERROR` come only from the browser client. These answers differ from another runtime's, for safety:

- Update and delete answer 404 `PASSKEY_NOT_FOUND` for another account's ID as for an unknown one, where another runtime answers 401, so the answer never confirms another account's passkey.
- The server refuses a credential that is already stored with `PREVIOUSLY_REGISTERED`, where another runtime's server stores it again and only its browser client reports that code.
- `USER_NOT_FOUND` is also answered without `createSession`, because the store always checks the account.
- A skipped session stores nothing: a registration rolls back, and a sign-in leaves the passkey's counter unchanged, where another runtime has already advanced it. [Error code tests](../adapters/sqlstore/passkey_errors_test.go)

## Credential identifiers

Credentials registered through a signed-in session retain their RP- and account-bound user handles. Passkey-first credentials use a random opaque handle. Their row ID carries that handle so assigning a final account ID after attestation preserves discoverable sign-in. The `credentialID` remains the authenticator’s independent credential ID. Neither value contains the user’s email. The browser comparison enrolls separate credentials with each server. Imported credentials require a matching stored user handle for discoverable login. The canonical MySQL schema limits the base64url credential ID to 255 characters.

Browser conditional UI remains on the [passkey checklist](parity/plugins/passkey.md).
