# Transfer a session with a one-time token

Use a short-lived credential to transfer an existing login to another client. Verification returns the original session and user. Revoking or expiring that session takes effect for both clients.

```go
plugin, err := onetimetoken.New(onetimetoken.Options{
	ExpiresIn:  3 * time.Minute,
	HashTokens: true,
})
if err != nil {
	return err
}
opts.Plugins = append(opts.Plugins, plugin)
```

Import the module's `plugins/onetimetoken` package. The SQL adapters use the existing verification table. Configure all instances with the same storage mode. For an in-process application or test, use one shared `memory.New()` store for the issuing and receiving handlers. Its transfer credentials expire with the session or transfer deadline and disappear when the process exits.

1. The signed-in client calls `GET /one-time-token/generate`. The response contains a `token`. Transfer it over a private application-controlled channel to the intended recipient.
2. The recipient sends `POST /one-time-token/verify` with `{"token":"..."}`. On success the response contains the bound `session` and `user`, and the server sets the session cookie. The token can succeed once across all instances.
3. The recipient uses that session for authenticated requests. Its expiration and revocation state come from the same database record as the originating client's session.

Both paths are relative to the auth mount. In the Go HTTP client, use `GenerateOneTimeToken` and `VerifyOneTimeToken`. The host application can also call `Auth.GenerateOneTimeToken(ctx, headers)` and `Auth.VerifyOneTimeToken(ctx, token)` directly.

| Option | Behavior |
| --- | --- |
| `ExpiresIn` | Sets the transfer lifetime using a Go duration. An unset duration uses the three-minute default. A positive duration can be shorter than a minute. Set `ExpireImmediately: true` to issue an already-expired proof. |
| `DisableClientRequest` | Restricts generation to the direct Go method. HTTP generation first checks authentication. A signed-out request receives 401 and a signed-in request receives 400. |
| `DisableSetSessionCookie` | Returns the session and user in JSON while suppressing the session cookie on verification. The JSON session token remains a credential. |
| `SetHeaderOnNewSession` | Publishes and exposes a fresh `Set-Ott` response header when the handler writes a valid session cookie. This includes sign-in, profile updates that reissue a cookie, sliding renewal and cookie-setting transfer verification. |
| `HashTokens` | Stores the transfer key using SHA-256 and unpadded URL-safe Base64. The default stores the raw key. |
| `HashToken`, `GenerateToken` | Supply a deterministic storage-key function or a cryptographically random token generator. Use the same deterministic storage-key mode on every server. |

A verification response that sets cookies honors the receiving browser’s signed temporary-session preference. With cookie suppression, verification returns the transferred identity in JSON and the browser keeps its current login. A replacement `Set-Ott` belongs to the returned session, including when the recipient had another account signed in. Reads without cookie renewal, explicit token generation, sign-out and rejected requests omit this header.

When you configure additional user or session fields, verification reads the public values belonging to the issuing account and session at redemption time. The Go client exposes them through `result.User.AdditionalField(name)` and `result.Session.AdditionalField(name)`. Hidden fields and physical column names stay out of the response. Cookie replacement and subsequent renewal keep the same owner. [Field transfer tests](../adapters/sqlstore/onetimetoken_fields_test.go)

### Request-aware token generation

Use `GenerateTokenWithRequest` when a generator needs the request that initiated the login or transfer. It receives the authenticated user, the issuing session and a copy of the HTTP request metadata. Its body is empty. Direct calls to `Auth.GenerateOneTimeToken` supply a nil request. Configure one generator per plugin instance.

```go
plugin, err := onetimetoken.New(onetimetoken.Options{
    HashTokens: true,
    GenerateTokenWithRequest: func(ctx context.Context, s plainauth.SessionResult, req *http.Request) (string, error) {
        if req != nil {
            metrics.CountTransfer(s.User.ID, req.Method)
        }
        return rand.Text(), nil // crypto/rand
    },
})
```

Generation and redemption both check that the original user still owns a live, direct session. A ban, an administrator’s delegated login or a replacement session prevents transfer. A completed redemption consumes its proof across handlers. [SQL authorization tests](../adapters/sqlstore/onetimetoken_policy_test.go) · [In-memory adapter tests](../adapters/memory/onetimetoken_test.go) · [Go client example](../client/onetimetoken_context_test.go)

A custom generator must produce a fresh, unpredictable credential on every call. Its output must be suitable for an HTTP header. A custom hasher needs to distinguish credentials and fit the canonical verification identifier, which has room for 240 bytes after the prefix. Hashed modes can accept longer raw credentials. SQL issuance rejects an already-live transfer key, including one issued by a compatible writer. Redemption rejects and consumes ambiguous live records. Generate globally unique values even after old proofs are spent or expire.

Explicit operations return generator and hasher errors to the native caller. HTTP callers receive a failure response. Cancellation during a generator or hasher prevents issuance or consumption. An optional header failure leaves the successful session cookie in place and writes a diagnostic without the credential. [Callback failure tests](../client/onetimetoken_contract_test.go) · [Released client and cookie tests](../conformance/transfer-options.mjs)
