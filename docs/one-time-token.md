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

Import the module's `plugins/onetimetoken` package. The SQL adapters use the existing verification table. Configure all instances with the same storage mode.

1. The signed-in client calls `GET /one-time-token/generate`. The response contains a `token`. Transfer it over a private application-controlled channel to the intended recipient.
2. The recipient sends `POST /one-time-token/verify` with `{"token":"..."}`. On success the response contains the bound `session` and `user`, and the server sets the session cookie. The token can succeed once across all instances.
3. The recipient uses that session for authenticated requests. Its expiration and revocation state come from the same database record as the originating client's session.

Both paths are relative to the auth mount. In the Go HTTP client, use `GenerateOneTimeToken` and `VerifyOneTimeToken`. The host application can also call `Auth.GenerateOneTimeToken(ctx, headers)` and `Auth.VerifyOneTimeToken(ctx, token)` directly.

| Option | Behavior |
| --- | --- |
| `ExpiresIn` | Sets the transfer lifetime. The default is three minutes. |
| `DisableClientRequest` | Restricts generation to the host application's direct Go method. Verification remains available over HTTP. |
| `DisableSetSessionCookie` | Returns the session and user in JSON while suppressing the session cookie on verification. The JSON session token remains a credential. |
| `SetHeaderOnNewSession` | Adds `Set-Ott` to a successful new-session response and exposes that header to browser clients. If optional header generation fails, the host logs the failure and omits the header. |
| `HashTokens` | Stores the transfer key using SHA-256 and unpadded URL-safe Base64. The default stores the raw key. |
| `HashToken`, `GenerateToken` | Supply a deterministic storage-key function or a cryptographically random token generator. Use one storage-key mode on every server. |
