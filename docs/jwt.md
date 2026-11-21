# Signed tokens for services

Enable the `jwt` schema profile and register `plugins/jwt` to issue service tokens to signed-in users. The auth server signs the assertions. Receiving services fetch the public JWKS and verify signatures locally.

```go
ddl, err := schema.Generate("postgres", []string{"jwt"})
if err != nil {
	return err
}
store, err := sqlstore.OpenWithSchema(ctx, "postgres", dsn, ddl)
if err != nil {
	return err
}
plugin, err := jwt.New(jwt.Options{
	Issuer:           "https://accounts.example.com",
	Audience:         "billing-api",
	Expiration:       10 * time.Minute,
	RotationInterval: 90 * 24 * time.Hour,
})
if err != nil {
	return err
}
opts.Store = store
opts.Plugins = append(opts.Plugins, plugin)
```

With the default auth mount, an authenticated client requests `GET /api/auth/token` and receives `{"token":"..."}`. It presents that token to the receiving service. The public key set is available at `GET /api/auth/jwks`. The Go HTTP client exposes these operations as `JWT(ctx)` and `JWKS(ctx, "")`. An authenticated `GET /api/auth/get-session` also supplies the assertion in the `Set-Auth-Jwt` header. Set `DisableHeader` to suppress it.

Configure the receiving service with the auth server's public JWKS address, expected issuer, expected audience, and permitted signing algorithm. Select keys by the signed `kid` and check expiration for each request. A key rotation adds a new `kid`, so clients that cache keys should refresh the JWKS on an unknown key. Revoking a session prevents it from obtaining additional assertions. A service performing offline verification accepts a previously issued assertion until its own expiration, provided its verification key remains trusted.

| Option | Behavior |
| --- | --- |
| `Algorithm` | Defaults to EdDSA with Ed25519. ES256 with P-256 is also available. |
| `Issuer`, `Audience` | Each defaults to the configured auth origin. Give each receiving service the expected values. |
| `Expiration` | Defaults to fifteen minutes. |
| `RotationInterval` | Positive duration schedules key rotation. A token request after the signing key's expiry generates a replacement under a database lock. The default key has no scheduled expiry. |
| `GracePeriod` | An expired signing key remains published for thirty days by default. Set a duration pointer to change that window. |
| `JWKSPath` | Sets the public verification endpoint relative to the auth mount. Defaults to `/jwks`. |
| `DefinePayload` | Receives the authenticated session. The default payload includes the public user profile. A callback can select individual application claims. The server supplies the subject, issuer, audience and timestamps. |

All auth instances sharing signing keys need the same encryption key configuration. The SQL store persists the encrypted private JWK and its public counterpart separately. The JWKS endpoint publishes public fields. The host can use `Auth.IssueJWT(ctx, headers)` for authenticated issuance and `Auth.PublicJWKS(ctx)` for public key discovery.
