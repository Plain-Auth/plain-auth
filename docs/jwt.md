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

With the default auth mount, an authenticated client requests `GET /api/auth/token` and receives `{"token":"..."}`. It presents that token to the receiving service. The public key set is available at `GET /api/auth/jwks`. The Go HTTP client exposes these operations as `JWT(ctx)` and `JWKS(ctx, "")`. With a custom `JWKSPath`, pass the same path, as in `JWKS(ctx, "/.well-known/jwks.json")`, and configure the browser client with it too; the default path then answers 404. An authenticated `GET /api/auth/get-session` also supplies the assertion in the `Set-Auth-Jwt` header. Set `DisableHeader` to suppress it.

Configure the receiving service with the auth server's public JWKS address, expected issuer, expected audience, and permitted signing algorithm. Select keys by the signed `kid` and check expiration for each request. A key rotation adds a new `kid`, so clients that cache keys should refresh the JWKS on an unknown key. Revoking a session prevents it from obtaining additional assertions. A service performing offline verification accepts a previously issued assertion until its own expiration, provided its verification key remains trusted.

| Option | Behavior |
| --- | --- |
| `Algorithm` | Defaults to EdDSA. Also supports ES256 (P-256), ES512 (P-521), RS256 and PS256. EdDSA keys always use Ed25519; there is no curve option, because Ed448 cannot sign here. `New` refuses every other algorithm: ECDH-ES and its key-wrapping variants agree encryption keys and cannot sign a JWS, and HMAC algorithms such as HS256 have no public key to publish. |
| `AdditionalAlgorithms` | Algorithms available for server-side issuance. A key for an additional algorithm is generated on first use. Ordinary session tokens continue to use `Algorithm`. |
| `RSAModulusBits` | Size of RS256 and PS256 keys in bits. Defaults to 2048. Must be an even number of at least 2048; odd sizes are not FIPS 140-approved and Go's FIPS 140-only mode refuses them. |
| `Issuer`, `Audience` | Each defaults to the configured auth origin. Give each receiving service the expected values. |
| `Expiration` | Defaults to fifteen minutes. |
| `RotationInterval` | Positive duration schedules key rotation. A token request after the signing key's expiry generates a replacement under a database lock. The default key has no scheduled expiry. Each new key expires one interval after its creation. |
| `GracePeriod` | An expired signing key remains published for thirty days by default. Set a duration pointer to change that window. |
| `JWKSPath` | Sets the public verification endpoint relative to the auth mount. Defaults to `/jwks`. |
| `DefinePayload` | Receives the authenticated session. The default payload includes the public user profile. A callback can select individual application claims. The server supplies the subject, issuer, audience and timestamps. |
| `KeyStore` | Keeps signing keys outside the main store. See [Keep keys in your own store](#keep-keys-in-your-own-store). |

All auth instances sharing signing keys need the same encryption key configuration. The SQL store persists the encrypted private JWK under the active encryption key version and its public counterpart separately. The JWKS endpoint publishes public fields. The host can use `Auth.IssueJWT(ctx, headers)` for authenticated issuance and `Auth.PublicJWKS(ctx)` for public key discovery.

## Keep keys in your own store

Set `KeyStore` to a `plainauth.JWTStore` to keep signing keys in memory, in a secret manager or in a per-tenant keyring instead of the main store, which then needs no `jwks` table.

```go
keys := tenantKeyring{} // your JWTStore
p, err := jwt.New(jwt.Options{KeyStore: keys})
```

`ActiveJWTKey` returns the newest unexpired key for an algorithm, or calls `generate` once under the store's own lock and saves the new key. `PublicJWTKeys` lists the keys with no expiry or one after the cutoff. Implement `plainauth.JWTKeyLookup` as well to support `JWTSignOptions.KeyID`. Both methods receive the request context, or the context your code passes to `SignJWT` and `VerifyJWT`, so a host middleware can put the tenant on the request context and the store choose its keyring from it. Another runtime takes a pair of functions and picks the key itself without serializing creation; here the store picks the key, so concurrent requests share one new key. [Tenant keyring test](../conformance/goapi/jwt_key_store_test.go)

## Sign and verify from Go

A host application can sign a service assertion after authorizing the subject. These two methods run in the host process. HTTP requests to the signing and verification methods have no route.

```go
token, err := instance.SignJWT(ctx, "billing-worker", plainauth.JWTSignOptions{
    Audience: []string{"invoice-service"},
    Claims: map[string]any{"job": "reconcile"},
})
if err != nil {
    return err
}
claims, err := instance.VerifyJWT(ctx, token, plainauth.JWTVerifyOptions{
    Audience: "invoice-service", Subject: "billing-worker",
})
if err != nil {
    return err
}
_ = claims["job"]
```

Set `JWTSignOptions.Algorithm` to select an enabled algorithm or `KeyID` to require a particular active key. Supplying both requires a match. The options also support token type, content type, issuer, multiple audiences, issuance, expiration and activation times. Reserved claims come from these options and the subject argument. Verification checks the key ID, algorithm, signature, issuer, audience, subject and time window before returning claims. An optional expected subject further restricts which assertions the service accepts.

## Disable browser token issuance

To keep serving verification keys while disabling browser token issuance, add `"/token"` to `Options.DisabledPaths` and configure `jwt.Options{DisableHeader: true}`. The first setting returns 404 for the token endpoint. The second removes the session JWT header from session reads. [Mounted client test](../conformance/core.test.mjs)
