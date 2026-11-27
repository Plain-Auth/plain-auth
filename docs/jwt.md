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

Configure the receiving service with the auth server's public JWKS address, expected issuer, expected audience, and permitted signing algorithm. Select keys by the signed `kid` and check expiration for each request. A key rotation adds a new `kid`, so clients that cache keys should refresh the JWKS on an unknown key. An OAuth resource server in the same process reads the published keys directly; see [Protect your API](oauth-resource-server.md#an-api-in-the-same-process). Revoking a session prevents it from obtaining additional assertions. A service performing offline verification accepts a previously issued assertion until its own expiration, provided its verification key remains trusted.

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
| `DisablePrivateKeyEncryption` | Stores private keys as plain JWK JSON. Encryption with the application's encryption key is the default and is recommended. An instance cannot sign with a key stored the other way and keeps choosing the newest live key, so when you change the setting delete the existing `jwks` rows, or wait for them to expire under `RotationInterval`. |
| `RemoteJWKSURL` | Publishes the key set at another address. See [Publish keys elsewhere](#publish-keys-elsewhere). |
| `Sign` | Signs every token with your own key or a key service. See [Sign with your own key or a key service](#sign-with-your-own-key-or-a-key-service). |
| `SessionCookieCache` | Signs jwt-strategy browser session snapshots with the plugin's key. See [Sign browser session snapshots with the key set](#sign-browser-session-snapshots-with-the-key-set). |
| `KeyStore` | Keeps signing keys outside the main store. See [Keep keys in your own store](#keep-keys-in-your-own-store). |

All auth instances sharing signing keys need the same encryption key configuration. The SQL store persists the encrypted private JWK, unless `DisablePrivateKeyEncryption` is set, under the active encryption key version and its public counterpart separately. The JWKS endpoint publishes public fields. The host can use `Auth.IssueJWT(ctx, headers)` for authenticated issuance and `Auth.PublicJWKS(ctx)` for public key discovery.

## Sign browser session snapshots with the key set

Set `SessionCookieCache` to sign the `session_data` cookie of the jwt cache strategy with the plugin's primary key instead of the application secret, so services holding the published key set can verify a browser's session without calling the server.

```go
p, err := jwt.New(jwt.Options{SessionCookieCache: true, DisableHeader: true})
auth, err := plainauth.New(plainauth.Options{
    SessionCookieCache: &plainauth.SessionCookieCacheOptions{Strategy: plainauth.SessionCacheJWT},
    Plugins: []plainauth.Plugin{p},
})
```

A snapshot carries `typ` `plainauth.session-cache+jwt`, the key's `kid`, `iss` as the token issuer, `aud` `plainauth:session-cache`, `sub` as the user ID and `sid` as the session token. Verifiers must require that type and audience, so a service token signed with the same key never passes as a snapshot, and should treat `sid` as a credential. The names are this library's own; give a verifier configured for another implementation these values. `New` refuses the option with another cache strategy, with the token header on (session reads that issue the header always read the store, so the option would do nothing) or with `Sign`, and warns when the cache `MaxAge` exceeds `GracePeriod`. A snapshot stops verifying once its key leaves the grace period, where another runtime accepts any stored key with that ID; the next read is live and replaces it. [Snapshot tests](../adapters/sqlstore/jwt_test.go)

## Publish keys elsewhere

Set `RemoteJWKSURL` to serve the key set from another address, such as a CDN. The local key route is then not served, and authorization-server and OpenID discovery advertise the URL. `Algorithm` must be set, because discovery advertises it and a remote key set cannot reveal it. The address must be absolute HTTPS with a host name and no fragment, or HTTP on a loopback host; another runtime accepts any string. Copy `Auth.PublicJWKS(ctx)` to that address, including keys retired within `GracePeriod`. `VerifyJWT` and OAuth introspection, revocation and UserInfo still verify with the keys in the store and never fetch the URL, where another runtime's OAuth provider fetches it; there is no network call or cache in the verification path. [Remote key set test](../conformance/goapi/jwt_remote_keys_test.go)

## Sign with your own key or a key service

Set `Sign` to sign every token the plugin issues yourself, for example with a key from your configuration or through a remote key service. `New` requires `RemoteJWKSURL` with it, and every active signer key must be published there.

```go
p, err := jwt.New(jwt.Options{
    Algorithm:     "ES256",
    RemoteJWKSURL: "https://keys.example.com/jwks.json",
    Sign: func(ctx context.Context, req plainauth.JWTSigningRequest) (string, error) {
        typ := req.Type
        if typ == "" {
            typ = "JWT"
        }
        options := (&jose.SignerOptions{}).WithHeader("kid", keyID).WithType(jose.ContentType(typ))
        if req.ContentType != "" {
            options.WithContentType(jose.ContentType(req.ContentType))
        }
        signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: privateKey}, options)
        if err != nil {
            return "", err
        }
        payload, err := json.Marshal(req.Claims)
        if err != nil {
            return "", err
        }
        signed, err := signer.Sign(payload)
        if err != nil {
            return "", err
        }
        return signed.CompactSerialize()
    },
})
```

The request carries the complete claims, with `sub`, `iss`, `aud`, `iat` and `exp` already set; the `typ` and `cty` the caller requires, such as `at+jwt` for OAuth access tokens; and the algorithm or key ID the caller pinned. For a remote key service, build the header and payload, send the SHA-256 digest of `header.payload` to the service, check the signature it returns and assemble the compact token. The server then parses the result and refuses it unless it is a compact JWS with the requested or primary algorithm, the pinned `kid`, the requested `typ` and `cty`, and exactly the claims it was given; another runtime returns whatever the signer produces. No local key is minted. `VerifyJWT` and OAuth introspection read public keys from `KeyStore` or the main store and never fetch `RemoteJWKSURL`, so give `KeyStore` the signer's public keys when this server must verify its own tokens. [Custom signer tests](../conformance/goapi/jwt_signer_test.go)

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
