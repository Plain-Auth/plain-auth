# Authenticate an OAuth client with a signing key

A backend application registered with `private_key_jwt` signs a short-lived JWT for each request. Its private key stays with the application. Plain Auth verifies the signature with the registered public key at the token, introspection and revocation endpoints. [Client registration](oauth-client-registration.md) · [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html#section-3)

## Register a public key

Enable the `oauth-provider` schema profile on SQLite, PostgreSQL or MySQL and mount the OAuth provider plugin. Register the client with `token_endpoint_auth_method` set to `private_key_jwt`. Supply either an inline `jwks` containing the application's public JWK Set or a `jwks_uri` that serves it. Give each signing key a distinct `kid`. For machine access tokens, register the `client_credentials` grant and authorize its scopes. [Schema and CLI](databases.md) · [Machine scope management](oauth-client-registration.md#grant-machine-to-machine-scopes)

For a remote set, configure the exact HTTPS origin in the host's `auth.Options.TrustedOrigins`. This option also affects which application origins the auth handler trusts. The default transport resolves and dials a public IP directly. The endpoint must return HTTP 200, a JSON media type and at most 64 KiB. The fetch timeout is five seconds and redirects are rejected.

Each provider instance caches key sets for five minutes and shares concurrent requests for the same URL. When the assertion identifies a missing key, the provider refreshes the set. To rotate a remote key without interrupting requests, publish both public keys, begin signing with the new key ID, and retire the old key after outstanding assertions expire. When a refetch fails, the cached set keeps verifying assertions for up to ten minutes after the last successful fetch, unless the response was not a valid key set, and the URL is refetched at most once a minute meanwhile. A failure past that, or an invalid key set, discards it. A custom `Assertions.JWKSTransport` must enforce the host's destination policy.

A client a [client discovery](oauth-extensions.md#resolve-clients-through-a-discovery) owns may publish its `jwks_uri` on its client ID's origin, on an explicitly trusted origin, or where the discovery's `AllowCrossOriginJWKSURI` allows, asked at each assertion; the URL must still be HTTPS on a public host. Its keys are fetched through the discovery's `Transport`, cached apart from other clients' at the same URL, and refused with `client discovery does not provide a metadata resource transport` without one. The discovery's `JWKSStaleIfError` keeps its cached keys verifying beyond ten minutes, up to that long after the last success and at most a day, through a 500, 502, 503 or 504 answer, a timeout or a connection failure, logging each use; any other failure stops that until a fetch succeeds. A fetch the discovery's transport refuses at a local capacity limit, wrapping `oauthprovider.ErrFetchCapacity`, keeps them verifying within five minutes of a transient failure and never discards them, since it says nothing about the keys. [Key tests](../plugins/oauthprovider/client_assertion_test.go)

## Sign a request

Set both `iss` and `sub` to the assigned client ID. Use the public URL of the receiving endpoint for `aud`, or the configured OAuth issuer when the assertion may be used at any of these endpoints. Use a fresh random `jti` and an `exp` within the configured lifetime. The optional `nbf` and `iat` claims are Unix timestamps. The provider accepts RSA (RS256/384/512 and PS256/384/512, minimum 2048 bits), ECDSA (ES256/384/512 on the corresponding curve), and Ed25519 (EdDSA). When the client omits `kid` from the JWT header, exactly one registered public key must qualify.

This Go function signs a token request with an Ed25519 private key obtained from the application's key store. The caller can submit the returned values with `http.Client.PostForm`.

```go
import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/json"
    "net/url"
    "time"

    "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
    jose "github.com/go-jose/go-jose/v4"
)

func tokenForm(endpoint, clientID, keyID string, privateKey ed25519.PrivateKey) (url.Values, error) {
    signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: privateKey},
        (&jose.SignerOptions{}).WithHeader("kid", keyID))
    if err != nil {
        return nil, err
    }
    now := time.Now()
    claims, err := json.Marshal(map[string]any{
        "iss": clientID, "sub": clientID, "aud": endpoint, "jti": rand.Text(),
        "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
    })
    if err != nil {
        return nil, err
    }
    signed, err := signer.Sign(claims)
    if err != nil {
        return nil, err
    }
    assertion, err := signed.CompactSerialize()
    if err != nil {
        return nil, err
    }
    return url.Values{
        "grant_type": {"client_credentials"},
        "client_assertion_type": {oauthprovider.ClientAssertionType},
        "client_assertion": {assertion},
    }, nil
}
```

Send a form-encoded POST to the endpoint used as the audience. For introspection or revocation, replace `grant_type` with a `token` field and sign a new assertion for that operation. The optional form `client_id` must equal the ID in the assertion. [Token issuance and introspection](machine-tokens.md) · [Token revocation](oauth-token-revocation.md)

## Lifetime and replay protection

Set `oauthprovider.Options.Assertions.MaxLifetime` to a positive whole number of seconds. Its default is five minutes. `ClockTolerance` defaults to zero and accepts up to one minute of skew. Plain Auth checks the remaining lifetime, the age of an optional `iat`, and when an optional `nbf` takes effect.

The SQL adapter reserves a digest of the client ID and `jti` in `oauthClientAssertion` before evaluating grant scopes. All instances using the same database share this protection across the three endpoints. Generate a new assertion for retries, including after an invalid scope response. A custom store implements `oauthprovider.ClientAssertionStore` and reserves identifiers atomically. Replay records carry an `expiresAt` that includes the configured clock tolerance.

Signature, issuer, subject, audience and time verification failures return HTTP 401 with `invalid_client`. A reused identifier, excessive lifetime or malformed assertion returns HTTP 400. [Interoperability tests](../conformance/oauth-client-assertions.mjs) · [Three-engine concurrency tests](../adapters/sqlstore/oauth_client_assertion_test.go)

## Rotate inline public keys

A registered application can rotate its own inline keys when the issuer enables `oauthprovider.AssertionOptions{AllowKeyRotation: true}` in `Options.Assertions`. The built-in SQL adapters support it. At startup, Plain Auth checks for a store capable of atomically reserving the assertion identifier and replacing the keys. The endpoint defaults to five requests per minute per client IP. Set `Assertions.KeyRotationRateLimit` to override the rule or use an empty rule to inherit the global limit.

1. Generate the next signing key in the application and export its public JWK with a new `kid`.
2. Sign an assertion with a current key. Set `aud` to the full public URL ending in `/oauth2/client/rotate-keys`. This operation requires the rotation URL, including when `aud` is a list.
3. Send the complete set of old and new public keys. After the response succeeds, deploy clients that sign with the new key.
4. Once all clients have switched, sign a fresh rotation assertion and send only the new public key. Inline keys omitted from the replacement stop authenticating immediately.

With the Go SDK, `keys` is a `json.RawMessage` containing the full public JWK Set. The call returns the client ID and registered keys.

```go
updated, err := c.RotateOAuthClientKeys(ctx, signedRotationAssertion, keys)
```

The equivalent HTTP call uses `application/json`. Set `AUTH_URL` to the public origin and place the complete public JWK Set in `public-keys.json`.

```sh
jq -n --arg assertion "$ROTATION_ASSERTION" --slurpfile keys public-keys.json '{
  client_assertion: $assertion,
  client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  jwks: $keys[0]
}' | curl --request POST "$AUTH_URL/api/auth/oauth2/client/rotate-keys" \
  --header 'Content-Type: application/json' --data-binary @-
```

HTTP 403 means rotation is disabled. HTTP 409 means another request changed the registration between signature verification and the write. Read the current registered keys and sign a fresh request with a current key. If a network failure obscures the result, inspect the registration before retrying. Clients with a remote key set rotate at their registered `jwks_uri`. Operator-managed registrations use the operator's administrative process. [Two-stage rollover tests](../conformance/oauth-key-rotation.mjs) · [Concurrent rotation and rollback tests](../adapters/sqlstore/oauth_key_rotation_test.go)
