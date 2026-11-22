# Authenticate an OAuth client with a signing key

A backend application registered with `private_key_jwt` signs a short-lived JWT for each request. Its private key stays with the application. Plain Auth verifies the signature with the registered public key at the token, introspection and revocation endpoints. [Client registration](oauth-client-registration.md) · [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html#section-3)

## Register a public key

Enable the `oauth-provider` schema profile on SQLite, PostgreSQL or MySQL and mount the OAuth provider plugin. Register the client with `token_endpoint_auth_method` set to `private_key_jwt`. Supply either an inline `jwks` containing the application's public JWK Set or a `jwks_uri` that serves it. Give each signing key a distinct `kid`. For machine access tokens, register the `client_credentials` grant and authorize its scopes. [Schema and CLI](databases.md) · [Machine scope management](oauth-client-registration.md#grant-machine-to-machine-scopes)

For a remote set, configure the exact HTTPS origin in the host's `auth.Options.TrustedOrigins`. This option also affects which application origins the auth handler trusts. The default transport resolves and dials a public IP directly. The endpoint must return HTTP 200, a JSON media type and at most 64 KiB. The fetch timeout is five seconds and redirects are rejected.

Each provider instance caches key sets for five minutes and shares concurrent requests for the same URL. When the assertion identifies a missing key, the provider refreshes the set. To rotate a remote key without interrupting requests, publish both public keys, begin signing with the new key ID, and retire the old key after outstanding assertions expire. On timeouts or transient HTTP failures a previously fetched set can be used for up to ten minutes from the last successful fetch. Invalid content and permanent HTTP errors discard it. A custom `Assertions.JWKSTransport` must enforce the host's destination policy.

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

    "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
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
