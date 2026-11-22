# Revoke OAuth tokens

Applications can send `POST /api/auth/oauth2/revoke` to invalidate an access or refresh token issued to their registration. The endpoint is part of the embedded `oauthprovider.New` plugin. Mount the auth handler on your router and enable the `oauth-provider` schema profile. SQLite, PostgreSQL and MySQL support the operation. [Router setup](routers.md) · [Database setup](schema.md#oauth-authorization-server-tables)

## Send a revocation request

Use the client authentication method selected at registration. A `client_secret_post` application sends its credentials in a URL-encoded form.

```sh
curl --request POST "$AUTH_URL/api/auth/oauth2/revoke" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET" \
  --data-urlencode "token=$ACCESS_TOKEN" \
  --data-urlencode 'token_type_hint=access_token'
```

A `client_secret_basic` application uses HTTP Basic with the form-encoded client ID and secret and sends only the token and optional hint in the body. A public registration using `none` sends its client ID and token. `AUTH_URL` is the public origin and `/api/auth` is the default mount.

A successful request returns HTTP 200 with an empty body. The same response covers expired, unknown, previously revoked, and differently owned tokens. Repeating a request cannot reveal who owns a token. Recognized hints are `access_token` and `refresh_token`. A hint controls lookup order. If the first lookup misses, Plain Auth checks the other type. [RFC 7009 §2](https://www.rfc-editor.org/rfc/rfc7009.html#section-2)

| Token submitted by its owner | Effect |
| --- | --- |
| Opaque access token | Deletes that token. Its refresh token and sibling access tokens remain usable. |
| Refresh token | Marks the refresh token revoked and deletes every opaque access token linked to it. Replaying a revoked refresh token invalidates the refresh family belonging to that client and user. |
| Live JWT access token | Returns HTTP 400 with `unsupported_token_type`. A service validating the signature can still accept the JWT until expiry. |

JWT recognition uses the configured issuer and signing keys. Every audience must be the issuer’s UserInfo endpoint or a registered resource. Disabling a resource preserves previously issued tokens. Deleting the resource makes tokens naming it inactive. A session JWT without an OAuth client claim is outside this flow.

Clients should retry after a transient server or transport error. A malformed request returns `invalid_request`. Invalid credentials return `invalid_client`. HTTP Basic authentication failures include a 401 challenge. A client registered with a public key can sign a fresh assertion for this endpoint. Introspection returns an inactive response for revoked machine access tokens and refresh tokens. [Refresh token introspection](machine-tokens.md#inspect-a-refresh-token) · [Signed client assertions](oauth-client-assertions.md) · [Machine access tokens](machine-tokens.md) · [OAuth checklist](parity/plugins/oauth-provider.md)

## Configure storage and limits

Plain Auth stores token lookups as SHA-256 digests encoded in unpadded base64url by default. The access-token path uses `Tokens.OpaquePrefix` and `Tokens.HashOpaqueToken`. For refresh tokens, revocation removes `Tokens.RefreshPrefix`, calls an optional `Tokens.DecodeRefreshToken`, then applies `Tokens.HashRefreshToken`. Return `oauthprovider.ErrInvalidRefreshToken` from the decoder for an unrecognized value. Operational errors from the decoder or digest function return a server error so clients know to retry.

With rate limiting enabled, the endpoint allows 30 requests per minute per client IP. Set `Tokens.RevocationRateLimit` for a custom rule or pass an empty `auth.RateLimitRule` to use the host's global limit. Custom stores implement `oauthprovider.RevocationStore` and check the current client credentials in the same transaction that changes token state. Signed tokens with resource audiences also require `OAuthResource` lookup. [SQL transaction tests](../adapters/sqlstore/oauth_revocation_test.go) · [Cross-runtime tests](../conformance/oauth-revocation.mjs)
