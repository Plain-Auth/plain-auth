# Issue a machine access token

An application can exchange its own credentials for an opaque Bearer token at `POST /api/auth/oauth2/token`. The endpoint runs inside the existing auth handler on any supported router. Each token belongs to one registered client and has a set of scopes and an expiry. A machine exchange does not start a user session.

## Configure the issuer

Enable the `oauth-provider` schema profile on SQLite, PostgreSQL or MySQL. Mount the plugin returned by `oauthprovider.New`. Register a confidential application with the `client_credentials` grant and the authentication method it will use, then have an authorized operator grant it machine scopes. A new client starts with an empty grant. [Registration and scope management](oauth-client-registration.md#grant-machine-to-machine-scopes) · [Mount the handler](routers.md) · [Database setup](schema.md#oauth-authorization-server-tables)

```go
opts := oauthprovider.Options{
    Scopes: []string{"reports:read", "reports:export"},
    Tokens: oauthprovider.TokenOptions{
        MachineLifetime: 10 * time.Minute,
        ScopeLifetimes:  map[string]time.Duration{"reports:export": 2 * time.Minute},
        OpaquePrefix:    "at_",
    },
}
```

Add the host's `ClientPrivileges` callback before passing these options to both the auth plugin and the client manager. The default machine lifetime is one hour. A token requesting multiple scopes gets the shortest applicable lifetime. Configure positive durations in whole seconds. With rate limiting enabled, the default endpoint limit is 20 requests per minute per client IP. `Tokens.RateLimit` overrides it.

## Request a token in Go

Use `golang.org/x/oauth2/clientcredentials`. Choose `AuthStyleInHeader` for a client registered with `client_secret_basic` or `AuthStyleInParams` for `client_secret_post`. The Go OAuth client handles form encoding, including special characters in IDs and secrets.

```go
package example

import (
    "context"

    "golang.org/x/oauth2"
    "golang.org/x/oauth2/clientcredentials"
)

func reportsTokens(ctx context.Context, tokenURL, id, secret string) oauth2.TokenSource {
    config := clientcredentials.Config{
        TokenURL:     tokenURL,
        ClientID:     id,
        ClientSecret: secret,
        AuthStyle:    oauth2.AuthStyleInHeader,
        Scopes:       []string{"reports:read"},
    }
    return config.TokenSource(ctx)
}
```

Reuse the returned token source for the application's lifetime. Its `Token()` method reuses a valid token and obtains another when needed. Set `tokenURL` to your public auth mount followed by `/oauth2/token`.

For a `client_secret_post` registration, the equivalent form request is:

```sh
curl --request POST "$AUTH_URL/api/auth/oauth2/token" \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET" \
  --data-urlencode 'scope=reports:read'
```

Here `AUTH_URL` is the public origin and `/api/auth` is the default mount. Supply the scope as a space-separated string or omit it to request the full machine grant. Sending an empty `scope` is invalid. A successful JSON response contains `access_token`, `token_type` (`Bearer`), `scope`, `expires_in` in seconds and `expires_at` as a Unix timestamp.

## Token storage and errors

Plain Auth generates a fresh token for each successful exchange and stores a SHA-256 digest encoded in unpadded base64url. `Tokens.OpaquePrefix` applies to the returned token. `Tokens.GenerateOpaqueToken` and `Tokens.HashOpaqueToken` customize the unprefixed value and its stored digest. If registration uses a randomized secret-storage function, configure `Registration.VerifySecret` to check an unprefixed secret against its stored representation. A deterministic `StoreSecret` can also be used for comparison.

The SQL adapters recheck the registration, credential, grant, and scopes when inserting the token. A rotation, deletion or withdrawal of permissions during issuance can reject the exchange. Deleting the application also deletes its stored tokens. [SQL and Go client tests](../adapters/sqlstore/oauth_machine_token_test.go) · [Issuance, independent introspection and revocation tests](../conformance/oauth-machine-tokens.mjs)

| Response | Meaning |
| --- | --- |
| 400 `invalid_request` | A required parameter is missing, a client authentication parameter is repeated, or multiple authentication methods were used. |
| 400 or 401 `invalid_client` | Client identification or authentication failed. Failed Basic authentication returns 401 with `WWW-Authenticate: Basic`. |
| 400 `unauthorized_client` | The client cannot use the grant or has no machine scopes. |
| 400 `invalid_scope` | A requested permission falls outside the current machine grant. |
| 415 `UNSUPPORTED_MEDIA_TYPE` | Send the token request as `application/x-www-form-urlencoded`. |

This flow issues opaque tokens for confidential registrations using a shared secret or a signed client assertion. For a key-based registration, generate a fresh assertion for each exchange. Resource-targeted issuance, DPoP, authorization codes and refresh tokens have separate checklist entries. Requests requiring those capabilities cannot obtain an unbound machine token through this flow. [Signed client assertions](oauth-client-assertions.md) · [OAuth feature checklist](parity/plugins/oauth-provider.md)

## Check whether a token is active

A confidential application can inspect its own opaque machine tokens, delegated access tokens, and refresh tokens at `POST /api/auth/oauth2/introspect`. Authenticate using the registered method. A signed client assertion can address the introspection endpoint or the issuer. For a `client_secret_post` registration, send the following request from your server.

```sh
curl --request POST "$AUTH_URL/api/auth/oauth2/introspect" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET" \
  --data-urlencode "token=$ACCESS_TOKEN" \
  --data-urlencode 'token_type_hint=access_token'
```

An active access token returns the issuer in `iss`, the issuing application in `client_id` and `azp`, its space-separated `scope`, and Unix timestamps in `iat` and `exp`. Before authorizing an operation, check `active`, the intended audience, the required scopes, and any sender binding in `cnf`.

An unknown, expired, revoked or unauthorized token returns HTTP 200 with only `{"active":false}`. Invalid client credentials produce an OAuth error. The optional `token_type_hint` can be omitted. The response uses `Cache-Control: no-store`.

With rate limiting enabled, the default is 100 introspection requests per minute per client IP. Set `Tokens.IntrospectionRateLimit` to override the limit, or supply an empty `auth.RateLimitRule` to use your host's global rule. If you customize `Tokens.HashOpaqueToken`, return the same digest each time for the same unprefixed token. Custom stores supporting delegated grants implement `oauthprovider.OpaqueAccessIntrospectionStore`. Return the caller registration, token, issuing registration, session, audiences, and resource links from a consistent database snapshot. Custom stores serving only machine tokens can implement `oauthprovider.MachineIntrospectionStore`. [Cross-runtime tests](../conformance/oauth-introspection.mjs) · [SQL adapter tests](../adapters/sqlstore/oauth_introspection_test.go)

To end access early, submit the token to `POST /api/auth/oauth2/revoke` using the issuing application's credentials. Its next introspection returns `{"active":false}`. [Revoke a token](oauth-token-revocation.md)

## Inspect a delegated token as a resource server

Register your API as a confidential OAuth client, then link that client to its registered resource identifier. Submit the access token to the introspection endpoint using the API’s own client credentials. A link to any one of the token’s explicit resource audiences authorizes inspection. Every audience must still exist. The implicit UserInfo endpoint can appear in the audience but grants no other client access. A token without a resource audience is visible only to its issuing application. [Manage resources and link a client](oauth-resource-management.md)

For a delegated opaque access token, `sub` identifies the user. A pairwise registration uses the issuing application’s sector even when another client inspects the token. A session-bound grant includes `sid` and becomes inactive when the session expires or ends. An unbound grant can remain active without a session. Key-bound tokens report `token_type: "DPoP"` and their confirmation key. Other tokens report `"Bearer"`. The introspection response describes the binding. Your resource server still verifies the proof accompanying each protected request.

The `aud` claim is a string for one audience and an array for several. For a resource-targeted grant with the `openid` scope, the issuer also includes its UserInfo endpoint. Resource policy claims are merged in audience order, with later resources taking precedence. The issuer controls identity, audience, binding, expiry and other protocol fields. Disabling a resource preserves outstanding grants. Deleting any named resource makes the token inactive. Signed JWT introspection and host-defined claim callbacks are tracked separately. [Delegated access tests](../conformance/oauth-opaque-introspection.mjs) · [SQL consistency tests](../adapters/sqlstore/oauth_opaque_introspection_test.go)

## Inspect a refresh token

Send a form-encoded request to the introspection endpoint with the refresh token and the issuing application's registered client credentials. Set `token_type_hint=refresh_token` to look up a refresh token directly. An omitted or unknown hint checks for a matching access token first. A recognized inactive access token yields `{"active":false}`.

```sh
curl --request POST "$AUTH_URL/api/auth/oauth2/introspect" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET" \
  --data-urlencode "token=$REFRESH_TOKEN" \
  --data-urlencode 'token_type_hint=refresh_token'
```

An active refresh grant returns its `client_id`, issuer, issue time, expiry, granted scopes and token type. A stored confirmation binding is returned in `cnf`. A DPoP thumbprint sets `token_type` to `DPoP`. The issuing application authenticates to introspect any of its grants, including those with a binding. The resulting claims describe the grant.

| Grant state | Introspection result |
| --- | --- |
| Live browser session | Includes the user's `sub` and the live session's `sid`. |
| Expired or deleted session, grant has `offline_access` | Stays active until token expiry or revocation. The response omits `sid`. |
| Expired or deleted session, session-bound grant without `offline_access` | Returns only `{"active":false}`. |
| Grant issued without a browser session or authorization code | Can stay active without `sid`. |
| Unknown, expired, revoked or owned by another application | Returns only `{"active":false}`. |

For a registration with `subject_type=pairwise`, configure the same `Options.PairwiseSecret` on every issuer instance. The subject derives from the user ID and the normalized host of the first registered redirect URI, including a non-default port. If the configured secret is missing for a stored pairwise client, the request fails and the user's account ID stays private.

`Tokens.RefreshPrefix`, `Tokens.DecodeRefreshToken` and `Tokens.HashRefreshToken` apply to both introspection and revocation. A decoder can return `oauthprovider.ErrInvalidRefreshToken` for an unrecognized envelope. Storage and operational decoder failures return an HTTP error, allowing callers to distinguish a service failure from an inactive token. For a custom adapter, implement `oauthprovider.RefreshIntrospectionStore` alongside `MachineIntrospectionStore`. [Cross-runtime authorization-code exchange](../conformance/oauth-refresh-introspection.mjs) · [Database integration tests](../adapters/sqlstore/oauth_refresh_introspection_test.go)
