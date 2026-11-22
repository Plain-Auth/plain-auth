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

This flow issues opaque tokens for shared-secret registrations without a resource indicator. Resource-targeted issuance, DPoP, client assertions, authorization codes and refresh tokens have separate checklist entries. Requests requiring those capabilities cannot obtain an unbound machine token through this flow. [OAuth feature checklist](parity/plugins/oauth-provider.md)
