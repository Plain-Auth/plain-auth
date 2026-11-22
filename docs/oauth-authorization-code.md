# Exchange an authorization code

An OAuth client can exchange an authorization code and an S256 PKCE verifier at `POST /oauth2/token`. Plain Auth returns an opaque bearer token bound to the user, browser session, client and scopes approved for that code. The exchange supports SQLite, PostgreSQL and MySQL through the `oauth-provider` database profile. [Database setup](schema.md#oauth-authorization-server-tables)

The current exchange supports grants such as `reports` with no resource audience. Browser authorization and interactive consent in Go are still in development. The interoperability test obtains codes through an independent issuer’s browser authorization endpoint and submits them to the Go handler using shared storage. ID tokens, initial refresh tokens, sender-bound tokens and resource-targeted tokens for this grant remain on the [feature checklist](parity/plugins/oauth-provider.md). Those exchanges return an error and leave the code available.

## Send the exchange

A public client generates a random PKCE verifier for each authorization request and retains it until the callback. It sends the unpadded base64url SHA-256 digest as `code_challenge` with `code_challenge_method=S256`. After checking the callback’s state and issuer, the client sends the original verifier and code to the token endpoint. Use exactly the redirect URI sent at authorization. Omit it when the original authorization omitted it.

```sh
curl --fail-with-body https://accounts.example.com/api/auth/oauth2/token \
  --data-urlencode grant_type=authorization_code \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "code=$AUTHORIZATION_CODE" \
  --data-urlencode "code_verifier=$PKCE_VERIFIER" \
  --data-urlencode 'redirect_uri=https://app.example.com/oauth/callback'
```

Confidential applications use their registered Basic, form secret or signed assertion authentication method. PKCE is required by default for confidential clients. An explicitly relaxed registration may omit the verifier for a grant issued without a challenge. Public clients always require PKCE. [Client authentication](oauth-client-registration.md) · [Signed assertions](oauth-client-assertions.md)

With `golang.org/x/oauth2`, pass the verifier saved for this callback to `Exchange`.

```go
cfg := oauth2.Config{
    ClientID:    clientID,
    RedirectURL: "https://app.example.com/oauth/callback",
    Endpoint: oauth2.Endpoint{
        TokenURL:  "https://accounts.example.com/api/auth/oauth2/token",
        AuthStyle: oauth2.AuthStyleInParams,
    },
}
token, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
```

The JSON response includes `access_token`, `token_type`, `scope`, `expires_in` and `expires_at`. The access token lifetime defaults to one hour. Configure `Tokens.AccessLifetime` and use `Tokens.ScopeLifetimes` to shorten the lifetime for particular scopes. The body is served with `Cache-Control: no-store`. [Token introspection](machine-tokens.md#inspect-a-delegated-token)

## Retries and replay

An incorrect verifier, client or redirect URI leaves the code usable by its original client. Plain Auth checks the current client registration, user and session before it saves the token. Consumption and the insert share one database transaction. An insertion failure rolls back both operations.

Each code permits one successful redemption. Reusing that code as its authenticated client returns `invalid_grant` and removes stored access and refresh tokens linked to it. This also applies when two requests race. Start a fresh authorization if an exchange succeeded but the client lost the response. Other codes for the same user and client keep their own tokens. [Three-database retry and race tests](../adapters/sqlstore/oauth_authorization_code_test.go) · [Cross-runtime exchange](../conformance/oauth-authorization-code.mjs)

The verification identifier defaults to the unpadded base64url SHA-256 digest of the code. `Tokens.HashAuthorizationCode` allows applications with a custom issuer to supply a matching derivation. `Tokens.OpaquePrefix`, `Tokens.GenerateOpaqueToken` and `Tokens.HashOpaqueToken` configure the resulting access token. Application callbacks receive the request context and run outside the SQL transaction.
