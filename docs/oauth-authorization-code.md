# Exchange an authorization code

An OAuth client can exchange an authorization code and an S256 PKCE verifier at `POST /oauth2/token`. Plain Auth returns an opaque bearer token bound to the user, browser session, client and scopes approved for that code. The exchange supports SQLite, PostgreSQL and MySQL through the `oauth-provider` database profile. [Database setup](schema.md#oauth-authorization-server-tables)

The exchange supports grants such as `reports` and `reports offline_access` with no resource audience. Browser authorization and interactive consent in Go are still in development. The interoperability test obtains codes through an independent issuer’s browser authorization endpoint and submits them to the Go handler using shared storage. ID tokens, sender-bound tokens and resource-targeted tokens for this grant remain on the roadmap. Those exchanges return an error and leave the code available. [Feature checklist](parity/plugins/oauth-provider.md)

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

## Request offline access

Include `offline_access` in the scopes approved at authorization and use S256 PKCE. Send the same code exchange shown above. A successful response also includes `refresh_token`. With the Go client, read it from `token.RefreshToken`. The access token remains tied to the browser session. The offline refresh token can remain active after that session expires. Plain Auth supports issuing, inspecting and revoking it. Native exchange of the refresh token for a replacement is still in development. [Refresh token introspection](machine-tokens.md#inspect-a-refresh-token) · [Revocation](oauth-token-revocation.md)

The refresh token defaults to 32 random letters and expires after 30 days. Set `Tokens.RefreshLifetime` to a positive duration in whole seconds to change it. The stored credential is the unpadded base64url SHA-256 digest. Each pair retains the client, user, original session, reference ID, authorization-code identifier and approved scopes. The refresh record uses the authentication time in the code or, when absent, the browser session’s creation time.

To customize the credential, supply `Tokens.GenerateRefreshToken` to generate the raw value and `Tokens.HashRefreshToken` to derive the stored lookup key. For a custom wire format, supply `Tokens.EncodeRefreshToken` and `Tokens.DecodeRefreshToken`. The encoder receives the raw token and session ID. Plain Auth adds `Tokens.RefreshPrefix` after encoding and removes it before decoding. The hash callback receives the raw value on both issuance and lookup. [Three-database offline grant tests](../adapters/sqlstore/oauth_offline_code_test.go)

## Retries and replay

An incorrect verifier, client or redirect URI leaves the code usable by its original client. Plain Auth checks the current client registration, user and session before it saves the token. For offline access, it runs the application’s refresh-token callbacks outside database locks, then verifies the same code and current permissions again. Code consumption and both token inserts share one transaction. A failed insert leaves the code usable and publishes neither token.

Each code permits one successful redemption. Reusing that code as its authenticated client returns `invalid_grant` and removes stored access and refresh tokens linked to it. This also applies when two requests race. Start a fresh authorization if an exchange succeeded but the client lost the response. Other codes for the same user and client keep their own tokens. [Three-database retry and race tests](../adapters/sqlstore/oauth_authorization_code_test.go) · [Cross-runtime exchange](../conformance/oauth-authorization-code.mjs)

The verification identifier defaults to the unpadded base64url SHA-256 digest of the code. `Tokens.HashAuthorizationCode` allows applications with a custom issuer to supply a matching derivation. `Tokens.OpaquePrefix`, `Tokens.GenerateOpaqueToken` and `Tokens.HashOpaqueToken` configure the resulting access token. Application callbacks receive the request context and run outside the SQL transaction.
