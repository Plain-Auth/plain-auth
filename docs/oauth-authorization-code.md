# Authorize a browser client and exchange its code

An application can send a signed-in user to `/oauth2/authorize` and exchange the resulting code at `/oauth2/token`. Plain Auth returns an opaque bearer token bound to the user, browser session, client and approved scopes. Both endpoints mount in your existing Go server and use the `oauth-provider` database profile on SQLite, PostgreSQL or MySQL. [Register a client](oauth-client-registration.md) · [Router setup](routers.md) · [Database setup](schema.md#oauth-authorization-server-tables)

## Obtain a code in the browser

Register the application's callback URL and enable the `authorization_code` grant on both the issuer and the client. The issuer enables this grant by default. This flow supports untargeted scopes such as `reports` and `reports offline_access`. It requires the account owner's active browser session and either a recorded approval covering every requested scope or an operator-managed client with `skipConsent` enabled. Dynamic registration rejects `skip_consent`. First-time interactive consent, ID tokens, sender binding and resource audiences for this grant remain on the roadmap. [Client registration](oauth-client-registration.md) · [Manage recorded approvals](oauth-consents.md) · [Feature checklist](parity/plugins/oauth-provider.md)

For a public client using `golang.org/x/oauth2`, configure both issuer endpoints. Generate new random state and a PKCE verifier for each visit. Save them with the expected issuer and callback in the application's session before redirecting the user's browser.

```go
cfg := oauth2.Config{
    ClientID:    clientID,
    RedirectURL: "https://app.example.com/oauth/callback",
    Scopes:      []string{"reports"},
    Endpoint: oauth2.Endpoint{
        AuthURL:   "https://accounts.example.com/api/auth/oauth2/authorize",
        TokenURL:  "https://accounts.example.com/api/auth/oauth2/token",
        AuthStyle: oauth2.AuthStyleInParams,
    },
}
state, verifier := oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
// Save state and verifier in the user's application session here.
target := cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
http.Redirect(w, r, target, http.StatusFound)
```

The endpoint accepts GET query parameters or an `application/x-www-form-urlencoded` POST body. Supply `response_type=code`, `client_id`, `redirect_uri` and the S256 challenge. Omitting `scope` requests the client's registered scopes, falling back to the issuer's scopes when the client has no explicit list. Web callbacks must match a registered URL exactly. A native app using an HTTP loopback callback may vary its port while preserving its host, path and query.

A successful navigation returns HTTP 302 to the callback with `code`, `iss` and the supplied `state`. A CORS fetch or a request accepting `application/json` receives HTTP 200 with `{"redirect":true,"url":"…"}`. On the callback, check `state` against the saved request, verify `iss` against the expected issuer, and check for `error` before exchanging the code. Unrecognized clients and unapproved callback URLs go to the issuer's error page. With `prompt=none`, `login_required` means the user needs to sign in and `consent_required` means the recorded approval does not cover this request. `max_age` limits the age of the login in seconds. Zero requests fresh authentication. [End-to-end browser and exchange tests](../conformance/oauth-browser-authorization.mjs)

### Configure issuance

`oauthprovider.Options.Authorization` accepts these settings. Host callbacks receive the request context and run outside database transactions.

| Setting | Behavior |
| --- | --- |
| `CodeLifetime` | A code expires after ten minutes by default. Set a positive duration in whole seconds to change it. |
| `ConsentReference` | Choose an approval namespace, such as the active organization's ID, from the verified session. An empty value selects personal consent. Approval for another namespace cannot authorize a code. |
| `ValidateRedirectURI` | Receives the requested URL, a copy of the client's registered URLs and the default match result. Return the decision from your host policy. Syntax and transport checks run first. An error rejects the redirect. |
| `RateLimit` | GET and POST share a default allowance of 30 requests per minute per client IP when rate limiting is enabled. Set a route rule to change it, or supply an empty rule to inherit the host default. |

Plain Auth checks the registration, session and current consent again before storing the code. `Tokens.HashAuthorizationCode` controls its stored identifier during both issuance and redemption. [Three-database issuance tests](../adapters/sqlstore/oauth_browser_authorization_test.go)

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

With the `oauth2.Config` above, pass the verifier saved for this callback to `Exchange`.

```go
token, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
```

The JSON response includes `access_token`, `token_type`, `scope`, `expires_in` and `expires_at`. The access token lifetime defaults to one hour. Configure `Tokens.AccessLifetime` and use `Tokens.ScopeLifetimes` to shorten the lifetime for particular scopes. The body is served with `Cache-Control: no-store`. [Token introspection](machine-tokens.md#inspect-a-delegated-token)

## Request offline access

Include `offline_access` in the scopes approved at authorization and use S256 PKCE. Send the same code exchange shown above. A successful response also includes `refresh_token`. With the Go client, read it from `token.RefreshToken`. The initial access token remains tied to the browser session. The offline refresh token can remain active after that session expires. [Refresh token introspection](machine-tokens.md#inspect-a-refresh-token) · [Revocation](oauth-token-revocation.md)

The refresh token defaults to 32 random letters and expires after 30 days. Set `Tokens.RefreshLifetime` to a positive duration in whole seconds to change it. The stored credential is the unpadded base64url SHA-256 digest. Each pair retains the client, user, original session, reference ID, authorization-code identifier and approved scopes. The refresh record uses the authentication time in the code or, when absent, the browser session’s creation time.

To customize the credential, supply `Tokens.GenerateRefreshToken` to generate the raw value and `Tokens.HashRefreshToken` to derive the stored lookup key. For a custom wire format, supply `Tokens.EncodeRefreshToken` and `Tokens.DecodeRefreshToken`. The encoder receives the raw token and session ID. Plain Auth adds `Tokens.RefreshPrefix` after encoding and removes it before decoding. The hash callback receives the raw value on both issuance and lookup. [Three-database offline grant tests](../adapters/sqlstore/oauth_offline_code_test.go)

## Exchange a refresh token

A public client sends its client ID and refresh token. A confidential client authenticates using its registered method, as it did for the original code exchange. Include `refresh_token` in the issuer’s `GrantTypes` when configuring an explicit list. The default includes it.

```sh
curl --fail-with-body https://accounts.example.com/api/auth/oauth2/token \
  --data-urlencode grant_type=refresh_token \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "refresh_token=$REFRESH_TOKEN"
```

Omit `scope` to retain the grant’s scopes. To narrow access, send a space-separated subset. The client’s current registration must still permit each scope. Adding a scope requires fresh authorization. If the parent has `offline_access`, a successful exchange returns a new access token and a replacement refresh token. Persist the replacement before the next refresh. Its lifetime starts at issuance. In Go, `cfg.TokenSource(ctx, token).Token()` performs the exchange when the access token has expired. [Go client integration test](../adapters/sqlstore/oauth_refresh_grant_test.go)

After the original session ends, an offline grant can still mint an access token. That access token omits `sid`. Dropping `offline_access` requires a live originating session for a code grant. While the session is active, narrowing an offline grant returns a session-bound replacement. A subsequent exchange of that replacement returns an access token and leaves the session-bound refresh token usable until its expiry, revocation or the end of its session. [Cross-runtime scope and session tests](../conformance/oauth-refresh-grant.mjs)

Serialize refresh requests that share a credential. Plain Auth commits the parent revocation and both replacements together. Reuse of a rotated credential under the default policy returns `invalid_grant` and invalidates the client’s refresh tokens for that user and their linked access tokens. A failed callback or database insert rolls back the exchange and leaves the parent usable for retry. The grant currently supports untargeted bearer access. Returning a cached response inside a retry window, ID tokens, resource audiences and sender-bound refresh exchanges remain on the roadmap. [Token revocation](oauth-token-revocation.md) · [Feature checklist](parity/plugins/oauth-provider.md)

## Retries and replay

An incorrect verifier, client or redirect URI leaves the code usable by its original client. Plain Auth checks the current client registration, user and session before it saves the token. For offline access, it runs the application’s refresh-token callbacks outside database locks, then verifies the same code and current permissions again. Code consumption and both token inserts share one transaction. A failed insert leaves the code usable and publishes neither token.

Each code permits one successful redemption. Reusing that code as its authenticated client returns `invalid_grant` and removes stored access and refresh tokens linked to it. This also applies when two requests race. Start a fresh authorization if an exchange succeeded but the client lost the response. Other codes for the same user and client keep their own tokens. [Three-database retry and race tests](../adapters/sqlstore/oauth_authorization_code_test.go) · [Cross-runtime exchange](../conformance/oauth-authorization-code.mjs)

The verification identifier defaults to the unpadded base64url SHA-256 digest of the code. `Tokens.HashAuthorizationCode` allows applications with a custom issuer to supply a matching derivation. `Tokens.OpaquePrefix`, `Tokens.GenerateOpaqueToken` and `Tokens.HashOpaqueToken` configure the resulting access token. Application callbacks receive the request context and run outside the SQL transaction.
