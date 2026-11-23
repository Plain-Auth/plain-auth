# Authorize a browser client and exchange its code

An application can send its user to `/oauth2/authorize` and exchange the resulting code at `/oauth2/token`. Plain Auth returns an opaque bearer token bound to the user, browser session, client and approved scopes. Both endpoints mount in your existing Go server and use the `oauth-provider` database profile on SQLite, PostgreSQL or MySQL. [Register a client](oauth-client-registration.md) · [Router setup](routers.md) · [Database setup](schema.md#oauth-authorization-server-tables)

## Obtain a code in the browser

Register the application's callback URL and enable the `authorization_code` grant on both the issuer and the client. The issuer enables this grant by default. This flow supports untargeted scopes such as `reports` and `reports offline_access`. It requires the account owner's active browser session and approval covering each requested scope. Your application can host the login, signup and consent pages. An operator-managed client can use `skipConsent` to bypass a prior grant. Dynamic registration rejects `skip_consent`. Social sign-in continuation, ID tokens, sender binding and resource audiences for this grant remain on the roadmap. [Client registration](oauth-client-registration.md) · [Manage recorded approvals](oauth-consents.md) · [Feature checklist](parity/plugins/oauth-provider.md)

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

## Sign in from the authorization request

Mount the issuer in your Go server and configure the pages your application serves. Plain Auth sends a signed-out browser to `LoginPage`. A client can request fresh authentication with `prompt=login` or `max_age=0`. With `prompt=create`, the issuer uses `SignupPage` when configured and falls back to `LoginPage`. With `prompt=none`, the issuer returns an interaction error to the registered callback without opening a page.

```go
plugin, err := oauthprovider.New(oauthprovider.Options{
    Scopes: []string{"reports", "export"},
    Authorization: oauthprovider.BrowserAuthorizationOptions{
        LoginPage:   "/login",
        SignupPage:  "/signup",
        ConsentPage: "/consent",
    },
})
```

In the GET handler for each page, pass `r.URL.RawQuery` to `api.VerifyOAuthPageQuery` and return HTTP 400 on error. Pass `fields.Encode()` from the verifier to your `html/template` as the value of a hidden form field named `oauth_query`. Send `Cache-Control: no-store` and `Referrer-Policy: no-referrer` on these pages. The consent handler below uses the same verifier. The signed request preserves the client, callback, scopes, state and PKCE challenge across login.

For a password form, submit the email, password and signed field to `POST /api/auth/sign-in/email` in the same browser. This example assumes the form has named inputs for those three fields and that the host provides the error and second-factor screens.

```js
async function signIn(form) {
    const input = new FormData(form)
    const res = await fetch("/api/auth/sign-in/email", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({
            email: input.get("email"),
            password: input.get("password"),
            oauth_query: input.get("oauth_query"),
        }),
    })
    const result = await res.json()
    if (!res.ok) return showLoginError(result)
    if (result.twoFactorRedirect) return showSecondFactor(input.get("oauth_query"))
    if (result.redirect && result.url) window.location.assign(result.url)
}
```

When a second factor is required, submit the same signed field with the verification code. Follow the returned authorization URL after the server issues the login session. In a Go client with a cookie jar scoped to that user, set `client.SignInRequest.OAuthQuery` or `client.SignUpRequest.OAuthQuery`. Check `TwoFactorRedirect` before following `URL`. If signup requires email verification or automatic sign-in is disabled, show your normal completion screen and return to login when the user can authenticate.

For an explicit `prompt=create`, call `POST /api/auth/sign-up/email` with the signed field and the new account credentials. After a session is issued, the browser returns to the signup page. Verify the query on that visit, then post `{"created":true,"oauth_query":"<signed query>"}` to `/api/auth/oauth2/continue` using the same browser session. Follow its returned URL to the next step. The Go equivalent is `sdk.ContinueOAuthSignup(ctx, fields.Encode())`. Expired or altered queries require a fresh authorization request. [Login through code exchange](../conformance/oauth-browser-login.mjs) · [Session replacement and two-factor verification](../adapters/sqlstore/oauth_browser_login_test.go)

## Choose a remembered account

Set `Authorization.SelectAccount.Page` to the account chooser served by your application. An application requesting `prompt=select_account` opens this page for a signed-in browser. Combine it with `consent` to ask for approval again after selection. A signed-out browser goes through login first. Without a configured chooser page, an explicit selection prompt returns `unsupported_prompt_select_account` on the issuer's error page.

An optional host policy can prompt for selection even when the client omits the prompt. It receives the active user, session, request headers and requested scopes. For example, an issuer can ask users to confirm the account for billing access.

```go
SelectAccount: oauthprovider.AccountSelectionOptions{
    Page: "/choose-account",
    ShouldRedirect: func(_ context.Context, _ oauthprovider.RegistrationAccess, scopes []string) (bool, error) {
        return slices.Contains(scopes, "billing"), nil
    },
},
```

The issuer runs that check on the initial authorization request. A silent request that needs selection returns `account_selection_required` with the original state and issuer at the registered callback. A host policy error stops authorization. When only the callback is configured, an implicit selection uses `LoginPage`.

On the chooser page, verify `r.URL.RawQuery` using `api.VerifyOAuthPageQuery` as on the login and consent pages. When you enable the multi-session plugin, load `GET /api/auth/multi-session/list-device-sessions` in the same browser and display the remembered users by name or email. On a user gesture, send the chosen entry's `session.token` to `POST /api/auth/multi-session/set-active` as `sessionToken`. Keep session tokens out of URLs and logs. After the switch succeeds, send `{"selected":true,"oauth_query":"<verified chooser query>"}` to `POST /api/auth/oauth2/continue` in the same browser. Follow its returned URL. The Go client equivalents share one cookie jar.

```go
_, err := sdk.SetActiveSession(ctx, selected.Session.Token)
if err != nil {
    return err
}
target, err := sdk.ContinueOAuthAccountSelection(ctx, fields.Encode())
if err != nil {
    return err
}
// Send this browser to target.
```

The newly active account supplies the session and any prior consent used for code issuance. If it needs consent, the returned URL is the consent page. The issuer checks the client registration and callback again, and a removed or replaced client cannot inherit a pending choice. [Multi-session setup](multi-session.md) · [Two remembered accounts on three databases](../adapters/sqlstore/oauth_account_selection_test.go) · [Protocol and token exchange](../conformance/oauth-account-selection.mjs)

## Ask the user for consent

Set `Authorization.ConsentPage` to a page in your application and mount it alongside the auth handler. When a signed-in user first visits a client or the client asks for additional scopes, the issuer redirects to that page. An explicit `prompt=consent` opens it again, including for operator-approved clients. With `prompt=none` the client receives an interaction error. Leaving the page unset supports applications that already have approval.

```go
plugin, err := oauthprovider.New(oauthprovider.Options{
    Scopes: []string{"reports", "export"},
    Authorization: oauthprovider.BrowserAuthorizationOptions{
        ConsentPage: "/consent",
    },
})
```

On the page's GET handler, verify the query before displaying the client ID or scopes. Render the verified values through `html/template`. The following handler assumes `page` is a parsed template and `api` is the same `*plainauth.Auth` mounted on the router.

```go
mux.HandleFunc("GET /consent", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Cache-Control", "no-store")
    w.Header().Set("Referrer-Policy", "no-referrer")
    fields, err := api.VerifyOAuthPageQuery(r.URL.RawQuery)
    if err != nil {
        http.Error(w, "This approval request has expired or changed.", http.StatusBadRequest)
        return
    }
    page.Execute(w, struct{ Client, Scope, Query string }{
        fields.Get("client_id"), fields.Get("scope"), fields.Encode(),
    })
})
```

For example, bind the template values to `<p>{{.Client}} requests {{.Scope}}</p>` and `<input type="hidden" id="oauth-query" value="{{.Query}}">`. The page verifier removes unsigned page preferences, such as `theme`, before returning the signed form. From the same-origin page, call this function when the user selects **Allow** or **Deny**. Omit `scope` to approve the full request. To offer scope selection, pass the selected names joined with a space.

```js
async function decide(accept, scope) {
    const response = await fetch("/api/auth/oauth2/consent", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            accept, scope, oauth_query: document.querySelector("#oauth-query").value,
        }),
    })
    const result = await response.json()
    if (!response.ok) throw new Error(result.error_description || "Could not record consent")
    window.location.assign(result.url)
}
```

An application using the Go client can call `sdk.DecideOAuthConsent(ctx, fields.Encode(), accept, selectedScopes)` with the user’s cookie jar. It returns the destination URL. Pass `nil` for all requested scopes or an empty slice to approve zero scopes.

Approval returns a callback URL containing a single-use code. The issuer stores the selected scopes and code together. A denial returns `access_denied` and preserves earlier approval. The issuer revalidates the registered callback before sending either decision. A disabled client or removed callback sends the user to the issuer's error page. A request can be decided once, by the browser session and tenant that saw the prompt. It expires after `CodeLifetime`. Start a new authorization request if an old tab or retry reports that the decision was already used. [Browser flow and independent signature verification](../conformance/oauth-browser-authorization.mjs) · [Database rollback and concurrent decisions](../adapters/sqlstore/oauth_browser_consent_test.go)

## Configure issuance

`oauthprovider.Options.Authorization` accepts these settings. Host callbacks receive the request context and run outside database transactions.

| Setting | Behavior |
| --- | --- |
| `LoginPage` | Trusted host page for signing in or reauthenticating, such as `/login`. |
| `SignupPage` | Optional account-creation page for `prompt=create`. Defaults to the login page. |
| `SelectAccount` | Optional account chooser page and policy for initial browser authorization. |
| `ConsentPage` | Trusted host page for first-time and forced approvals, such as `/consent`. |
| `CodeLifetime` | Codes and signed interaction prompts expire after ten minutes by default. Set a positive duration in whole seconds to change it. |
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
