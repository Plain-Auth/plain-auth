# Authorize a browser client and exchange its code

An application can send its user to `/oauth2/authorize` and exchange the resulting code at `/oauth2/token`. Plain Auth returns an opaque bearer token bound to the user, browser session, client and approved scopes. Both endpoints mount in your existing Go server and use the `oauth-provider` database profile on SQLite, PostgreSQL or MySQL. [Register a client](oauth-client-registration.md) · [Router setup](routers.md) · [Database setup](schema.md#oauth-authorization-server-tables)

## Obtain a code in the browser

Register the application's callback URL and enable the `authorization_code` grant on both the issuer and the client. The issuer enables this grant by default. This flow supports untargeted scopes such as `reports` and `reports offline_access`. It requires the account owner's active browser session and approval covering each requested scope. Your application can host the login, signup and consent pages. An operator-managed client can use `skipConsent` to bypass a prior grant. Dynamic registration rejects `skip_consent`. Request the `openid` scope for a signed ID token. Sender binding and resource audiences for this grant are tracked in the roadmap. [Client registration](oauth-client-registration.md) · [Manage recorded approvals](oauth-consents.md) · [Feature checklist](parity/plugins/oauth-provider.md)

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

## Sign in with an external provider

An application can offer a configured social provider on its issuer login page. Verify the page query with `api.VerifyOAuthPageQuery` and pass its encoded fields to the normal social sign-in endpoint. An HTTP client sends the following JSON to `POST /api/auth/sign-in/social` using the login browser's cookie jar.

```json
{
  "provider": "github",
  "disableRedirect": true,
  "errorCallbackURL": "/login/retry",
  "oauth_query": "<verified login page query>"
}
```

The response contains the identity provider's authorization URL. Open it in the browser that started the request. Plain Auth keeps the signed issuer request in the shared flow store, or sealed in the state cookie with `OAuthStateCookie`, while the browser visits the provider. A successful callback issues a fresh session and rechecks the original client's request, including any required organization selection or consent. The provider's state and PKCE exchange are independent of the client application's state and PKCE exchange.

For a top-level navigation, the callback sends HTTP 302 to the next destination. An HTTP client requesting JSON receives HTTP 200 and `{"redirect":true,"url":"…"}`. Your application owns the pages and decides how to handle the destination. If the provider denies access or the token exchange fails, your trusted `errorCallbackURL` can handle the error. An expired issuer login request requires a new authorization request.

The Go SDK exposes the same field as `client.SocialSignInRequest.OAuthQuery`. A provider that supports direct ID-token sign-in also accepts its normal `idToken` object on this request. Successful verification returns the issuer's next destination. Ordinary social sign-in can omit `oauth_query` and use `callbackURL` or `newUserCallbackURL`. [Social provider setup](social.md) · [Two independent code exchanges](../conformance/oauth-social-authorization.mjs) · [Session ownership on three SQL engines](../adapters/sqlstore/oauth_social_authorization_test.go)

### Sign in through an enterprise directory

Your login page can offer an enterprise OpenID Connect directory. Send the verified login query to `POST /api/auth/sign-in/sso` using the same browser session. Select a directory by provider ID, organization slug, domain or email. Include a trusted application callback.

```json
{
  "providerId": "company",
  "callbackURL": "/account",
  "errorCallbackURL": "/login/retry",
  "oauth_query": "<verified login page query>"
}
```

Open the returned identity provider URL in that browser. Both the directory-specific and shared OIDC callbacks resume the original client request using the newly issued session. If organization selection or consent is required, a navigation receives HTTP 302 to your configured page. A JSON client receives HTTP 200 with `{"redirect":true,"url":"…"}`. Your application chooses what to display and when to follow that URL. An issuer request that expires during sign-in requires a fresh authorization request.

The Go client accepts the same field as `client.SSOSignInRequest.OAuthQuery`. Ordinary OIDC sign-in uses the application's return URLs. A SAML assertion returns to the application's `callbackURL`. [Enterprise SSO setup](sso.md#enterprise-browser-sign-in) · [End-to-end enterprise code exchanges](../conformance/oauth-enterprise-authorization.mjs)

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

## Require onboarding before authorization

A signed-in user may still need to accept terms or finish setting up a profile. Configure `Authorization.CheckSignup` to read your application's record for the active user. The issuer calls it after account selection and again when a signed interaction resumes. A client that requests `prompt=none` gets `interaction_required` at its registered callback if onboarding is required.

For example, suppose your application stores terms acceptance by user ID and version. Here `terms.Accepted` is your storage lookup and `currentVersion` is the version you require.

```go
Authorization: oauthprovider.BrowserAuthorizationOptions{
    LoginPage:   "/login",
    SignupPage:  "/signup",
    ConsentPage: "/consent",
    CheckSignup: func(ctx context.Context, a oauthprovider.RegistrationAccess, scopes []string) (*oauthprovider.SignupStep, error) {
        accepted, err := terms.Accepted(ctx, a.User.ID, currentVersion)
        if err != nil || accepted {
            return nil, err
        }
        return &oauthprovider.SignupStep{Page: "/accept-terms"}, nil
    },
},
```

Return `nil, nil` to continue. Return `&oauthprovider.SignupStep{}` for the configured signup page, with the login page as its fallback. Set `Page` to choose a specific trusted page. A lookup error stops authorization. The callback receives the current user, session, request headers and requested scopes. An approval for fewer scopes passes those chosen scopes on the next check.

In the onboarding page's GET handler, verify the signed query with `api.VerifyOAuthPageQuery`. On submission, use your application's authenticated handler to persist the user's decision. Then use the same browser session to post `{"created":true,"oauth_query":"<verified page query>"}` to `/api/auth/oauth2/continue`, or call `sdk.ContinueOAuthSignup(ctx, fields.Encode())`. Follow the returned URL. If the saved record still requires onboarding, that URL leads back to the required page.

If the policy changes while a consent screen is open, the issuer can record the user's approval for the selected scopes and return to onboarding. It consumes the consent prompt once. Code issuance waits until the check passes and the issuer revalidates the active session, client and approval. The bundled SQL adapters support this transaction. A custom store that enables interactive consent with signup or post-login checks must implement `oauthprovider.DeferredConsentStore`. [End-to-end code exchange](../conformance/oauth-signup-policy.mjs) · [Three-database tests](../adapters/sqlstore/oauth_signup_step_test.go)

## Select an organization or team after login

`Authorization.PostLogin` is an optional issuer policy for delegated authorization. The host supplies a trusted page and decides when the user needs to choose an organization or team. The page can use any language or framework. For ordinary app switching, call the organization or team JSON API directly. [Organization and team selection](organizations.md#switch-organizations-and-teams-from-any-client)

The example below uses the organization store configured by the host. It checks current memberships, asks users with multiple memberships to choose on a new authorization, and uses the selected organization as the consent reference. Return an error from the reference callback if the required membership has ended. This check also runs when approving the consent form.

```go
Authorization: oauthprovider.BrowserAuthorizationOptions{
    LoginPage: "/login", ConsentPage: "/consent",
    PostLogin: &oauthprovider.PostLoginOptions{
        Page: "/select-organization",
        ShouldRedirect: func(ctx context.Context, a oauthprovider.PostLoginContext) (bool, error) {
            groups, err := store.OrganizationsForUser(ctx, a.User.ID)
            if err != nil {
                return false, err
            }
            id := a.Session.ActiveOrganizationID
            selected := slices.ContainsFunc(groups, func(g organization.Organization) bool {
                return id != nil && g.ID == *id
            })
            return !selected || (len(groups) > 1 && !a.IsContinuation), nil
        },
    },
    ConsentReference: func(ctx context.Context, a oauthprovider.RegistrationAccess, scopes []string) (string, error) {
        id := a.Session.ActiveOrganizationID
        if id == nil {
            return "", errors.New("select an organization")
        }
        group, err := store.OrganizationForMember(ctx, a.User.ID, *id, "")
        if err != nil {
            return "", err
        }
        return group.ID, nil
    },
},
```

On the host page, verify the signed query with `api.VerifyOAuthPageQuery` and preserve `fields.Encode()` for continuation. Save the user's choice through `POST /organization/set-active` or `POST /organization/set-active-team` under the auth mount. Once it succeeds, post `{"postLogin":true,"oauth_query":"<verified page query>"}` to `/oauth2/continue` in the same session. The Go SDK equivalent is `sdk.ContinueOAuthPostLogin(ctx, fields.Encode())`. Either returns the next destination. Your client controls how to navigate there.

The explicit continuation reruns `ShouldRedirect` with `IsContinuation` set. Check the stored selection each time. A new authorization runs the policy again. For a one-request switch, a client can include `oauth_query` with the selection write itself. When that write reissues a session cookie, the issuer evaluates the policy with `IsContinuation` false. A policy that asks on every new authorization can return the selector again. A silent authorization that requires this step returns `interaction_required` to the registered callback.

After selection, the signed consent page carries proof for the current login. Submitting that page can finish consent without showing the selector again. Plain Auth checks the consent reference when saving the decision. Switching organizations in another tab cannot move an outstanding approval to the new organization. Returning a selector form to the consent endpoint asks for the remaining steps. Approval requires a signed consent form.

Returning an empty reference uses personal consent. The SQL adapters isolate personal consent from organization grants and prefer a NULL reference when both NULL and empty-string personal records exist. With a nonempty organization reference, the authorization code and its issued token retain that reference. For team-level grants, the host can validate the selected team and return its ID as the reference. [Organization flow and token exchange](../conformance/oauth-post-login.mjs) · [Session and personal-consent tests](../adapters/sqlstore/oauth_post_login_test.go)

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

When onboarding is complete, approval returns a callback URL containing a single-use code. The issuer stores the selected scopes and code together. A denial returns `access_denied` and preserves earlier approval. The issuer revalidates the registered callback before sending either decision. A disabled client or removed callback sends the user to the issuer's error page. A request can be decided once, by the browser session and tenant that saw the prompt. It expires after `CodeLifetime`. Start a new authorization request if an old tab or retry reports that the decision was already used. [Browser flow and independent signature verification](../conformance/oauth-browser-authorization.mjs) · [Database rollback and concurrent decisions](../adapters/sqlstore/oauth_browser_consent_test.go)

## Configure issuance

`oauthprovider.Options.Authorization` accepts these settings. Host callbacks receive the request context and run outside database transactions.

| Setting | Behavior |
| --- | --- |
| `LoginPage` | Trusted host page for signing in or reauthenticating, such as `/login`. |
| `SignupPage` | Optional account-creation page for `prompt=create`. Defaults to the login page. |
| `PostLogin` | Optional trusted page and host policy evaluated after signup and before consent. |
| `CheckSignup` | Recheck the host’s onboarding requirements before issuing a code for the current account and scopes. |
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

The JSON response includes `access_token`, `token_type`, `scope`, `expires_in` and `expires_at`. The access token lifetime defaults to one hour. Configure `Tokens.AccessLifetime` and use `Tokens.ScopeLifetimes` to shorten the lifetime for particular scopes. The body is served with `Cache-Control: no-store`. [Token introspection](machine-tokens.md#inspect-a-delegated-token-as-a-resource-server)

## Receive and verify an OpenID Connect ID token

Install the JWT and OAuth provider plugins on the same auth handler and apply both database profiles. Include `openid` in the issuer's and client's allowed scopes. The default signing algorithm is Ed25519 (`EdDSA`). The JWT plugin also supports `RS256`, `ES256`, `ES512` and `PS256`. The public key set defaults to `/api/auth/jwks`. [OpenID issuer discovery](oauth-issuer-discovery.md#connect-a-relying-party-using-the-issuer-url) · [JWT configuration and key rotation](jwt.md) · [Database setup](schema.md)

```go
signer, err := auth.NewJWT(auth.JWTOptions{Algorithm: "RS256"})
if err != nil {
    return err
}
issuer, err := oauthprovider.New(oauthprovider.Options{
    Scopes: []string{"openid", "profile", "email", "offline_access"},
    Tokens: oauthprovider.TokenOptions{IDTokenLifetime: 15 * time.Minute},
})
if err != nil {
    return err
}
// Include signer and issuer in auth.Options.Plugins on your existing handler.
```

Request `scope=openid` and supply a fresh random `nonce` together with state and the S256 challenge. Store all three values in the client's login session. After checking the callback's state and issuer, exchange the code with the original verifier. The token response includes a signed `id_token`. With `golang.org/x/oauth2`, retrieve it with `token.Extra("id_token").(string)` using a checked type assertion.

Use an OpenID Connect verifier in your client's language. Configure the expected issuer, client ID, allowed signing algorithm and trusted JWKS URL. Verify the signature, issuer, audience, expiry and original nonce before accepting the login. Check `at_hash` against the entire access token string returned alongside the ID token, including any configured prefix. The client's account key is the pair `(iss, sub)`. When reading UserInfo, check that its `sub` matches. A pairwise registration receives a subject derived for its redirect sector. [UserInfo](oauth-userinfo.md) · [Independent client verification](../conformance/oauth-id-tokens.mjs)

The ID token lasts ten hours by default. Set `Tokens.IDTokenLifetime` in whole seconds to override it. It includes the original authentication time when available and reports authentication context `acr: "0"`. An essential ACR request that excludes this value returns `access_denied`. The issuer includes `sid` for a live session when the client enables end-session or back-channel logout. A refresh that retains `openid` issues a new ID token with the original authentication time and a new access-token hash. The nonce belongs to the original code exchange. An offline refresh after session expiry omits `sid`.

Profile and email fields are available from UserInfo. To request individual fields, pass a JSON `claims` authorization parameter such as `{"userinfo":{"email":null,"name":null}}`. Your consent page can approve email alone by including `"claims":{"userinfo":{"email":null}}` in its consent decision. In Go, use `sdk.DecideOAuthConsentWithClaims(ctx, query, true, []string{"openid"}, []string{"email"})`. Omitting the selection retains the requested names. An empty selection declines all individually requested names. Separately approved scopes still grant their usual fields. A silent request for a previously unapproved claim returns `consent_required`.

Signing and persistence must both succeed before the issuer responds with credentials. If a signing key is temporarily unavailable, the client can retry using the same code or refresh token. A custom database adapter must implement `oauthprovider.OpenIDGrantStore` for these exchanges. [Credential retry tests on all three databases](../adapters/sqlstore/oauth_id_token_test.go)

### Add application claims to an ID token

Configure `Tokens.CustomIDTokenClaims` on the issuer. The callback runs once during each code or refresh exchange that issues an ID token. It receives the current account, the scopes approved for this exchange and the issuing client's stored metadata. A pairwise client still receives its sector-specific `sub`. The hook sees the internal account ID so your backend can look up entitlements.

For example, an issuer can expose a billing tier to clients granted `plan:read`. Declare the `tier` user attribute with `ServerOnly: true` if it controls access, enable the scope on the issuer and client, and use a claim name under a domain you control.

```go
Tokens: oauthprovider.TokenOptions{
    CustomIDTokenClaims: func(ctx context.Context, in oauthprovider.IDTokenClaimsInput) (map[string]any, error) {
        if !slices.Contains(in.Scopes, "plan:read") {
            return nil, nil
        }
        tier := in.UserFields["tier"]
        if len(tier) == 0 {
            return nil, nil
        }
        return map[string]any{"https://app.example.com/claims/plan": tier}, nil
    },
},
```

`UserFields` contains registered scalar values as `json.RawMessage`, keyed by logical field name even when the SQL name differs. It includes hidden fields for trusted server code and the stored fields contributed by this issuer's enabled plugins. `User` presents the ordinary account profile. `Metadata` contains the stored client metadata object, with raw JSON values that preserve nested data and large integers. A registration with no metadata supplies a nil map. Public client registration cannot set these operator values.

Your application chooses which claims to disclose and can consult its own membership policy using the request context. The hook receives no active organization or team selection. The library copies only the returned application claims into the ID token. The hook does not add claims to UserInfo or access tokens. Returning `nil, nil` leaves the default ID-token contents intact.

Plain Auth owns the issuer, subject, audience, time, authentication context, nonce, session and token-hash claims. The protected names are `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `auth_time`, `acr`, `amr`, `azp`, `nonce`, `sid`, `at_hash`, `c_hash` and `s_hash`. Returning any of these logs the names and discards the attempted values. An operator can explicitly add profile claims such as `email` when its disclosure policy permits.

A callback error stops issuance. Ordinary errors produce a generic HTTP 500 and reach the host's `OnAPIError` reporter. The SQL adapter runs the callback outside locks and checks the same account fields, grant and client metadata again before commit. A change during evaluation leaves the original credential usable. A subsequent refresh rereads the user's profile and uses the effective scopes, including any reduction. [Cross-runtime claim and scope checks](../conformance/oauth-id-tokens.mjs) · [Three-database failure and retry tests](../adapters/sqlstore/oauth_id_token_test.go)

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

Serialize refresh requests that share a credential. Plain Auth commits the parent revocation and both replacements together. Reuse of a rotated credential under the default policy returns `invalid_grant` and invalidates the client’s refresh tokens for that user and their linked access tokens. A failed callback or database insert rolls back the exchange and leaves the parent usable for retry. The grant currently supports untargeted bearer access. Returning a cached response inside a retry window, resource audiences and sender-bound refresh exchanges remain on the roadmap. [Token revocation](oauth-token-revocation.md) · [Feature checklist](parity/plugins/oauth-provider.md)

## Retries and replay

An incorrect verifier, client or redirect URI leaves the code usable by its original client. Plain Auth checks the current client registration, user and session before it saves the token. For offline access, it runs the application’s refresh-token callbacks outside database locks, then verifies the same code and current permissions again. Code consumption and both token inserts share one transaction. A failed insert leaves the code usable and publishes neither token.

Each code permits one successful redemption. Reusing that code as its authenticated client returns `invalid_grant` and removes stored access and refresh tokens linked to it. This also applies when two requests race. Start a fresh authorization if an exchange succeeded but the client lost the response. Other codes for the same user and client keep their own tokens. [Three-database retry and race tests](../adapters/sqlstore/oauth_authorization_code_test.go) · [Cross-runtime exchange](../conformance/oauth-authorization-code.mjs)

The verification identifier defaults to the unpadded base64url SHA-256 digest of the code. `Tokens.HashAuthorizationCode` allows applications with a custom issuer to supply a matching derivation. `Tokens.OpaquePrefix`, `Tokens.GenerateOpaqueToken` and `Tokens.HashOpaqueToken` configure the resulting access token. Application callbacks receive the request context and run outside the SQL transaction.
