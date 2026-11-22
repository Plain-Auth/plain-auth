# Social sign-in

Register an OAuth application at the identity provider. Set its callback to your public origin, the mounted auth path and the provider name. For example, a GitHub application serving `https://app.example.com` with the default mount uses `https://app.example.com/api/auth/callback/github`.

```go
import (
    "os"

    auth "github.com/Plain-Auth/plain-auth"
    "github.com/Plain-Auth/plain-auth/providers"
)

// Set SocialProviders on the same Options that configures your database,
// stable secret, public origin and handler.
social := map[string]auth.OAuthProvider{
    "github": providers.GitHub(os.Getenv("GITHUB_CLIENT_ID"), os.Getenv("GITHUB_CLIENT_SECRET")),
    "google": providers.Google(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")),
}
```

Assign `social` to `Options.SocialProviders`. Your application owns the credential environment variables in this example. Their names are configurable. A provider is enabled when the application registers its configuration. The SQLite, PostgreSQL and MySQL adapters support social sign-in. To start the flow, send a same-origin JSON request and navigate the browser to the returned authorization URL.

```js
const response = await fetch("/api/auth/sign-in/social", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ provider: "github", callbackURL: "/dashboard" }),
});
if (response.ok) {
  const { url } = await response.json();
  window.location.assign(url);
}
```

The callback issues a session cookie and redirects to `callbackURL`. You can also supply `newUserCallbackURL` for a new account or `errorCallbackURL` for a failed authorization. Redirect targets must pass the host application's configured origin checks. Each authorization carries a one-time state bound to the initiating browser and expires in ten minutes. Providers that support PKCE receive an S256 challenge.

Google sign-in verifies the ID token's signing key, issuer, audience, expiry and nonce. GitHub sign-in reads the numeric account ID and email verification status through its authenticated APIs. These providers can link a matching email when both accounts have verified it. A returning account is identified by its provider and stable subject.

For another provider, populate `auth.OAuthProvider.Config` with the provider's OAuth endpoints and scopes. Implement `Resolve` to obtain an `auth.OAuthProfile` from an authenticated provider API or a validated ID token. Supply a stable provider subject and the email verification status reported by the identity provider. Validate the supplied nonce when using an ID token. New social accounts preserve the reported verification status. Set `AllowVerifiedEmailLink` only for providers trusted to verify email ownership.

For an OpenID Connect provider, use discovery at startup. Supply the issuer from trusted application configuration.

```go
work, err := providers.OpenIDConnect(ctx, os.Getenv("WORK_OIDC_ISSUER"),
    os.Getenv("WORK_OIDC_CLIENT_ID"), os.Getenv("WORK_OIDC_CLIENT_SECRET"))
if err != nil {
    return err
}
social["work"] = work
```

To link a provider explicitly, a signed-in user can submit the same request body to `POST /api/auth/link-social`. The provider's verified email must match the current user's email. The callback checks that the initiating session is still active and keeps that session when linking succeeds.

Apple, Google, Microsoft and discovered OpenID Connect providers also accept `{ "provider": "work", "idToken": { "token": "...", "nonce": "..." } }` on the sign-in and link routes. Supply the same nonce used to request the provider's ID token. The server verifies the signature and claims, limits token age to one hour and records successful use until expiry. Direct sign-in returns `user`, `token` and `redirect: false` and sets the session cookie.

Use `providers.Names()` to enumerate the default browser providers. Use `providers.New(name, clientID, clientSecret)` for a listed provider. Callback URLs use the same stable identifier as the registration map. The catalog fixtures exercise each provider's default scopes, token client authentication, profile requests, stable account identifier and email verification mapping using local responses.

Apple requires a services ID or bundle identifier and an Apple-issued developer configuration with a signed client-secret JWT. Supply the JWT as the secret. The browser callback accepts Apple's form POST, redirects to the same callback origin, and consumes the browser's state cookie on the subsequent GET. The first authorization may include the user's display name in the form.

Microsoft uses the common Entra endpoint by default. Use `providers.Microsoft(id, secret, providers.MicrosoftOptions{TenantID: tenant})` for a tenant GUID, `organizations`, or `consumers`. Verified tokens must match the tenant issuer and account class. Set `DisableProfilePhoto` to skip the optional Microsoft Graph photo request.

The catalog covers default provider flows. Advanced provider-specific SDK parameters, custom claims mappings and scope overrides may require configuring `auth.OAuthProvider` directly.

Cognito requires a region, user pool ID and hosted sign-in domain. A public client can use an empty client secret. The optional `IdentityProvider` sets the hosted-UI identity provider.

```go
cognito, err := providers.Cognito(os.Getenv("COGNITO_CLIENT_ID"), os.Getenv("COGNITO_CLIENT_SECRET"),
    providers.CognitoOptions{
        Domain: os.Getenv("COGNITO_DOMAIN"), Region: os.Getenv("AWS_REGION"),
        UserPoolID: os.Getenv("COGNITO_USER_POOL_ID"),
    })
if err != nil {
    return err
}
social["cognito"] = cognito
```

Cognito accepts user-pool ID tokens for direct sign-in as well. Paybin uses the public issuer by default and requires a working OIDC discovery document and RSA signing keys. Use `providers.Paybin(id, secret, issuer)` for a self-hosted issuer. Twitch requests email and profile claims in a signed ID token. Both use browser authorization-code grants.

The default PayPal registration uses the sandbox. Notion requests the workspace owner's profile with the versioned API. Facebook verifies the returned access token against the configured app before reading the profile. X reads confirmed email using a second provider request. TikTok, WeChat, Reddit, Roblox and X can return a provider-specific placeholder when the service withholds email. Placeholder addresses remain unverified. VK requires the device ID on its callback. The local tests use provider response fixtures and test signing keys.

To complete sign-in while keeping the opener on its current page, use [OAuth popup sign-in](oauth-popup.md).

## User fields on social registration

On first registration, a static social provider can supply configured user attributes through `OAuthProfile.AdditionalFields`. Set this map inside the application's provider resolver after it authenticates the profile. For example, a resolver that already fetched and validated a provider identity can return its preferred locale.

```go
mapped := map[string]any{}
if identity.Locale != "" {
    mapped["locale"] = identity.Locale
}
return plainauth.OAuthProfile{
    Subject: identity.Subject, Email: identity.Email, EmailVerified: identity.EmailVerified,
    Name: identity.Name, AdditionalFields: mapped,
}, nil
```

Use the logical names from `Options.UserAdditionalFields`. The service accepts declared writable values, skips server-owned claims and fills missing fields from application defaults. A required field without a default needs a mapped value. The SQL adapter checks the field policy when creating the user and commits the profile, account link and session together. Hidden values stay in storage.

Only the resolver's explicit mapping supplies application attributes. With the default provider configuration, users manage their profiles through the authenticated update API, and a returning login reads their saved values. Custom stores that support mapped registration fields implement `OAuthRegistrationStore`. [Additional user fields](user-fields.md)

## Refresh a profile on social sign-in

Enable `OverrideUserInfoOnSignIn` on a provider whose profile should supply the current name, photo, email and mapped attributes. For example, an application can use Google Workspace as the source of employee profiles.

```go
google := providers.GoogleWithOptions(providers.GoogleOptions{
    ClientID: clientID, ClientSecret: clientSecret, HostedDomain: "example.org",
})
google.OverrideUserInfoOnSignIn = true
opts.SocialProviders = map[string]plainauth.OAuthProvider{"google": google}
```

The setting applies to authorization-code sign-in, direct ID-token sign-in and Google One Tap. A returning user keeps the local ID associated with the provider subject. A first-time link during sign-in can refresh the profile after it passes the application's verified-email linking policy. Explicit linking through `/link-social` only attaches or refreshes the credential.

The server lowercases the provider's email. For the same address, either the existing local verification or the provider's verification is sufficient. A changed address takes its verification status from the provider. An omitted name or image keeps the stored value. Mapped attributes update only when supplied, including `false`, zero and an explicit `nil` for a nullable field. Server-owned fields keep their application values, and hidden fields stay out of responses.

SQLite, PostgreSQL and MySQL commit the profile, provider credential and session in one transaction. If another user already owns the proposed email, the browser receives `profile_conflict` at its configured error callback. Direct grants return HTTP 409 with `OAUTH_PROFILE_CONFLICT`. A custom adapter implements `OAuthProfileSyncStore` to enable the same transaction. [Browser callback tests](../conformance/social-user-fields.mjs) · [SQL and native sign-in tests](../adapters/sqlstore/oauth_profile_sync_test.go)

## Require a verified email for a provider

Set `RequireEmailVerification` on each provider that needs a verified mailbox before sign-in. Configure a mail sender so users can confirm addresses the provider reports as unverified.

```go
work := providers.GitHub(clientID, clientSecret)
work.RequireEmailVerification = true
opts.SocialProviders = map[string]plainauth.OAuthProvider{"github": work}
opts.SendVerificationEmail = func(ctx context.Context, message plainauth.MailLink) error {
    return mailer.SendVerificationLink(ctx, message.User.Email, message.URL)
}
opts.SendVerificationOnSignIn = true
```

On the first unverified sign-in, the SQL adapters save the user and provider account. The browser returns to `errorCallbackURL` with `error=email_not_verified`, or to the mounted error page when that URL is omitted. Direct ID-token and Google One Tap requests receive HTTP 403 with code `EMAIL_NOT_VERIFIED`. The session table receives its first row when a sign-in satisfies the policy. A consumed ID token requires a fresh grant on retry.

By default, a provider requiring verification sends a link for a new unverified user when a mail sender is configured. Set `SendVerificationOnSignUp` to a pointer to `false` to suppress that first delivery. Set `SendVerificationOnSignIn` to `true` to resend on subsequent blocked sign-ins. The verification link uses the original trusted callback URL. A missing or failing sender leaves the account awaiting verification.

The gate checks the local user's current email and verification status. A user who confirms through the link can sign in even if the provider still reports the address as unverified. A fresh verified provider claim for the same address also satisfies the gate. With profile refresh enabled, a newly supplied address must qualify on its own. The password sign-in policy is configured independently through `Options.RequireEmailVerification`.

Custom stores implement `OAuthVerifiedEmailStore` to check the owner and issue the session in one transaction. With an OAuth proxy, the preview honors verification required by either deployment. [Delivery and browser tests](../conformance/social-user-fields.mjs) · [SQL and One Tap tests](../adapters/sqlstore/oauth_verified_email_test.go)

## Auth0, Keycloak and Okta

Set the provider's browser callback to your public auth mount followed by `/callback/` and its registration name. For example, a provider registered as `work` under the mount `/identity` uses `https://app.example.com/identity/callback/work`.

```go
work, err := providers.Keycloak(ctx, "https://id.example.com/realms/employees", clientID, clientSecret)
if err != nil {
    return err
}
opts.SocialProviders = map[string]auth.OAuthProvider{"work": work}
```

| Provider | Constructor | Tenant setting |
| --- | --- | --- |
| Auth0 | `providers.Auth0(ctx, domain, clientID, clientSecret)` | A tenant domain such as `example.us.auth0.com`, or its HTTPS origin. [Auth0 discovery](https://auth0.com/docs/get-started/applications/configure-applications-with-oidc-discovery) |
| Keycloak | `providers.Keycloak(ctx, issuer, clientID, clientSecret)` | The full realm issuer, including any installation prefix and `/realms/<realm>`. [Keycloak endpoints](https://www.keycloak.org/securing-apps/oidc-layers) |
| Okta | `providers.Okta(ctx, issuer, clientID, clientSecret)` | The organization origin or a custom authorization server issuer, such as `https://example.okta.com/oauth2/default`. [Okta authorization servers](https://developer.okta.com/docs/concepts/auth-servers/) |

Construct each provider at startup. Discovery uses its configured issuer to obtain the authorization, token, and signing-key endpoints. The default scopes are `openid profile email`. Sign-in uses PKCE and verifies the signed ID token and browser nonce before issuing a session. The integration tests exercise a custom mount and isolate each issuer using a local HTTP transport. [End-to-end tests](../providers/enterprise_oidc_test.go)

## Linked provider credentials

Find a linked account's local record ID with `GET /api/auth/list-accounts`. The following routes use that ID. HTTP callers need a live session belonging to the account owner.

| Request | Response |
| --- | --- |
| `POST /api/auth/get-access-token` with `{"accountId":"…"}` | Access token, granted scopes and any stored ID token or access-token expiry |
| `POST /api/auth/refresh-token` with the same body | Refreshed tokens, their known expiry times, the original granted scope, provider ID and local account ID |
| `GET /api/auth/account-info?accountId=…` | Provider profile, provider data and identifiers for the linked account |

Access-token and account-info reads refresh a credential within five seconds of its expiration when the account has a refresh token and the provider allows refresh. A forced refresh returns a specific error for a provider without refresh support or an account without a refresh token. Refresh calls serialize on the owned SQL row. A narrower scope returned by the provider preserves the original stored grant. Account-info reads verify the retrieved subject against the stored provider account ID.

Go services can call `GetAccessToken`, `RefreshToken` and `AccountInfo` directly. With session headers the authenticated user owns the operation. With nil headers trusted application code supplies `auth.AccountSelection{AccountID: account.ID, UserID: user.ID}`. These adapters persist credentials in SQL. Cookie-based account selection requires a separate account-cookie implementation. OIDC account info requires a provider credential that can still be validated. WeChat also requires the transient openID issued during its original code exchange. The standard account row stores the stable unionID when available, so a later WeChat account-info read may be unavailable.

## Encrypt provider credentials

Set `Options.EncryptOAuthTokens` to `true` on every instance before accepting social sign-ins to store encrypted access, refresh and ID tokens. The default is `false`. Encryption uses the configured key ring, authenticates the provider, account subject and token field, and preserves the provider's expiry and scopes for lookup. New grants and refreshed tokens use the active encryption key. Keep a retiring key available until all accounts that use it have refreshed or reauthorized. Applications continue to use the same account-selection, access, refresh and user-info APIs. [Storage and rotation tests](../adapters/sqlstore/oauth_encryption_test.go)

## Gumroad, HubSpot, Patreon, Slack and Yandex

Use the table name to construct the provider. The key you assign in `SocialProviders` determines the name sent by the client and the callback URL. Register the callback URL including your auth mount, for example `https://app.example.com/api/auth/callback/patreon`. Each registration needs an OAuth application at that provider and its own client credentials.

| Name for `providers.New` | Default permissions | Account identity |
| --- | --- | --- |
| `gumroad` | `view_profile` | Gumroad user ID. The account email is unverified. [Gumroad API](https://gumroad.com/api) |
| `hubspot` | `oauth` | HubSpot user ID. The registered email serves as both email and display name. The preset checks that the token is active, belongs to this client, and represents an access token. [HubSpot OAuth](https://developers.hubspot.com/docs/api-reference/latest/authentication/manage-oauth-tokens) |
| `patreon` | `identity[email]` | Patreon user ID. The user’s profile supplies the name, photo and email verification status. [Patreon identity API](https://docs.patreon.com/#get-api-oauth2-v2-identity) |
| `slack-oidc` | `openid profile email` | Slack subject. This preset uses PKCE by default. UserInfo supplies the email verification status and profile picture. [Slack UserInfo](https://docs.slack.dev/reference/methods/openid.connect.userInfo/) |
| `yandex` | `login:info login:email login:avatar` | Yandex ID. The default email takes precedence over the first address in the list. It is stored as unverified. [Yandex profile API](https://yandex.com/dev/id/doc/en/user-information) |

```go
patreon, err := providers.New("patreon", os.Getenv("PATREON_CLIENT_ID"), os.Getenv("PATREON_CLIENT_SECRET"))
if err != nil {
    return err
}
opts.SocialProviders = map[string]auth.OAuthProvider{"patreon": patreon}
```

The application reads these vendor credentials and passes them into the constructor. HubSpot uses its September 2026 API for token exchange and introspection. Credentials travel in the HTTPS request body. Only the mapped identity fields are returned by the account-info endpoint.

## LINE Login channels

Create a LINE Login channel and request approval for the email permission. Register the channel ID and secret with `providers.LINE`. If you operate multiple channels, assign each one a separate registration name. Register each callback with the corresponding LINE channel. For example, `line-jp` under `/identity` uses `https://app.example.com/identity/callback/line-jp`.

```go
opts.SocialProviders = map[string]auth.OAuthProvider{
    "line-jp": providers.LINE(os.Getenv("LINE_JP_CHANNEL_ID"), os.Getenv("LINE_JP_CHANNEL_SECRET")),
    "line-th": providers.LINE(os.Getenv("LINE_TH_CHANNEL_ID"), os.Getenv("LINE_TH_CHANNEL_SECRET")),
}
```

Sign-in requests `openid profile email`. When LINE issues an ID token, the handler submits it to LINE for verification and checks the issuer, channel, nonce and timestamps. An access-token-only response uses the channel’s UserInfo endpoint. The account requires a subject and email address, and the email is stored as unverified. [LINE Login API](https://developers.line.biz/en/reference/line-login/#verify-id-token)

## Single-tenant Microsoft Entra ID

Register a web application in your Microsoft Entra tenant. Pass its directory tenant GUID, application client ID and credential into `providers.MicrosoftEntraID`. Register your callback, for example `https://app.example.com/api/auth/callback/company`, in that application.

```go
company, err := providers.MicrosoftEntraID(ctx, os.Getenv("ENTRA_TENANT_ID"), os.Getenv("ENTRA_CLIENT_ID"), os.Getenv("ENTRA_CLIENT_SECRET"))
if err != nil {
    return err
}
opts.SocialProviders = map[string]auth.OAuthProvider{"company": company}
```

The preset discovers the tenant’s signing keys, requests `openid profile email`, and binds each account to the directory object ID from the signed ID token. It checks the issuer, audience, tenant, nonce and token lifetime. Microsoft Graph can fill missing name, email and picture fields when its UserInfo subject matches the signed subject. An absent email receives a stable, unverified address ending in `@microsoft-entra-id.placeholder.invalid`. An email verification flag from Graph applies only to the same email address. [Microsoft ID token claims](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference) · [Microsoft UserInfo](https://learn.microsoft.com/en-us/entra/identity-platform/userinfo)

## Control account linking

To require users to link an additional provider from an authenticated session, set `Options.DisableImplicitAccountLinking = true` on every instance performing callbacks. An existing matching mailbox then receives `account_not_linked` on a browser sign-in, including when the provider verified the email or the enterprise directory proved its domain. Have the owner sign in with their current method and call `client.LinkSocial` to add a static provider. A new mailbox can register under the normal signup policy, and an existing provider identity can still sign in. [Browser and client comparison](../conformance/social-link-policy.mjs) · [Verified enterprise domain](../adapters/sqlstore/sso_domain_test.go)

To close account linking entirely, set `Options.DisableAccountLinking = true` on each instance. Users can register with a provider or sign in with one they already linked. A browser request to attach a provider returns to the configured error callback with `unable_to_link_account`. A mobile ID-token request to attach a new identity returns `401 LINKING_NOT_ALLOWED`. The SQL adapters also allow an authenticated owner to refresh an identity they already own using a fresh ID token. An identity owned by another user returns `409 SOCIAL_ACCOUNT_ALREADY_LINKED`. Custom stores can support that refresh by implementing `auth.OAuthLinkRefreshStore` and checking the session and identity ownership together. [Mobile client tests](../oauth_signup_test.go) · [Storage tests](../adapters/sqlstore/social_test.go)

## Require explicit registration

Set `DisableImplicitSignUp` on a provider when an existing user can sign in directly but a first-time user must choose to register. Persist that choice with the initiating sign-in. The callback reads it from single-use server state. Setting `DisableSignUp` on the server or provider still closes new registrations.

```go
work := providers.GitHub(clientID, secret)
work.DisableImplicitSignUp = true
opts.SocialProviders = map[string]auth.OAuthProvider{"work": work}
```

Post `{"provider":"work","requestSignUp":true}` to `/sign-in/social` from the registration button. Omit `requestSignUp` from the returning-user button. The Go client exposes the same choice through `client.SocialSignInRequest.RequestSignUp`. Keep the browser’s state cookie through the callback.

## Request extra scopes or a login hint

Add `scopes`, `loginHint` and `additionalParams` to a sign-in or account-linking request. These values apply to that browser flow. For example, an application can defer asking for contacts until a user chooses to import them.

```json
{
  "provider": "work",
  "scopes": ["contacts"],
  "loginHint": "jo@example.org",
  "additionalParams": {"prompt": "consent", "ui_locales": "fr"},
  "disableRedirect": true
}
```

The configured scopes remain in effect. Provider support determines which hints have an effect on the consent screen. The handler owns the OAuth state, client identity, callback, response type, PKCE parameters, nonce and scope field. It rejects those names in `additionalParams`, along with client-secret fields, vendor client-ID aliases and parameters that replace the authorization request. Native applications can supply the same fields to `SignInSocial` and `LinkSocial` on the Go client.

## Sign out from an identity provider

OIDC discovery can supply an `end_session_endpoint`. For a manually registered provider, set `OAuthProvider.EndSessionEndpoint` to its HTTPS logout URL. Set `PostLogoutRedirectURI` to a trusted application return URL registered at the provider. Use `DisableProviderLogout` to keep sign-out local for an individual provider.

`POST /sign-out` revokes the current local session and clears its cookies. When the account owner has a linked provider with a logout endpoint, the response includes its URL. Pass `disableRedirect: true` to read that URL without a `Location` header. The server selects the most recently updated eligible account. A stored ID token supplies the provider hint when available. A trusted `callbackURL` overrides the configured return address, and `state` is sent to the provider with that address. Account or provider lookup failures still allow local sign-out.

```go
result, err := c.SignOutProvider(ctx, client.ProviderSignOutRequest{
    CallbackURL: "/signed-out", State: returnState, DisableRedirect: true,
})
if err != nil {
    return err
}
// When result.URL is populated, open it in the user's browser.
```

## Sign an Apple client secret in Go

For a web application, register the Services ID and the HTTPS return URL for your auth mount with Apple. For the default mount the return URL is `https://auth.example.org/api/auth/callback/apple`. Obtain the Team ID, Key ID and the Sign in with Apple private key for that application. [Apple configuration guide](https://developer.apple.com/documentation/signinwithapple/configuring-your-environment-for-sign-in-with-apple)

Use `providers.GenerateAppleClientSecret` when constructing the provider. The environment variable names below belong to the example application.

```go
clientID := os.Getenv("APPLE_CLIENT_ID")
privateKey, err := os.ReadFile(os.Getenv("APPLE_PRIVATE_KEY_FILE"))
if err != nil {
    return err
}
secret, err := providers.GenerateAppleClientSecret(providers.AppleClientSecretOptions{
    ClientID: clientID,
    TeamID: os.Getenv("APPLE_TEAM_ID"),
    KeyID: os.Getenv("APPLE_KEY_ID"),
    PrivateKeyPEM: privateKey,
    ValidFor: 30 * 24 * time.Hour,
})
if err != nil {
    return err
}
opts.SocialProviders = map[string]plainauth.OAuthProvider{
    "apple": providers.Apple(clientID, secret),
}
```

The function signs with the P-256 key from the PKCS#8 `.p8` file. The subject is the exact client ID, the issuer is the Team ID, and the audience is `https://appleid.apple.com`. The default lifetime is 180 days. Apple accepts a maximum of 15,777,000 seconds. Generate a new secret and configure your running auth instances before the previous one expires. Store both the private key and generated credential on the server. [Apple client-secret specification](https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret) · [Signature and expiry tests](../providers/apple_secret_test.go) · [Token exchange test](../providers/apple_microsoft_test.go)

### Accept a native Apple app alongside a web application

Use the Services ID for the browser and the bundle ID for directly submitted native ID tokens. A native app signs in through `POST /sign-in/social` with its Apple ID token and the nonce used for that login.

```go
apple, err := providers.AppleWithOptions(providers.AppleOptions{
    ClientID: clientID,
    ClientSecret: secret,
    AppBundleIdentifier: "org.example.mobile",
})
if err != nil {
    return err
}
opts.SocialProviders["apple"] = apple
```

For multiple native audiences, set `NativeAudiences` to their exact case-sensitive identifiers. A nonempty list replaces the bundle ID for native verification. Include the web Services ID in that list if clients also submit its tokens directly. The browser's code exchange always verifies its configured Services ID. Multiple-audience tokens must identify an authorized party that is both configured and present in the token. [Native client comparison](../conformance/apple-native.mjs) · [Browser and native audience tests](../providers/apple_audiences_test.go)
