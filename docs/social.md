# Social sign-in

Register an OAuth application at the identity provider. Set its callback to your public origin, the mounted auth path and the provider name. For example, a GitHub application serving `https://app.example.com` with the default mount uses `https://app.example.com/api/auth/callback/github`.

```go
import (
    "os"

    auth "github.com/Stonewrit/stonewrit-auth"
    "github.com/Stonewrit/stonewrit-auth/providers"
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
