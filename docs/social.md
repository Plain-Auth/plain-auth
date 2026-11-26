# Social sign-in

Register an OAuth application at the identity provider. Set its callback to your public origin, the mounted auth path and the provider name. For example, a GitHub application serving `https://app.example.com` with the default mount uses `https://app.example.com/api/auth/callback/github`.

```go
import (
    "os"

    auth "github.com/Plain-Org/plain-auth"
    "github.com/Plain-Org/plain-auth/providers"
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

A callback whose state cannot be used redirects to the error page, `ErrorRedirectURL` or `<mount>/error`, with an `error` code: `state_not_found` when the callback has no state, `state_mismatch` when no flow matches it in this browser (a missing, expired or already used state, another tab's sign-in, or a changed session), and `state_invalid` when a sealed state cookie cannot be opened. `errorCallbackURL` is not used until the state is verified, so nothing in the request chooses where the browser goes. A repeated `state`, `code` or `error` parameter answers 400 `VALIDATION_ERROR`, and a store failure still answers 500 and reaches `OnAPIError`. A provider's form-post callback is forwarded to this check unchanged. [State failure tests](../conformance/oauth-callback-state.mjs)

Once the state is verified, every failure returns the browser to `errorCallbackURL`, or to the error page when the sign-in gave none. A provider that answers with an `error` has its `error` and `error_description` passed through unchanged. A callback without a code receives `no_code`, and a code the provider refuses receives `invalid_code`. A profile that cannot be read, or has no usable subject or a malformed email, receives `unable_to_get_user_info`, and a profile without an email receives `email_not_found`, on a link as well. No failure issues a session. [Callback error tests](../conformance/goapi/oauth_callback_errors_test.go)

Server-side requests to a provider, the token exchange, refresh, profile, discovery and signing-key requests, do not follow redirects, so a provider endpoint cannot steer them to another address. [Redirect test](../providers/redirects_test.go)

Google sign-in verifies the ID token's signing key, issuer, audience, expiry and nonce. `GoogleWithOptions` sends `include_granted_scopes=true` unless `DisableIncludeGrantedScopes` is set, and `AccessType` and `Display` as `access_type` and `display`; `AccessType: "offline"` with `prompt=select_account consent` asks for a refresh token every time. `AdditionalClientIDs` lists the app's other Google client IDs, such as its iOS and Android ones: a directly submitted ID token or One Tap credential may name any of them as its audience, while the code exchange uses `ClientID` and its secret. An authorized party (`azp`), when a token has one, must be a listed ID, so list every platform's ID; an Android token names the web ID as audience and the Android ID as authorized party. [Google option tests](../providers/google_test.go) GitHub sign-in reads the numeric account ID and email verification status through its authenticated APIs, sends the client secret in the token form and no nonce. A GitHub App needs the read-only "Email addresses" permission: without it only a public email is available, unverified, and a user without one gets `error=email_not_found`. GitHub returns no refresh token or expiry for OAuth apps, so the access token is kept as it is and `/refresh-token` answers `REFRESH_TOKEN_NOT_FOUND`. [GitHub tests](../providers/provider_flows_test.go) These providers can link a matching email when both accounts have verified it. A returning account is identified by its provider and stable subject.

For another provider, populate `auth.OAuthProvider.Config` with the provider's OAuth endpoints and scopes. Implement `Resolve` to obtain an `auth.OAuthProfile` from an authenticated provider API or a validated ID token. Supply a stable provider subject and the email verification status reported by the identity provider. Validate the supplied nonce when using an ID token. New social accounts preserve the reported verification status. Set `AllowVerifiedEmailLink` only for providers trusted to verify email ownership.

The provider returns the browser to `{BaseURL}{BasePath}/callback/{id}`. To register another address, set `Config.RedirectURL` to an absolute HTTP or HTTPS URL. The authorization request and the code exchange both send it, and your application must forward that route to the callback, keeping the query. [Redirect URL tests](../conformance/goapi/oauth_redirect_uri_test.go)

For an OpenID Connect provider, use discovery at startup. Supply the issuer from trusted application configuration.

```go
work, err := providers.OpenIDConnect(ctx, os.Getenv("WORK_OIDC_ISSUER"),
    os.Getenv("WORK_OIDC_CLIENT_ID"), os.Getenv("WORK_OIDC_CLIENT_SECRET"))
if err != nil {
    return err
}
social["work"] = work
```

If your application also acts as an OAuth issuer, the host login page can pass its verified `oauth_query` through social sign-in. The external identity provider authenticates the user. Plain Auth then resumes the requesting client's authorization using the new session. [Social sign-in during authorization](oauth-authorization-code.md#sign-in-with-an-external-provider)

To link a provider explicitly, a signed-in user can submit the same request body to `POST /api/auth/link-social`. The provider's email must match the current user's email and be verified by the provider, unless the provider is trusted. The callback checks that the initiating session is still active and keeps that session when linking succeeds: a session revoked before the provider redirects back fails with `unable_to_link_account`. The link is bound to the browser's session cookie, so a browser that signed out before the callback fails earlier, with `state_mismatch` at the error page, without exchanging the provider's code. [Link session tests](../adapters/sqlstore/oauth_link_session_test.go) A failed browser link returns to the error callback, or to the error page when none was given, with `unable_to_link_account`, `email_does_not_match` or `account_already_linked_to_different_user`, checked in that order. Re-linking an identity the user already owns goes through the same checks and then refreshes its credential. An ID-token link first refreshes an identity the user owns or refuses one another user owns with `409 SOCIAL_ACCOUNT_ALREADY_LINKED`, then returns `401 LINKING_NOT_ALLOWED` or `401 LINKING_DIFFERENT_EMAILS_NOT_ALLOWED`.

Apple, Google, Microsoft and discovered OpenID Connect providers also accept `{ "provider": "work", "idToken": { "token": "...", "nonce": "..." } }` on the sign-in and link routes. Supply the same nonce used to request the provider's ID token. The server verifies the signature and claims, limits token age to one hour and records successful use until expiry. Direct sign-in returns `user`, `token` and `redirect: false` and sets the session cookie.

Use `providers.Names()` to enumerate the default browser providers. Use `providers.New(name, clientID, clientSecret)` for a listed provider. Callback URLs use the same stable identifier as the registration map. The catalog fixtures exercise each provider's default scopes, token client authentication, profile requests, stable account identifier and email verification mapping using local responses.

A preset is plain data that you can change before adding it to `Options.SocialProviders`. Replacing `VerifyIDToken` replaces the preset's own key check: the function receives the raw token and the client's nonce, and an error answers 401 `INVALID_TOKEN` without a session. A verified token whose profile has no email answers 401 `USER_EMAIL_NOT_FOUND`. Replacing `Config.Scopes` drops the preset's default scopes, and `AuthorizationParams` is added to every sign-in and link authorization URL. Set a value with `p.AuthorizationParams.Set("prompt", "select_account consent")`: replacing the map drops a preset's own parameters, such as Google's `include_granted_scopes` and `hd`. A call's `additionalParams` override them. [Preset option tests](../conformance/goapi/provider_contract_test.go)

To require the browser flow for a provider on the social routes, set `provider.DisableIDTokenSignIn = true` before adding it to `Options.SocialProviders`. Both `POST /sign-in/social` and an authenticated `POST /link-social` then return HTTP 404 with `ID_TOKEN_NOT_SUPPORTED` when the client submits an ID token. Browser sign-in and linking still use the provider's configured callback. Google One Tap has its own plugin and challenge verification. [Signed-token comparisons](../conformance/apple-native.mjs) · [Browser callback tests](../conformance/goapi/oauth_signup_test.go)

Apple requires a services ID or bundle identifier and an Apple-issued developer configuration with a signed client-secret JWT. Supply the JWT as the secret. The browser callback accepts Apple's form POST, redirects to the same callback origin, and consumes the browser's state cookie on the subsequent GET. The first authorization may include the user's display name in the form.

Microsoft uses the common Entra endpoint by default. Use `providers.Microsoft(id, secret, providers.MicrosoftOptions{TenantID: tenant})` for a tenant GUID, `organizations`, or `consumers`. Verified tokens must match the tenant issuer and account class. `Authority` selects another sign-in origin, such as `https://<tenant-id>.ciamlogin.com` for External ID with the tenant GUID as `TenantID`, or a sovereign cloud; it must be a secure origin with no path. `AdditionalClientIDs` lists other client IDs a directly submitted ID token may name as its audience, while the code exchange uses the client ID. `HTTPClient` fetches the signing keys, the token endpoint and the photo. The profile photo is fetched from Microsoft Graph at `ProfilePhotoSize` pixels (48, the default, or 64, 96, 120, 240, 360, 432, 504 or 648, checked when the provider is built), without following redirects, and stored as a data URI of at most 1 MiB; larger photos are left out. Set `DisableProfilePhoto` to skip the request, or wrap the preset's `Resolve` to store the image elsewhere or clear it before it reaches the user row. [Microsoft option tests](../providers/microsoft_test.go)

The catalog covers default provider flows. Some presets also have a constructor with options:

| Constructor | Options |
| --- | --- |
| `providers.GitLab(id, secret, providers.GitLabOptions{Issuer: "https://gitlab.company.com"})` | A self-managed instance, optionally under a path; https only. Empty uses gitlab.com |
| `providers.Salesforce(id, secret, providers.SalesforceOptions{...})` | `Sandbox` uses test.salesforce.com; `LoginURL`, a bare My Domain host, wins over it |
| `providers.PayPal(id, secret, providers.PayPalOptions{Live: true})` | The live endpoints instead of the sandbox |
| `providers.Discord(id, secret, providers.DiscordOptions{Permissions: 8})` | Bot permissions, sent only when the `bot` scope is requested; zero sends none |
| `providers.Dropbox(id, secret, providers.DropboxOptions{AccessType: "offline"})` | `token_access_type`: offline, online or legacy |
| `providers.Facebook(id, secret, providers.FacebookOptions{Fields: []string{"birthday"}, ConfigID: "..."})` | More Graph profile fields, and a Login for Business `config_id` |
| `providers.Reddit(id, secret, providers.RedditOptions{Duration: "permanent"})` | `duration`, permanent for a refresh token |

`GitLab` and `Salesforce` return an error for a URL they cannot use. A call's `additionalParams` override the parameters these options send. Other provider-specific parameters, custom claims mappings and scope overrides may require configuring `auth.OAuthProvider` directly. [Preset option tests](../providers/catalog_options_test.go)

Cognito requires a region, user pool ID and hosted sign-in domain. A public client can use an empty client secret; set `RequireClientSecret` to refuse an app client configured without one. The optional `IdentityProvider` sets the hosted-UI identity provider, and a call's `additionalParams` can override it. Extra scopes such as `phone` or `aws.cognito.signin.user.admin` can be added to `Config.Scopes`. [Cognito tests](../providers/provider_flows_test.go)

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

The default PayPal registration uses the sandbox; `providers.PayPal` with `Live` uses the live endpoints. Notion requests the workspace owner's profile with the versioned API. Facebook verifies the returned access token against the configured app before reading the profile. X reads confirmed email using a second provider request. TikTok, WeChat, Reddit, Roblox and X can return a provider-specific placeholder when the service withholds email. Placeholder addresses remain unverified. VK requires the device ID on its callback. The local tests use provider response fixtures and test signing keys.

To complete sign-in while keeping the opener on its current page, use [OAuth popup sign-in](oauth-popup.md).

## Keep OAuth state in a cookie

A browser sign-in waits for the provider's callback in a flow: its PKCE verifier, nonce, callbacks and the binding to the browser and session that started it. By default the flow is stored through `OAuthFlowStore`, and the callback consumes it once. Set `Options.OAuthStateStrategy` to `plainauth.OAuthStateCookie` to seal the whole flow into the `oauth_state` cookie instead, so no flow is written:

```go
opts.OAuthStateStrategy = plainauth.OAuthStateCookie
```

The cookie is encrypted with the key ring, bound to its URL state and to the browser and session that started the flow, and expires after ten minutes. Enterprise SSO flows keep theirs in `sso_state`, or in the SameSite=None `saml_state` for a SAML form post. The store must still implement `OAuthIdentityStore`; `OAuthFlowStore` is needed only for the database strategy. A flow too large for one cookie, such as one with a very long callback, is refused with a 400.

The callback expires the cookie, but unlike a stored flow a copy captured before then stays valid for the rest of its ten minutes. In the browser that signed in the replay fails, because the session changed. Elsewhere it reaches the provider, whose single-use authorization code refuses it, so rely on providers that enforce single-use codes. The OAuth proxy's preview completion has no provider round trip: within its `MaxAge` window, a captured preview cookie and completion URL can be replayed, so keep the database strategy for proxied previews. Sign-out ends a sealed social or enterprise flow that is in progress. Changing the strategy, or the key ring without the old key, drops flows that are in progress, so switch every instance together: after a switch to the cookie strategy or a key ring without the old key they answer `state_invalid`, and after a switch back to the database strategy `state_mismatch`. [Strategy tests](../conformance/goapi/oauth_state_test.go) · [Enterprise test](../adapters/sqlstore/sso_state_cookie_test.go)

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

To copy the provider's profile only when an identity is linked, set `Options.UpdateUserInfoOnLink = true` instead. A link through `/link-social`, including a re-link of an identity the user owns, and a sign-in that links a new identity by email then copy the provider's name, image and writable mapped attributes. The email and its verification never change. A profile that fails validation still links and copies nothing, and a returning sign-in copies nothing. [Browser comparison](../conformance/social-link-options.mjs) · [User field tests](../adapters/sqlstore/oauth_link_profile_test.go)

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

By default, a returning social sign-in saves each fresh access token, refresh token, ID token and expiry the provider supplies. The account keeps the previous value for an omitted field. To keep the original credentials through routine sign-ins, set `Options.DisableAccountUpdateOnSignIn = true`. The first grant is still stored. Returning users receive sessions under the usual verification policy, and providers can still synchronize the user's profile. With a custom store, honor `OAuthLoginOptions.DisableAccountUpdateOnSignIn` when updating an existing provider account. [Credential policy tests](../adapters/sqlstore/oauth_account_update_test.go)

To expand a grant, have the signed-in owner call `linkSocial` with the additional scopes. An approved callback saves the new credentials and appends newly granted scopes to the account in provider order. Ordinary sign-ins keep the recorded scope list. Explicit token refresh also works with either sign-in policy. [Browser sign-in and relinking tests](../conformance/social-user-fields.mjs)

Find a linked account's local record ID with `GET /api/auth/list-accounts`. The following routes use that ID. HTTP callers need a live session belonging to the account owner.

| Request | Response |
| --- | --- |
| `POST /api/auth/get-access-token` with `{"accountId":"…"}` | Access token, granted scopes and any stored ID token or access-token expiry |
| `POST /api/auth/refresh-token` with the same body | Refreshed tokens, their known expiry times, the original granted scope, provider ID and local account ID |
| `GET /api/auth/account-info?accountId=…` | Provider profile, provider data and identifiers for the linked account |

Access-token and account-info reads refresh a credential within five seconds of its expiration when the account has a refresh token and the provider allows refresh. A forced refresh returns a specific error for a provider without refresh support or an account without a refresh token. Refresh calls serialize on the owned SQL row. A narrower scope returned by the provider preserves the original stored grant. Account-info reads verify the retrieved subject against the stored provider account ID.

Go services can call `GetAccessToken`, `RefreshToken` and `AccountInfo` directly. With session headers the authenticated user owns the operation. With nil headers trusted application code supplies `auth.AccountSelection{AccountID: account.ID, UserID: user.ID}`. These adapters persist credentials in SQL. OIDC account info requires a provider credential that can still be validated. WeChat also requires the transient openID issued during its original code exchange. The standard account row stores the stable unionID when available, so a later WeChat account-info read may be unavailable.

Set `Options.StoreAccountCookie` to select the account a browser signed in with instead of passing `accountId`: a social, ID-token, One Tap or SSO sign-in then sets a sealed `account_data` cookie naming that provider account, and the three routes accept `useAccountCookie: true` (or `?useAccountCookie=true`). The cookie works only for the user who signed in, and only while that account is still linked. It names the account; its tokens stay in the store, so refreshes still serialize on the stored row and an unlinked account's tokens are never served from a cookie. It lasts as long as `SessionCookieCache.MaxAge`, or five minutes. Over HTTP, a token refresh of the account the cookie selected re-issues it with a fresh lifetime, and so does a session cache re-issued for the same user; a session cache re-issued for another user expires it. Reads that refresh nothing, and refreshes selected by `accountId`, leave it alone. It is not set when linking an account, and sign-out expires it. A direct Go call reads it from the headers it passes and does not renew it. [Account cookie tests](../conformance/goapi/account_cookie_test.go)

## Store fields on a linked account

Use account fields for attributes that belong to one provider identity. For example, a user can have a different provider email on each linked account. Declare the columns in your SQL schema, then pass the same declarations to the auth instance.

```go
fields := map[string]auth.AccountField{
    "providerEmail": {Type: auth.FieldString, Column: "provider_mail"},
    "directoryNote": {Type: auth.FieldString, Hidden: true},
    "ownerClass":    {Type: auth.FieldString, ServerOnly: true, Default: "member"},
}
store, err := sqlstore.OpenWithAdditionalFields(ctx, "postgres", dsn, nil, schema.AdditionalFields{Account: fields})
if err != nil {
    return err
}
opts.Store = store
opts.AccountAdditionalFields = fields
work.GetAccountFields = func(ctx context.Context, grant auth.OAuthAccountFieldInput) (map[string]any, error) {
    return map[string]any{"providerEmail": grant.Profile.Email}, nil
}
opts.SocialProviders = map[string]auth.OAuthProvider{"work": work}
```

`GetAccountFields` runs after the provider verifies a browser authorization or a direct ID token. The SQL adapter saves accepted values when it creates or links an account. Returning sign-ins update supplied fields unless `DisableAccountUpdateOnSignIn` is enabled. An explicit link can update them under either policy. Omit a key to preserve its current value. Return a present `nil` to clear a nullable column.

Map keys use logical field names. The mapper can set declared writable fields. Account IDs, user IDs, provider IDs, credentials and other core columns are protected. `ServerOnly` fields can receive application defaults. `Hidden` fields are stored and omitted from the account list. Public fields appear at the top level of each item in `GET /list-accounts` and under `LinkedAccount.AdditionalFields` in the Go client.

Use `Options.AccountFieldRules` to validate or transform individual fields. A validator checks the normalized scalar returned by the provider. A transform runs when the adapter writes the field, including creation defaults. A validation or transform error rolls back the account and session write. Password and wallet accounts apply creation defaults too. Choose nullable fields or supply defaults for accounts that receive no provider mapping.

Browser exchanges pass the provider's tokens to the hook. Read a provider-specific response field with `grant.ExchangedToken.Extra("field_name")`. Direct sign-in passes the verified ID token in `grant.Tokens`. Optional access and refresh strings sent by the native client are separately available as `ClientAccessToken` and `ClientRefreshToken`. Their ownership has not been verified. One Tap and the OAuth proxy apply ordinary account defaults without calling the provider mapper. [Schema and CLI configuration](schema.md#configure-user-session-and-account-fields) · [Signed-token comparisons](../conformance/apple-native.mjs) · [Browser linking and rollback](../conformance/account-fields.mjs) · [Three-engine storage tests](../adapters/sqlstore/account_fields_test.go)

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

### Trusted providers and different emails

By default, a sign-in links to an existing user only when the provider verified the email and the provider sets `AllowVerifiedEmailLink`. To link a provider whose emails you trust even when it does not mark them verified, list it in `Options.TrustedProviders`:

```go
opts.TrustedProviders = []string{"google", "work"}
```

A sign-in from a trusted provider then links to an existing user with the same email, and a signed-in user can link it through `/link-social`. The local user's email must still be verified, and trust never marks an email as verified. To choose the list per request, for example per tenant, set `Options.TrustedProvidersForRequest` instead. It receives a copy of the request without its body, and an error, such as an `*auth.APIError`, fails the sign-in. SSO providers are never trusted by name, and registering an SSO provider ID that is on the list fails. Trusting a provider that does not own its users' addresses lets anyone who registers that email there take over the account.

Set `Options.AllowDifferentEmails` to let a signed-in user link an identity whose email differs from their own. The user's email does not change. Whoever controls that provider account can then sign in as this user, so enable it only when users understand that. [Browser comparison](../conformance/social-link-options.mjs) · [Storage tests](../adapters/sqlstore/oauth_link_options_test.go) · [Per-request trust tests](../conformance/goapi/oauth_link_options_test.go)

To close account linking entirely, set `Options.DisableAccountLinking = true` on each instance. Users can register with a provider or sign in with one they already linked. A browser request to attach a provider returns to the configured error callback with `unable_to_link_account`. A mobile ID-token request to attach a new identity returns `401 LINKING_NOT_ALLOWED`. The SQL adapters also allow an authenticated owner to refresh an identity they already own using a fresh ID token. An identity owned by another user returns `409 SOCIAL_ACCOUNT_ALREADY_LINKED`. Custom stores can support that refresh by implementing `auth.OAuthLinkRefreshStore` and checking the session and identity ownership together. [Mobile client tests](../conformance/goapi/oauth_signup_test.go) · [Storage tests](../adapters/sqlstore/social_test.go)

## Require explicit registration

Set `DisableImplicitSignUp` on a provider when an existing user can sign in directly but a first-time user must choose to register. Persist that choice with the initiating sign-in. The callback reads it from the sign-in's flow state. Setting `DisableSignUp` on the server or provider still closes new registrations.

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

## Pass application data through the flow

Send `additionalData` with `/sign-in/social` or `/link-social` to carry your own values, such as an invitation or the page the user came from, to the callback. On the Go client it is `SocialSignInRequest.AdditionalData`. It must be a JSON object of up to 8 KiB; anything else answers 400 `VALIDATION_ERROR`. With `OAuthStateCookie` the whole flow must also fit in the state cookie. The data is kept only for that browser flow; an ID-token request carries none.

The names the flow's own state uses are dropped: `callbackURL`, `codeVerifier`, `errorURL`, `newUserURL`, `expiresAt`, `oauthState`, `link`, `requestSignUp`, `idTokenNonce` and `serverContext`. A browser cannot change the destinations, the PKCE verifier, the link target or the expiry this way.

During the callback, read the data with `plainauth.OAuthAdditionalData(ctx)` in the provider's exchange and profile callbacks, in `ValidateUserInfo` and in database hooks. In an after hook on the callback, read it from the hook's request:

```go
plainauth.EndpointHook{
	Match: func(c *plainauth.HookContext) bool { return c.Path == "/callback/:id" },
	Run: func(c *plainauth.HookContext) error {
		if invitedBy, ok := plainauth.OAuthAdditionalData(c.Request.Context())["invitedBy"].(string); ok {
			c.Auth.Logger().Info("invited sign-in", "invitedBy", invitedBy)
		}
		return nil
	},
}
```

The values are browser input: check them before you act on them, and do not change the map. Numbers come back as `float64`. Values the server derives itself belong in the [server context](#carry-server-data-through-the-flow) rather than in `additionalData`. [Additional data tests](../conformance/goapi/oauth_additional_data_test.go)

## Read the flow's state in hooks

`plainauth.OAuthStateFrom(ctx)` returns what hooks may read of a browser sign-in or link flow:

| Field | Meaning |
| --- | --- |
| `CallbackURL`, `NewUserURL`, `ErrorURL` | The destinations the start chose. During the callback of a redirect flow, `ErrorURL` is where a failure returns: the error page when the start chose none. A popup flow posts its failures to the opener instead |
| `LinkUserID` | The user `/link-social` links the provider account to, or empty for a sign-in |
| `RequestSignUp` | Whether the start asked to create an account |
| `ExpiresAt` | When the flow expires, ten minutes after it started |
| `AdditionalData` | The browser's `additionalData`: untrusted input |
| `ServerContext` | What hooks added before the flow started; see below |

The start has the state once it has built its flow, so after hooks on `/sign-in/social`, `/link-social` and `/oauth-popup/start` read it through `c.Request.Context()`. The callback has it once it has read the flow: in the provider's `ExchangeCode`, `Resolve` and `GetAccountFields`, in `ValidateUserInfo` and the database hooks, and in after hooks on `/callback/:id`. It reports false in before hooks, in the verification delete hooks that spend the flow, for an ID-token sign-in, which starts no flow, and on the OAuth proxy's production instance. The state leaves out the flow's secrets: the PKCE verifier, the nonce and the browser binding; a provider's `ExchangeCode` receives the verifier. A link names its target by user ID; read the user for its current email. Values a plugin keeps for its own flow are not in `ServerContext`. Do not change the maps. [Flow state tests](../conformance/goapi/oauth_flow_state_test.go)

## Carry server data through the flow

A before hook on `/sign-in/social`, `/link-social` or `/oauth-popup/start` can keep values the server derives with the flow, and read them back on the callback:

```go
opts.Hooks.Before = append(opts.Hooks.Before, plainauth.EndpointHook{
	Match: func(c *plainauth.HookContext) bool { return c.Path == "/sign-in/social" },
	Run: func(c *plainauth.HookContext) error {
		c.AddOAuthServerContext(map[string]any{"tenantID": tenantID(c.Request.Context())})
		return nil
	},
})
opts.Hooks.After = append(opts.Hooks.After, plainauth.EndpointHook{
	Match: func(c *plainauth.HookContext) bool { return c.Path == "/callback/:id" },
	Run: func(c *plainauth.HookContext) error {
		if state, ok := plainauth.OAuthStateFrom(c.Request.Context()); ok {
			tenant, _ := state.ServerContext["tenantID"].(string)
			_ = tenant // use it
		}
		return nil
	},
})
```

Calls merge, and a later value for a key replaces an earlier one. The values are kept as JSON, so numbers come back as `float64`, and a value JSON cannot encode fails the start: `/sign-in/social` and `/link-social` answer 500, and `/oauth-popup/start` shows the `popup_sign_in_failed` page and logs the cause. The database strategy stores them as plain JSON in the flow's verification row, so keep secrets out; with `OAuthStateCookie` the whole flow, values included, must fit the sealed cookie. The browser can neither read nor set the values, and a `serverContext` it sends is ignored. An ID-token sign-in keeps none. Behind the OAuth proxy the preview keeps the values with its own flow, and production never receives them. [Flow state tests](../conformance/goapi/oauth_flow_state_test.go) · [OAuth proxy tests](../adapters/sqlstore/oauth_proxy_test.go)

`/link-social` checks its body first, then the caller's session, then the provider, so an anonymous request for an unknown provider answers 401 `UNAUTHORIZED`. A provider subject that is blank, or the placeholder `null` or `undefined`, cannot name an account: an ID-token sign-in or link answers 401 `FAILED_TO_GET_USER_INFO`, and a browser callback receives `unable_to_get_user_info`. [Link contract test](../conformance/goapi/provider_contract_test.go)

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
