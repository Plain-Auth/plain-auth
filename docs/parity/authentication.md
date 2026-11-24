# Authentication

[Feature index](README.md)

## Apple

- [ ] Apple
  - [ ] Get your OAuth credentials
    - [ ] Navigate to Certificates, Identifiers & Profiles:
    - [ ] Create an App ID:
    - [ ] Create a Service ID:
    - [ ] Identifier: Set a unique identifier for the service. Use a reverse domain format, distinct from your App ID (e.g., `com.yourcompany.yourapp.si`, where `.si` indicates service identifier - this is for your organization and not required). This Service ID will be your `clientId`.
    - [ ] Configure the Service ID:
    - [ ] Create a Client Secret Key:
    - [x] Generate the Client Secret (JWT): ([test](../../providers/apple_secret_test.go#L30))
      - [x] Sign the case-sensitive client ID and Apple audience with a PKCS#8 P-256 developer key and verify expiry bounds ([test](../../providers/apple_secret_test.go#L30))
  - [ ] Configure the provider
    - [ ] Localhost and Non-TLS Restrictions
  - [ ] Usage
    - [ ] Sign In with Apple
      - [ ] `provider`
    - [ ] Sign In with Apple With ID Token
  - [x] Generate Apple Client Secret (JWT) ([test](../../providers/apple_secret_test.go#L30))
    - [x] Sign the case-sensitive client ID and Apple audience with a PKCS#8 P-256 developer key and verify expiry bounds ([test](../../providers/apple_secret_test.go#L30))
    - [x] Use the generated assertion during a local Apple authorization code exchange ([test](../../providers/apple_microsoft_test.go#L65))

## Atlassian

- [ ] Atlassian
  - [ ] Get your Credentials
  - [ ] Configure the provider
  - [ ] Sign In with Atlassian
    - [ ] `provider`

## Cloudflare

- [ ] Cloudflare
  - [ ] Get your Cloudflare credentials
  - [ ] Configure the provider
  - [ ] Usage
    - [ ] Sign in with Cloudflare
  - [ ] Options
    - [ ] Scopes
    - [ ] Token authentication method
    - [ ] Clients without a secret
    - [ ] Client visibility
    - [ ] Refresh tokens
    - [ ] Profile and email verification

## Cognito

- [ ] Cognito
  - [ ] Get your Cognito Credentials
  - [ ] Configure the provider
  - [ ] Sign In with Cognito
  - [ ] Additional Options:
    - [ ] `scope`
    - [ ] `openid`
    - [ ] `profile`
    - [ ] `email`
    - [ ] `phone`
    - [ ] `aws.cognito.signin.user.admin`
    - [ ] `getUserInfo`
    - [ ] `identityProvider`
    - [ ] `refreshAccessToken`
  - [ ] Refresh tokens

## Discord

- [ ] Discord
  - [ ] Get your Discord credentials
  - [ ] Configure the provider
  - [ ] Usage
    - [ ] Sign In with Discord
      - [ ] `provider`
  - [ ] Options
    - [ ] Bot Permissions (Optional)

## Dropbox

- [ ] Dropbox
  - [ ] Get your Dropbox credentials
  - [ ] Configure the provider
  - [ ] Sign In with Dropbox
    - [ ] `provider`

## Email & Password

- [ ] Email & Password
  - [x] Enable Email and Password ([test](../../conformance/email-password-options.mjs#L77))
    - [x] With EmailAndPassword off, both runtimes refuse registration and existing-credential sign-in ([test](../../conformance/email-password-options.mjs#L77))
  - [ ] Usage
    - [ ] Sign Up
      - [x] Create a password account and return a usable session token on SQLite ([test](../../conformance/core.test.mjs#L193))
      - [x] `POST /sign-up/email` ([test](../../conformance/goapi/http_test.go#L71))
        - [x] An HTTP POST to sign-up/email with name, email and password returns 200 ([test](../../conformance/goapi/http_test.go#L71))
        - [x] Parameter `name` ([test](../../conformance/existing-signup.mjs#L67))
          - [x] On both runtimes, the stored owner created through sign-up carries the submitted name ([test](../../conformance/existing-signup.mjs#L67))
        - [x] Parameter `email` ([test](../../conformance/core.test.mjs#L194))
          - [x] The sign-up response user has the submitted email, compared against the reference ([test](../../conformance/core.test.mjs#L194))
        - [x] Parameter `password` ([test](../../conformance/email-password-options.mjs#L39))
          - [x] Sign-up enforces the default 8/128 bounds (and configured ones) on the password on both runtimes ([test](../../conformance/email-password-options.mjs#L39))
        - [x] Parameter `image` (optional) ([test](../../conformance/existing-signup.mjs#L68))
          - [x] On both runtimes, the image submitted at sign-up is persisted on the stored owner ([test](../../conformance/existing-signup.mjs#L68))
        - [x] Parameter `callbackURL` (optional) ([test](../../conformance/goapi/account_lifecycle_test.go#L41))
          - [x] A sign-up CallbackURL (via the native SignUpEmail RequestMeta) becomes the verification link's redirect target ([test](../../conformance/goapi/account_lifecycle_test.go#L41))
    - [ ] Sign In
      - [x] Reject the wrong password and issue a fresh session for valid credentials ([test](../../conformance/core.test.mjs#L202))
      - [x] `POST /sign-in/email` ([test](../../conformance/goapi/http_test.go#L77))
        - [x] An HTTP POST to sign-in/email returns 200 with a token, session cookies and redirect fields ([test](../../conformance/goapi/http_test.go#L77))
        - [x] Parameter `email` ([test](../../conformance/core.test.mjs#L203))
          - [x] Signing in with the registered email resolves to the same user ID the sign-up created ([test](../../conformance/core.test.mjs#L203))
        - [x] Parameter `password` ([test](../../conformance/core.test.mjs#L1419))
          - [x] A wrong password is rejected with INVALID_EMAIL_OR_PASSWORD on each runtime ([test](../../conformance/core.test.mjs#L1419))
        - [x] Parameter `rememberMe` (optional) ([test](../../conformance/goapi/http_test.go#L83))
          - [x] rememberMe:false issues a session cookie with no Max-Age plus a dont_remember marker cookie ([test](../../conformance/goapi/http_test.go#L83))
        - [x] Parameter `callbackURL` (optional) ([test](../../conformance/goapi/http_test.go#L79))
          - [x] A sign-in callbackURL sets the Location header and returns redirect:true with the url in the body ([test](../../conformance/goapi/http_test.go#L79))
    - [x] Sign Out ([test](../../conformance/core.test.mjs#L206))
      - [x] Clear the client's session cookies and return an anonymous session ([test](../../conformance/core.test.mjs#L206))
      - [x] The released client's signOut returns success, and getSession afterwards is anonymous, matching the reference ([test](../../conformance/core.test.mjs#L206))
      - [x] `POST /sign-out` ([test](../../conformance/core.test.mjs#L206))
        - [x] POST /sign-out through the released client returns {success:true} and clears the session, deep-compared with the reference ([test](../../conformance/core.test.mjs#L206))
    - [ ] Email Verification
      - [x] `user` ([test](../../conformance/goapi/account_test.go#L47))
        - [x] send-verification-email delivers exactly one MailLink whose User.Email is the signed-in account owner's ([test](../../conformance/goapi/account_test.go#L47))
      - [x] `url` ([test](../../conformance/goapi/account_test.go#L54))
        - [x] Following the delivered MailLink.URL verifies the email and 302s to the requested callbackURL ([test](../../conformance/goapi/account_test.go#L54))
      - [x] `token` ([test](../../conformance/email-verification-session.mjs#L7))
        - [x] Each runtime consumes the other's delivered MailLink.Token via verify-email ([test](../../conformance/email-verification-session.mjs#L7))
      - [x] Require Email Verification ([test](../../conformance/goapi/account_lifecycle_test.go#L15))
        - [x] Deliver the stored owner to the host while preserving private responses across both modes and ordinary 422 behavior in the released client ([test](../../conformance/core.test.mjs#L1457))
        - [x] Return the same default guest and phone fields on fresh and duplicate private registrations ([test](../../adapters/sqlstore/existing_signup_test.go#L271))
        - [x] With RequireEmailVerification, sign-up returns no token and an unverified sign-in fails with EMAIL_NOT_VERIFIED, resending mail ([test](../../conformance/goapi/account_lifecycle_test.go#L15))
      - [ ] Email Enumeration Protection
        - [x] Plugins that add user fields ([test](../../adapters/sqlstore/existing_signup_test.go#L222))
          - [x] Go adds built-in plugin fields to the synthetic duplicate response automatically ([test](../../adapters/sqlstore/existing_signup_test.go#L222))
          - [x] `coreFields` ([test](../../conformance/synthetic-user.mjs#L5))
            - [x] The hook receives the requested name, the lowercased email, emailVerified false, the image and the timestamps, and the response follows it on both runtimes ([test](../../conformance/synthetic-user.mjs#L5))
          - [x] `additionalFields` ([test](../../conformance/goapi/synthetic_user_test.go#L45))
            - [x] The hook receives the public user fields after defaults, and a hidden field never reaches the response ([test](../../conformance/goapi/synthetic_user_test.go#L45))
          - [x] `id` ([test](../../conformance/goapi/synthetic_user_test.go#L45))
            - [x] The hook receives a fresh ID that differs from the owner's and becomes the response's ID ([test](../../conformance/goapi/synthetic_user_test.go#L45))
      - [x] Triggering manually Email Verification ([test](../../conformance/goapi/account_test.go#L45))
        - [x] A manual POST to send-verification-email with email and callbackURL returns 200 and delivers one link ([test](../../conformance/goapi/account_test.go#L45))
    - [x] Request Password Reset ([test](../../conformance/goapi/mail_request_test.go#L55))
      - [x] Request a password reset over HTTP and deliver the link with a copy of the request ([test](../../conformance/goapi/mail_request_test.go#L55))
      - [x] `user` ([test](../../conformance/goapi/password_reset_hook_test.go#L29))
        - [x] The reset MailLink.User ID and email must equal the account whose password OnPasswordReset reports as reset ([test](../../conformance/goapi/password_reset_hook_test.go#L29))
      - [x] `url` ([test](../../conformance/goapi/account_test.go#L82))
        - [x] Following the delivered reset MailLink.URL 302s to the application's redirect ([test](../../conformance/goapi/account_test.go#L82))
      - [x] `token` ([test](../../conformance/goapi/account_test.go#L89))
        - [x] The delivered MailLink.Token completes POST /reset-password with 200 ([test](../../conformance/goapi/account_test.go#L89))
      - [x] `POST /request-password-reset` ([test](../../conformance/goapi/account_test.go#L72))
        - [x] An HTTP POST to request-password-reset returns 200 and delivers a reset link for a registered account ([test](../../conformance/goapi/account_test.go#L72))
        - [x] Parameter `email` ([test](../../conformance/goapi/account_test.go#L76))
          - [x] Unknown and registered emails get byte-identical responses, and only the registered address receives a delivery ([test](../../conformance/goapi/account_test.go#L76))
        - [x] Parameter `redirectTo` (optional) ([test](../../conformance/goapi/account_test.go#L85))
          - [x] The reset callback redirects to the redirectTo target, keeping its query, with ?token= set to the delivered token ([test](../../conformance/goapi/account_test.go#L85))
      - [x] `newPassword` ([test](../../conformance/goapi/account_test.go#L93))
        - [x] After reset-password with a newPassword, signing in with that new password succeeds ([test](../../conformance/goapi/account_test.go#L93))
      - [x] `POST /reset-password` ([test](../../conformance/core.test.mjs#L249))
        - [x] Go's POST /reset-password consumes a reference-issued token once (200, then 400) ([test](../../conformance/core.test.mjs#L249))
        - [x] Parameter `newPassword` ([test](../../conformance/email-password-options.mjs#L70))
          - [x] newPassword is length-checked before the token is spent on both runtimes ([test](../../conformance/email-password-options.mjs#L70))
        - [x] Parameter `token` ([test](../../conformance/goapi/account_test.go#L96))
          - [x] Under concurrent use a reset token succeeds exactly once and the loser gets INVALID_TOKEN ([test](../../conformance/goapi/account_test.go#L96))
      - [x] Revoking Sessions on Password Reset ([test](../../conformance/goapi/account_test.go#L92))
        - [x] With RevokeSessionsOnPasswordReset on, the previously live session is rejected (401) after a successful reset ([test](../../conformance/goapi/account_test.go#L92))
    - [ ] Update password
      - [x] A signed-in user changes the password over HTTP and receives a replacement session cookie ([test](../../conformance/goapi/account_test.go#L63))
      - [ ] `POST /change-password`
        - [x] The released client's changePassword succeeds against each runtime ([test](../../conformance/core.test.mjs#L1421))
        - [x] Parameter `newPassword` ([test](../../conformance/core.test.mjs#L1423))
          - [x] The newPassword set via change-password becomes the working credential on the other runtime ([test](../../conformance/core.test.mjs#L1423))
        - [x] Parameter `currentPassword` ([test](../../conformance/goapi/account_test.go#L62))
          - [x] change-password with a wrong currentPassword is rejected with 400 ([test](../../conformance/goapi/account_test.go#L62))
        - [ ] Parameter `revokeOtherSessions` (optional)
    - [ ] Configuration
      - [x] Password ([test](../../conformance/email-password-options.mjs#L54))
        - [x] On both runtimes, the sign-up password is stored in the account table under providerId 'credential' (exactly one row is updated) ([test](../../conformance/email-password-options.mjs#L54))
      - [x] Password Hashing ([test](../../conformance/core.test.mjs#L1391))
        - [x] Open and replace host-encoded credentials from either runtime in the same account database ([test](../../conformance/core.test.mjs#L1391))
      - [x] Example ([test](../../conformance/core.test.mjs#L1391))
        - [x] A custom hash/verify pair (PBKDF2 in place of the doc's Argon2) via PasswordHash/PasswordVerify interoperates across runtimes for sign-up, sign-in and change-password ([test](../../conformance/core.test.mjs#L1391))
      - [x] `emailPasswordOptionsType.enabled` ([test](../../conformance/email-password-options.mjs#L77))
        - [x] Compare disabled email sign-in and closed registration with a pre-existing credential and a fresh browser ([test](../../conformance/email-password-options.mjs#L77))
      - [x] `emailPasswordOptionsType.disableSignUp` ([test](../../conformance/email-password-options.mjs#L77))
        - [x] Compare disabled email sign-in and closed registration with a pre-existing credential and a fresh browser ([test](../../conformance/email-password-options.mjs#L77))
      - [x] `emailPasswordOptionsType.minPasswordLength` ([test](../../conformance/email-password-options.mjs#L18))
        - [x] Verify inclusive UTF-16 limits on registration, password changes and link recovery, and sign in with an existing shorter password ([test](../../conformance/email-password-options.mjs#L18))
      - [x] `emailPasswordOptionsType.maxPasswordLength` ([test](../../conformance/email-password-options.mjs#L18))
        - [x] Verify inclusive UTF-16 limits on registration, password changes and link recovery, and sign in with an existing shorter password ([test](../../conformance/email-password-options.mjs#L18))
      - [x] `emailPasswordOptionsType.sendResetPassword` ([test](../../client/account_test.go#L125))
        - [x] The configured SendResetPassword receives a token when the client requests a reset ([test](../../client/account_test.go#L125))
      - [x] `emailPasswordOptionsType.onPasswordReset` ([test](../../conformance/password-reset-hook.mjs#L8))
        - [x] Compared with the reference, OnPasswordReset runs once after the credential commit and session revocation, with the request ([test](../../conformance/password-reset-hook.mjs#L8))
      - [x] `emailPasswordOptionsType.onExistingUserSignUp` ([test](../../conformance/core.test.mjs#L1457))
        - [x] Deliver the stored owner to the host while preserving private responses across both modes and ordinary 422 behavior in the released client ([test](../../conformance/core.test.mjs#L1457))
        - [x] Run the callback after storage releases the account, isolate errors and panics, and preserve owned request metadata ([test](../../adapters/sqlstore/existing_signup_test.go#L83))
        - [x] Use one committed owner for concurrent registrations across separate instances and storage connections ([test](../../adapters/sqlstore/existing_signup_test.go#L197))
      - [x] `emailPasswordOptionsType.customSyntheticUser` ([test](../../conformance/synthetic-user.mjs#L5))
        - [x] On both runtimes the hook sets the values of a duplicate sign-up's user fields but cannot add fields a real sign-up lacks ([test](../../conformance/synthetic-user.mjs#L5))
      - [x] `emailPasswordOptionsType.autoSignIn` ([test](../../conformance/goapi/account_lifecycle_test.go#L54))
        - [x] With DisableAutoSignIn, sign-up returns no session token, while a later manual sign-in succeeds ([test](../../conformance/goapi/account_lifecycle_test.go#L54))
      - [x] `emailPasswordOptionsType.requireEmailVerification` ([test](../../conformance/goapi/account_lifecycle_test.go#L34))
        - [x] With RequireEmailVerification, an unverified credential sign-in fails with EMAIL_NOT_VERIFIED and sends a fresh verification mail ([test](../../conformance/goapi/account_lifecycle_test.go#L34))
      - [x] `emailPasswordOptionsType.revokeSessionsOnPasswordReset` ([test](../../conformance/password-reset-hook.mjs#L70))
        - [x] With revokeSessionsOnPasswordReset on, both runtimes have zero sessions left for the user by the time the reset observer runs ([test](../../conformance/password-reset-hook.mjs#L70))
      - [x] `emailPasswordOptionsType.resetPasswordTokenExpiresIn` ([test](../../conformance/goapi/account_test.go#L142))
        - [x] With PasswordResetTokenTTL set to a nanosecond, the delivered reset token is rejected with INVALID_TOKEN ([test](../../conformance/goapi/account_test.go#L142))
      - [x] `emailPasswordOptionsType.password` ([test](../../conformance/core.test.mjs#L1391))
        - [x] Open and replace host-encoded credentials from either runtime in the same account database ([test](../../conformance/core.test.mjs#L1391))

## Facebook

- [ ] Facebook
  - [ ] Get your Facebook credentials
    - [ ] App ID
    - [ ] App Secret
  - [ ] Configure the provider
  - [ ] Sign In with Facebook
    - [ ] `provider`
  - [ ] Additional Configuration
    - [ ] Scopes
      - [ ] `scopes`
      - [ ] `fields`
    - [ ] Sign In with Facebook With ID or Access Token

## Figma

- [ ] Figma
  - [ ] Get your Credentials
  - [ ] Configure the provider
  - [ ] Sign In with Figma
    - [ ] `provider`

## GitHub

- [ ] GitHub
  - [ ] Get your GitHub credentials
  - [ ] Configure the provider
  - [ ] Sign In with GitHub
    - [ ] `provider`
  - [ ] Usage
    - [ ] Setting up your Github app
    - [ ] Why don't I have a refresh token?

## GitLab

- [ ] GitLab
  - [ ] Get your GitLab credentials
  - [ ] Configure the provider
    - [ ] Configuration Options
      - [ ] `clientId`
      - [ ] `clientSecret`
      - [ ] `issuer`
    - [ ] Example with self-hosted GitLab
  - [ ] Sign In with GitLab
    - [ ] `provider`

## Google

- [ ] Google
  - [ ] Get your Google credentials
    - [ ] Creating Your Google OAuth Credentials
    - [ ] `http://localhost:3000/api/auth/callback/google`
    - [ ] `https://your-domain.com/api/auth/callback/google`
  - [ ] Configure the provider
    - [ ] Important: Set Your Base URL
    - [ ] Option 1: Environment Variable (Recommended)
    - [ ] Option 2: Explicit Configuration
  - [ ] Usage
    - [ ] Sign In with Google
      - [ ] `provider`
    - [ ] Sign In with Google With ID Token
    - [ ] Cross-Platform Sign In (Web, iOS, Android)
    - [ ] Restrict Sign-In to Google Workspace
    - [ ] Always ask to select an account
    - [ ] Requesting Additional Google Scopes
    - [ ] Disable incremental authorization
    - [ ] Always get refresh token
    - [ ] Restricting to a Google Workspace domain

## Hugging Face

- [ ] Hugging Face
  - [ ] Get your Hugging Face credentials
  - [ ] Configure the provider
  - [ ] Sign In with Hugging Face
    - [ ] `provider`

## Kakao

- [ ] Kakao
  - [ ] Get your Kakao Credentials
  - [ ] Configure the provider
  - [ ] Sign In with Kakao
  - [ ] Usage
    - [ ] Sign In with Kakao using ID Token
  - [ ] Options
    - [ ] Scopes

## Kick

- [ ] Kick
  - [ ] Get your Kick Credentials
  - [ ] Configure the provider
  - [ ] Sign In with Kick
    - [ ] `provider`

## LINE

- [ ] LINE
  - [ ] Get your LINE credentials
  - [ ] Configure the provider
  - [ ] Usage
    - [ ] Sign In with LINE
    - [ ] Sign In with LINE using ID Token (optional)
    - [ ] Notes
  - [ ] Multi-Channel Support

## Linear

- [ ] Linear
  - [ ] Get your Linear credentials
  - [ ] Configure the provider
  - [ ] Sign In with Linear
    - [ ] `provider`
  - [ ] Available scopes
    - [ ] `read`
    - [ ] `write`
    - [ ] `issues:create`
    - [ ] `comments:create`
    - [ ] `timeSchedule:write`
    - [ ] `admin`

## LinkedIn

- [ ] LinkedIn
  - [ ] Get your LinkedIn credentials
  - [ ] Configure the provider
  - [ ] Sign In with LinkedIn
    - [ ] `provider`

## Microsoft

- [ ] Microsoft
  - [ ] Get your Microsoft credentials
  - [ ] Configure the provider
    - [ ] Authority URL
    - [ ] Client assertions
  - [ ] Account identifiers
  - [ ] Large Profile Images ⚠️
  - [ ] Sign In with Microsoft
    - [ ] `provider`
    - [ ] Preselecting an organizational domain

## Naver

- [ ] Naver
  - [ ] Get your Naver Credentials
  - [ ] Configure the provider
  - [ ] Sign In with Naver
    - [ ] `provider`

## Notion

- [ ] Notion
  - [ ] Get your Notion credentials
  - [ ] Configure the provider
  - [ ] Usage
    - [ ] Sign In with Notion
      - [ ] `provider`
    - [ ] Notion Integration Types
      - [ ] Public integrations
      - [ ] Internal integrations
    - [ ] Requesting Additional Notion Scopes

## Other Social Providers

- [ ] Other Social Providers
  - [ ] Provider Helpers
    - [ ] Built-in Provider Helpers
      - [ ] Auth0
      - [ ] Gumroad
      - [ ] HubSpot
      - [ ] Keycloak
      - [ ] LINE
      - [ ] Microsoft Entra ID (Azure AD)
      - [ ] Okta
      - [ ] Patreon
      - [ ] Slack
      - [ ] Yandex
      - [ ] Microsoft Entra ID
      - [ ] `clientId`
      - [ ] `clientSecret`
      - [ ] `tokenEndpointAuth`
      - [ ] `scopes`
      - [ ] `redirectURI`
      - [ ] `pkce`
      - [ ] `disableImplicitSignUp`
      - [ ] `disableSignUp`
      - [ ] `overrideUserInfo`
      - [ ] `endSessionEndpoint`
      - [ ] `postLogoutRedirectURI`
      - [ ] `disableProviderLogout`
    - [ ] Community Provider Helpers
      - [ ] AgentID
      - [ ] EVE Online
      - [ ] ThunderID
      - [ ] Create a Provider Helper
  - [ ] Configure a Provider Manually
    - [ ] Instagram Example
    - [ ] Coinbase Example

## Paybin

- [ ] Paybin
  - [ ] Get your Paybin credentials
    - [ ] Application Name
    - [ ] Redirect URIs
  - [ ] Configure the provider
  - [ ] Sign In with Paybin
  - [ ] Additional Configuration
    - [ ] Scopes
    - [ ] User Profile Mapping

## PayPal

- [ ] PayPal
  - [ ] Get your PayPal Credentials
  - [ ] Configure the provider
    - [ ] Options
      - [ ] `environment`
      - [ ] `requestShippingAddress`
  - [ ] Sign In with PayPal
    - [ ] `provider`
  - [ ] Additional Options:
    - [ ] `environment`
    - [ ] `requestShippingAddress`
    - [ ] `scope`
    - [ ] `mapProfileToUser`
    - [ ] `getUserInfo`
    - [ ] `verifyIdToken`

## Polar

- [ ] Polar
  - [ ] Get your Polar credentials
    - [ ] Application Name
    - [ ] Client Type
    - [ ] Redirect URIs
    - [ ] Scopes
    - [ ] Homepage URL
  - [ ] Configure the provider
  - [ ] Sign In with Polar

## Railway

- [ ] Railway
  - [ ] Get your Railway credentials
  - [ ] Configure the provider
  - [ ] Usage
    - [ ] Sign in with Railway
      - [ ] `provider`
  - [ ] Options
    - [ ] Available Scopes
      - [ ] `openid`
      - [ ] `email`
      - [ ] `profile`
      - [ ] `offline_access`
      - [ ] `workspace:viewer`
      - [ ] `workspace:member`
      - [ ] `workspace:admin`
      - [ ] `project:viewer`
      - [ ] `project:member`

## Reddit

- [ ] Reddit
  - [ ] Get your Reddit Credentials
  - [ ] Configure the provider
  - [ ] Sign In with Reddit
    - [ ] `provider`
  - [ ] Additional Configuration
    - [ ] Scopes
      - [ ] `identity`
      - [ ] `read`
      - [ ] `submit`
      - [ ] `subscribe`
      - [ ] `history`

## Roblox

- [ ] Roblox
  - [ ] Get your Roblox Credentials
  - [ ] Configure the provider
  - [ ] Sign In with Roblox
    - [ ] `provider`

## Salesforce

- [ ] Salesforce
  - [ ] Get your Salesforce Credentials
  - [ ] Configure the provider
    - [ ] Configuration Options
      - [ ] `clientId`
      - [ ] `clientSecret`
      - [ ] `environment`
      - [ ] `loginUrl`
      - [ ] `redirectURI`
    - [ ] Advanced Configuration
  - [ ] Environment Variables
  - [ ] Sign In with Salesforce
    - [ ] `provider`

## Slack

- [ ] Slack
  - [ ] Get your Slack credentials
  - [ ] Configure the provider
  - [ ] Usage
    - [ ] Sign In with Slack
      - [ ] `provider`
    - [ ] Requesting Additional Scopes
    - [ ] Workspace-Specific Sign In
    - [ ] Using Slack API After Sign In

## Spotify

- [ ] Spotify
  - [ ] Get your Spotify Credentials
  - [ ] Configure the provider
  - [ ] Sign In with Spotify
    - [ ] `provider`

## TikTok

- [ ] TikTok
  - [ ] Get your TikTok Credentials
  - [ ] Configure the provider
  - [ ] Sign In with TikTok
    - [ ] `provider`

## Twitch

- [ ] Twitch
  - [ ] Get your Twitch Credentials
  - [ ] Configure the provider
  - [ ] Sign In with Twitch
    - [ ] `provider`

## Twitter (X)

- [ ] Twitter (X)
  - [ ] Get your Twitter Credentials
  - [ ] Configure the provider
  - [ ] Sign In with Twitter
    - [ ] `provider`

## Vercel

- [ ] Vercel
  - [ ] Get your Vercel credentials
  - [ ] Configure the provider
  - [ ] Usage
    - [ ] Sign in with Vercel
      - [ ] `provider`
  - [ ] Options
    - [ ] Token endpoint authentication
      - [ ] OIDC client authentication
      - [ ] Private key JWT client authentication
    - [ ] Available Scopes
      - [ ] `openid`
      - [ ] `email`
      - [ ] `profile`
      - [ ] `offline_access`

## VK

- [ ] VK
  - [ ] Get your VK ID credentials
  - [ ] Configure the provider
  - [ ] Sign In with VK
    - [ ] `provider`

## WeChat

- [ ] WeChat
  - [ ] Get your WeChat Credentials
  - [ ] Configure the provider
    - [ ] Optional Configuration
  - [ ] Sign In with WeChat
    - [ ] `provider`
  - [ ] Usage
    - [ ] Platform Support
    - [ ] Development Notes

## Zoom

- [ ] Zoom
  - [ ] Create a Zoom App from Marketplace
  - [ ] Configure your Zoom App
  - [ ] Configure the provider
  - [ ] Sign In with Zoom
