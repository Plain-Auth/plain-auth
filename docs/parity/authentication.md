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
    - [ ] Generate the Client Secret (JWT):
  - [ ] Configure the provider
    - [ ] Localhost and Non-TLS Restrictions
  - [ ] Usage
    - [ ] Sign In with Apple
      - [ ] `provider`
    - [ ] Sign In with Apple With ID Token
  - [ ] Generate Apple Client Secret (JWT)

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
  - [ ] Enable Email and Password
  - [ ] Usage
    - [ ] Sign Up
      - [x] Create a password account and return a usable session token on SQLite ([test](../../conformance/core.test.mjs#L188))
      - [ ] `POST /sign-up/email`
        - [ ] Parameter `name`
        - [ ] Parameter `email`
        - [ ] Parameter `password`
        - [ ] Parameter `image` (optional)
        - [ ] Parameter `callbackURL` (optional)
    - [ ] Sign In
      - [x] Reject the wrong password and issue a fresh session for valid credentials ([test](../../conformance/core.test.mjs#L197))
      - [ ] `POST /sign-in/email`
        - [ ] Parameter `email`
        - [ ] Parameter `password`
        - [ ] Parameter `rememberMe` (optional)
        - [ ] Parameter `callbackURL` (optional)
    - [ ] Sign Out
      - [x] Clear the client's session cookies and return an anonymous session ([test](../../conformance/core.test.mjs#L201))
      - [ ] `POST /sign-out`
    - [ ] Email Verification
      - [ ] `user`
      - [ ] `url`
      - [ ] `token`
      - [ ] Require Email Verification
      - [ ] Email Enumeration Protection
        - [ ] Plugins that add user fields
          - [ ] `coreFields`
          - [ ] `additionalFields`
          - [ ] `id`
      - [ ] Triggering manually Email Verification
    - [ ] Request Password Reset
      - [ ] `user`
      - [ ] `url`
      - [ ] `token`
      - [ ] `POST /request-password-reset`
        - [ ] Parameter `email`
        - [ ] Parameter `redirectTo` (optional)
      - [ ] `newPassword`
      - [ ] `POST /reset-password`
        - [ ] Parameter `newPassword`
        - [ ] Parameter `token`
      - [ ] Revoking Sessions on Password Reset
    - [ ] Update password
      - [ ] `POST /change-password`
        - [ ] Parameter `newPassword`
        - [ ] Parameter `currentPassword`
        - [ ] Parameter `revokeOtherSessions` (optional)
    - [ ] Configuration
      - [ ] Password
      - [ ] Password Hashing
      - [ ] Example
      - [ ] `emailPasswordOptionsType.enabled`
      - [ ] `emailPasswordOptionsType.disableSignUp`
      - [ ] `emailPasswordOptionsType.minPasswordLength`
      - [ ] `emailPasswordOptionsType.maxPasswordLength`
      - [ ] `emailPasswordOptionsType.sendResetPassword`
      - [ ] `emailPasswordOptionsType.onPasswordReset`
      - [ ] `emailPasswordOptionsType.onExistingUserSignUp`
      - [ ] `emailPasswordOptionsType.customSyntheticUser`
      - [ ] `emailPasswordOptionsType.autoSignIn`
      - [ ] `emailPasswordOptionsType.requireEmailVerification`
      - [ ] `emailPasswordOptionsType.revokeSessionsOnPasswordReset`
      - [ ] `emailPasswordOptionsType.resetPasswordTokenExpiresIn`
      - [ ] `emailPasswordOptionsType.password`

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
