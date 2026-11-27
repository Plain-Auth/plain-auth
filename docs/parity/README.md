# Feature checklist

## Verification progress

**3,047 of 6,419 inventory entries are fully verified (47.5%).**

| Inventory status | Entries |
| --- | ---: |
| Fully verified | 3,047 |
| Partially verified | 1,586 |
| No linked test evidence | 1,786 |
| Not applicable to a Go server | 606 |

The inventory covers features, options, integrations and documentation topics. Partial verification means an open entry has a passing case somewhere beneath it. The checklists also contain 8,047 links from passing scenarios to tests. Adding a scenario leaves the inventory denominator unchanged.

Entries that exist only for JavaScript clients, frameworks or runtimes are listed as not applicable, with the reason, and are left out of the totals. Backlog entries stay open on the roadmap but are not scheduled.

A checked item links to a local test for that behavior. An open parent means the feature still has unverified cases. Browser, protocol and storage options each have their own checkboxes.

Browse [authentication, storage and tools](#authentication-storage-and-tools), [plugins](#plugins-and-integrations) or [third-party integrations](#third-party-integrations). Each table counts the checked and open boxes on its linked pages, including individual options and tested scenarios. A behavior can appear in more than one checklist.

## Implementation guides

| Capability | Documentation |
| --- | --- |
| Credentials, cookies and session lifecycle | [Authentication](../authentication.md) · [Account management](../account.md) |
| Remember and switch accounts in one browser | [Account switching](../multi-session.md) |
| Guest sessions and account upgrades | [Guest sessions](../anonymous.md) |
| OAuth popup sign-in for top-level and embedded applications | [OAuth popup sign-in](../oauth-popup.md) |
| Share a registered OAuth callback across trusted preview deployments | [OAuth proxy setup](../oauth-proxy.md) |
| Google One Tap popup, button and browser challenges | [Google One Tap](../one-tap.md) |
| Read OpenID Connect profile and email claims for a signed or opaque access token | [UserInfo](../oauth-userinfo.md) |
| Publish discovery metadata and respond to access-token failures | [Resource discovery and challenges](../oauth-resource-discovery.md) |
| Discover browser and machine endpoints, signing keys and supported claims from an issuer URL | [OAuth and OpenID Connect discovery](../oauth-issuer-discovery.md) |
| Sign in, choose an account, collect consent and exchange a PKCE code for access or offline refresh tokens | [Browser authorization and code exchange](../oauth-authorization-code.md) |
| Manage OAuth resource policies and client grants from server code | [Resource management](../oauth-resource-management.md) |
| Manage the signed-in user’s OAuth consent grants | [Authorized applications](../oauth-consents.md) |
| Register OAuth clients and rotate shared secrets | [OAuth client registration](../oauth-client-registration.md) |
| Grant or revoke machine-to-machine scopes from Go server code | [Machine scope management](../oauth-client-registration.md#grant-machine-to-machine-scopes) |
| Issue signed or opaque machine tokens with resource audiences, scoped permissions and sender binding | [Machine access tokens](../machine-tokens.md#request-access-to-a-resource) · [Token introspection](../machine-tokens.md#check-whether-a-token-is-active) |
| Authenticate an OAuth application with its own signing key and rotate its keys | [Signed client assertions](../oauth-client-assertions.md) |
| Rotate a refresh token, narrow its scopes or check its session | [Refresh exchange](../oauth-authorization-code.md#exchange-a-refresh-token) · [Refresh token introspection](../machine-tokens.md#inspect-a-refresh-token) |
| Revoke an OAuth token or invalidate a replayed refresh-token family | [Token revocation](../oauth-token-revocation.md) |
| List or delete owned applications and show public client details | [Manage registered applications](../oauth-client-directory.md) |
| OAuth authorization-server database tables | [Schema and migration](../schema.md#oauth-authorization-server-tables) |
| First-party device grants and authorization | [Sign in a device](../device-authorization.md) |
| Sign in with an Ethereum wallet | [Wallet sign-in](../siwe.md) |
| Passkey registration, login and credential management | [Passkeys](../passkeys.md) |
| Email link sign-in and single-use session transfer | [Magic links](../magic-link.md) · [One-time tokens](../one-time-token.md) |
| Application-defined fields on users and sessions | [User fields](../user-fields.md) · [Session fields](../session-fields.md) · [Schema commands](../schema.md) |
| Breached-password screening for credential writes | [Password checks](../password-checks.md) |
| CAPTCHA verification and trusted request conditions | [CAPTCHA](../captcha.md) |
| Service tokens, key rotation and public verification keys | [JWT and JWKS](../jwt.md) |
| TOTP enrollment, challenge verification and backup codes | [Two-factor authentication](../2fa.md) |
| Runtime settings, key rotation and startup | [Environment](../environment.md) |
| OAuth sign-in, identity verification and account linking | [Social providers](../social.md) |
| Enterprise provider registration, browser sign-in and organization membership | [Enterprise single sign-on](../sso.md) |
| Go client and router integrations | [HTTP client](../client.md) · [Routers](../routers.md) |
| Memory, SQLite, PostgreSQL and MySQL | [Databases](../databases.md) · [Schema generation and migrations](../schema.md) |
| Username registration, sign-in and availability | [Username sign-in](../username.md) |
| Administrative roles, bans and impersonation | [Administrator accounts](../admin.md) |
| Organization membership and invitations | [Organizations](../organizations.md) |
| Personal checkout, customer portal, billing state and signed notifications | [Polar billing](../polar.md) |
| Checkout, subscription changes, cancellation, restoration and signed webhooks | [Subscription lifecycle](../subscriptions.md) · [Billing portal](../plugins.md#open-the-users-stripe-billing-portal) |
| Role definitions and action checks | [Role permissions](../access.md) |
| Personal and organization application credentials | [API keys](../api-keys.md) |
| Verify a phone number, sign in or recover a password by SMS | [Phone accounts](../phone-number.md) |
| Provision directory users with scoped bearer credentials | [SCIM provisioning](../scim.md) |
| Translate authentication errors and select a locale | [Localization](../localization.md) |
| Keep sessions, share rate limits and store short-lived application values in Redis | [Redis secondary storage](../redis.md) |
| Describe installed HTTP endpoints and render their reference | [OpenAPI](../openapi.md) |
| Extension hooks, bearer sessions and login method | [Plugins](../plugins.md) |

## Authentication, storage and tools

| Checklist | Checked | Open | Not applicable |
| --- | ---: | ---: | ---: |
| [Published package interfaces](packages.md) | 111 | 116 | 43 |
| [Native Go client, routers and databases](go.md) | 51 | 3 | 0 |
| [Core API, sign-in providers and CLI](runtime.md) | 559 | 104 | 32 |
| [Database adapters](adapters.md) | 82 | 49 | 163 |
| [Authentication](authentication.md) | 759 | 188 | 4 |
| [Core concepts](concepts.md) | 808 | 262 | 1 |
| [Managed infrastructure](infrastructure.md) | 0 | 528 | 0 |
| [Framework integrations](integrations.md) | 7 | 24 | 201 |
| [Reference and configuration](reference.md) | 469 | 227 | 6 |

## Plugins and integrations

| Checklist | Checked | Open | Not applicable |
| --- | ---: | ---: | ---: |
| [Two-factor authentication](plugins/2fa.md) | 308 | 68 | 6 |
| [Access](plugins/access.md) | 25 | 1 | 4 |
| [Additional fields](plugins/additional-fields.md) | 0 | 0 | 2 |
| [Admin](plugins/admin.md) | 315 | 56 | 6 |
| [Anonymous](plugins/anonymous.md) | 87 | 7 | 0 |
| [API keys](plugins/api-key.md) | 513 | 99 | 1 |
| [Bearer](plugins/bearer.md) | 30 | 0 | 0 |
| [Captcha](plugins/captcha.md) | 153 | 26 | 0 |
| [Client ID metadata documents](plugins/cimd.md) | 74 | 19 | 0 |
| [Custom session](plugins/custom-session.md) | 21 | 3 | 0 |
| [Device authorization](plugins/device-authorization.md) | 176 | 41 | 3 |
| [Electron](plugins/electron.md) | 0 | 12 | 40 |
| [Email otp](plugins/email-otp.md) | 245 | 48 | 0 |
| [Expo](plugins/expo.md) | 0 | 5 | 14 |
| [Generic OAuth](plugins/generic-oauth.md) | 454 | 150 | 0 |
| [Have I Been Pwned](plugins/have-i-been-pwned.md) | 46 | 0 | 0 |
| [Internationalization](plugins/i18n.md) | 183 | 6 | 0 |
| [JSON Web Tokens](plugins/jwt.md) | 132 | 42 | 2 |
| [Last login method](plugins/last-login-method.md) | 100 | 18 | 2 |
| [Magic link](plugins/magic-link.md) | 108 | 5 | 0 |
| [Model Context Protocol](plugins/mcp.md) | 183 | 40 | 0 |
| [Multi session](plugins/multi-session.md) | 64 | 2 | 0 |
| [OAuth popup](plugins/oauth-popup.md) | 56 | 5 | 0 |
| [OAuth provider](plugins/oauth-provider.md) | 1034 | 233 | 0 |
| [OAuth proxy](plugins/oauth-proxy.md) | 27 | 5 | 1 |
| [One tap](plugins/one-tap.md) | 78 | 9 | 0 |
| [One time token](plugins/one-time-token.md) | 76 | 0 | 0 |
| [OpenAPI](plugins/open-api.md) | 55 | 5 | 5 |
| [Organization](plugins/organization.md) | 1044 | 73 | 41 |
| [Passkey](plugins/passkey.md) | 168 | 45 | 10 |
| [Phone number](plugins/phone-number.md) | 148 | 30 | 0 |
| [SCIM provisioning](plugins/scim.md) | 701 | 43 | 6 |
| [Sign in with Ethereum](plugins/siwe.md) | 122 | 7 | 0 |
| [Single sign-on](plugins/sso.md) | 990 | 75 | 10 |
| [Stripe](plugins/stripe.md) | 294 | 168 | 0 |
| [Test utils](plugins/test-utils.md) | 86 | 10 | 1 |
| [Username](plugins/username.md) | 126 | 23 | 2 |

## Third-party integrations

These integrations have independent release cycles.

| Checklist | Status | Checked | Open | Not applicable |
| --- | --- | ---: | ---: | ---: |
| [Agent auth](plugins/agent-auth.md) | Planned | 0 | 58 | 0 |
| [Autumn](plugins/autumn.md) | Backlog | 0 | 18 | 0 |
| [Chargebee](plugins/chargebee.md) | Backlog | 0 | 159 | 0 |
| [Commet](plugins/commet.md) | Backlog | 0 | 37 | 0 |
| [Community plugins](plugins/community-plugins.md) | Backlog | 0 | 55 | 0 |
| [Creem](plugins/creem.md) | Backlog | 0 | 74 | 0 |
| [Dodopayments](plugins/dodopayments.md) | Backlog | 0 | 20 | 0 |
| [Dub](plugins/dub.md) | Backlog | 0 | 15 | 0 |
| [Polar](plugins/polar.md) | Planned | 26 | 56 | 0 |
