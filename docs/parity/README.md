# Feature checklist

## Verification progress

**471 of 7,025 inventory entries are fully verified (6.7%).**

| Inventory status | Entries |
| --- | ---: |
| Fully verified | 471 |
| Partially verified | 952 |
| No linked test evidence | 5,602 |

The inventory covers features, options, integrations and documentation topics. Partial verification means an open entry has a passing case somewhere beneath it. The checklists also contain 1,980 links from passing scenarios to tests. Adding a scenario leaves the inventory denominator unchanged.

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
| Publish discovery metadata and respond to access-token failures | [Resource discovery and challenges](../oauth-resource-discovery.md) |
| Manage OAuth resource policies and client grants from server code | [Resource management](../oauth-resource-management.md) |
| Manage the signed-in user’s OAuth consent grants | [Authorized applications](../oauth-consents.md) |
| Register OAuth clients and rotate shared secrets | [OAuth client registration](../oauth-client-registration.md) |
| Grant or revoke machine-to-machine scopes from Go server code | [Machine scope management](../oauth-client-registration.md#grant-machine-to-machine-scopes) |
| Issue opaque machine access tokens and check their current scopes and expiry | [Machine access tokens](../machine-tokens.md) · [Token introspection](../machine-tokens.md#check-whether-a-token-is-active) |
| Authenticate an OAuth application with its own signing key | [Signed client assertions](../oauth-client-assertions.md) |
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
| Share rate limits and store short-lived application values in Redis | [Redis secondary storage](../redis.md) |
| Describe installed HTTP endpoints and render their reference | [OpenAPI](../openapi.md) |
| Extension hooks, bearer sessions and login method | [Plugins](../plugins.md) |

## Authentication, storage and tools

| Checklist | Checked | Open |
| --- | ---: | ---: |
| [Published package interfaces](packages.md) | 89 | 160 |
| [Native Go client, routers and databases](go.md) | 38 | 4 |
| [Core API, sign-in providers and CLI](runtime.md) | 165 | 276 |
| [Database adapters](adapters.md) | 32 | 224 |
| [Authentication](authentication.md) | 26 | 415 |
| [Core concepts](concepts.md) | 68 | 505 |
| [Managed infrastructure](infrastructure.md) | 0 | 528 |
| [Framework integrations](integrations.md) | 0 | 228 |
| [Reference and configuration](reference.md) | 95 | 390 |

## Plugins and integrations

| Checklist | Checked | Open |
| --- | ---: | ---: |
| [Two-factor authentication](plugins/2fa.md) | 40 | 141 |
| [Access](plugins/access.md) | 7 | 14 |
| [Additional fields](plugins/additional-fields.md) | 0 | 2 |
| [Admin](plugins/admin.md) | 74 | 141 |
| [Anonymous](plugins/anonymous.md) | 27 | 25 |
| [API keys](plugins/api-key.md) | 114 | 210 |
| [Bearer](plugins/bearer.md) | 30 | 0 |
| [Captcha](plugins/captcha.md) | 17 | 65 |
| [Client ID metadata documents](plugins/cimd.md) | 0 | 48 |
| [Custom session](plugins/custom-session.md) | 21 | 3 |
| [Device authorization](plugins/device-authorization.md) | 22 | 99 |
| [Electron](plugins/electron.md) | 0 | 52 |
| [Email otp](plugins/email-otp.md) | 43 | 95 |
| [Expo](plugins/expo.md) | 0 | 19 |
| [Generic OAuth](plugins/generic-oauth.md) | 28 | 262 |
| [Have I Been Pwned](plugins/have-i-been-pwned.md) | 46 | 0 |
| [Internationalization](plugins/i18n.md) | 116 | 36 |
| [JSON Web Tokens](plugins/jwt.md) | 13 | 75 |
| [Last login method](plugins/last-login-method.md) | 24 | 48 |
| [Magic link](plugins/magic-link.md) | 67 | 19 |
| [Model Context Protocol](plugins/mcp.md) | 0 | 108 |
| [Multi session](plugins/multi-session.md) | 15 | 22 |
| [OAuth popup](plugins/oauth-popup.md) | 56 | 5 |
| [OAuth provider](plugins/oauth-provider.md) | 316 | 414 |
| [OAuth proxy](plugins/oauth-proxy.md) | 27 | 6 |
| [One tap](plugins/one-tap.md) | 38 | 18 |
| [One time token](plugins/one-time-token.md) | 76 | 0 |
| [OpenAPI](plugins/open-api.md) | 15 | 24 |
| [Organization](plugins/organization.md) | 84 | 385 |
| [Passkey](plugins/passkey.md) | 26 | 94 |
| [Phone number](plugins/phone-number.md) | 36 | 67 |
| [SCIM provisioning](plugins/scim.md) | 66 | 257 |
| [Sign in with Ethereum](plugins/siwe.md) | 90 | 11 |
| [Single sign-on](plugins/sso.md) | 75 | 319 |
| [Stripe](plugins/stripe.md) | 206 | 175 |
| [Test utils](plugins/test-utils.md) | 69 | 18 |
| [Username](plugins/username.md) | 33 | 54 |

## Third-party integrations

These integrations have independent release cycles.

| Checklist | Checked | Open |
| --- | ---: | ---: |
| [Agent auth](plugins/agent-auth.md) | 0 | 58 |
| [Autumn](plugins/autumn.md) | 0 | 18 |
| [Chargebee](plugins/chargebee.md) | 0 | 159 |
| [Commet](plugins/commet.md) | 0 | 37 |
| [Community plugins](plugins/community-plugins.md) | 0 | 55 |
| [Creem](plugins/creem.md) | 0 | 74 |
| [Dodopayments](plugins/dodopayments.md) | 0 | 20 |
| [Dub](plugins/dub.md) | 0 | 15 |
| [Polar](plugins/polar.md) | 21 | 57 |
