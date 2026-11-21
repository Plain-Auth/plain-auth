# Feature checklist

A checked item links to a local test for that behavior. An open parent means the feature still has unverified cases. Browser, protocol and storage options each have their own checkboxes.

Browse [authentication, storage and tools](#authentication-storage-and-tools), [plugins](#plugins-and-integrations) or [third-party integrations](#third-party-integrations). Each table counts the checked and open boxes on its linked pages, including individual options and tested scenarios. A behavior can appear in more than one checklist.

## Implementation guides

| Capability | Documentation |
| --- | --- |
| Credentials, cookies and session lifecycle | [Authentication](../authentication.md) · [Account management](../account.md) |
| Remember and switch accounts in one browser | [Account switching](../multi-session.md) |
| Guest sessions and account upgrades | [Guest sessions](../anonymous.md) |
| Google One Tap popup, button and browser challenges | [Google One Tap](../one-tap.md) |
| First-party device grants and authorization | [Sign in a device](../device-authorization.md) |
| Passkey registration, login and credential management | [Passkeys](../passkeys.md) |
| Email link sign-in and single-use session transfer | [Magic links](../magic-link.md) · [One-time tokens](../one-time-token.md) |
| Breached-password screening for credential writes | [Password checks](../password-checks.md) |
| CAPTCHA verification and trusted request conditions | [CAPTCHA](../captcha.md) |
| Service tokens, key rotation and public verification keys | [JWT and JWKS](../jwt.md) |
| TOTP enrollment, challenge verification and backup codes | [Two-factor authentication](../2fa.md) |
| Runtime settings, key rotation and startup | [Environment](../environment.md) |
| OAuth sign-in, identity verification and account linking | [Social providers](../social.md) |
| Enterprise provider registration, browser sign-in and organization membership | [Enterprise OpenID Connect](../sso.md) |
| Go client and router integrations | [HTTP client](../client.md) · [Routers](../routers.md) |
| Memory, SQLite, PostgreSQL and MySQL | [Databases](../databases.md) · [Schema generation and migrations](../schema.md) |
| Username registration, sign-in and availability | [Username sign-in](../username.md) |
| Administrative roles, bans and impersonation | [Administrator accounts](../admin.md) |
| Organization membership and invitations | [Organizations](../organizations.md) |
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
| [Published package interfaces](packages.md) | 62 | 161 |
| [Native Go client, routers and databases](go.md) | 36 | 4 |
| [Core API, sign-in providers and CLI](runtime.md) | 102 | 280 |
| [Database adapters](adapters.md) | 32 | 224 |
| [Authentication](authentication.md) | 3 | 424 |
| [Core concepts](concepts.md) | 23 | 515 |
| [Managed infrastructure](infrastructure.md) | 0 | 528 |
| [Framework integrations](integrations.md) | 0 | 228 |
| [Reference and configuration](reference.md) | 14 | 410 |

## Plugins and integrations

| Checklist | Checked | Open |
| --- | ---: | ---: |
| [Two-factor authentication](plugins/2fa.md) | 40 | 141 |
| [Access](plugins/access.md) | 7 | 14 |
| [Additional fields](plugins/additional-fields.md) | 0 | 2 |
| [Admin](plugins/admin.md) | 65 | 141 |
| [Anonymous](plugins/anonymous.md) | 27 | 25 |
| [API keys](plugins/api-key.md) | 96 | 214 |
| [Bearer](plugins/bearer.md) | 9 | 10 |
| [Captcha](plugins/captcha.md) | 17 | 65 |
| [Client ID metadata documents](plugins/cimd.md) | 0 | 48 |
| [Custom session](plugins/custom-session.md) | 11 | 3 |
| [Device authorization](plugins/device-authorization.md) | 22 | 99 |
| [Electron](plugins/electron.md) | 0 | 52 |
| [Email otp](plugins/email-otp.md) | 39 | 95 |
| [Expo](plugins/expo.md) | 0 | 19 |
| [Generic OAuth](plugins/generic-oauth.md) | 22 | 265 |
| [Have I Been Pwned](plugins/have-i-been-pwned.md) | 26 | 10 |
| [Internationalization](plugins/i18n.md) | 116 | 36 |
| [JSON Web Tokens](plugins/jwt.md) | 12 | 75 |
| [Last login method](plugins/last-login-method.md) | 24 | 48 |
| [Magic link](plugins/magic-link.md) | 10 | 44 |
| [Model Context Protocol](plugins/mcp.md) | 0 | 108 |
| [Multi session](plugins/multi-session.md) | 15 | 22 |
| [OAuth popup](plugins/oauth-popup.md) | 0 | 29 |
| [OAuth provider](plugins/oauth-provider.md) | 0 | 455 |
| [OAuth proxy](plugins/oauth-proxy.md) | 0 | 17 |
| [One tap](plugins/one-tap.md) | 36 | 18 |
| [One time token](plugins/one-time-token.md) | 9 | 27 |
| [OpenAPI](plugins/open-api.md) | 9 | 24 |
| [Organization](plugins/organization.md) | 60 | 386 |
| [Passkey](plugins/passkey.md) | 26 | 94 |
| [Phone number](plugins/phone-number.md) | 33 | 67 |
| [SCIM provisioning](plugins/scim.md) | 51 | 251 |
| [Sign in with Ethereum](plugins/siwe.md) | 0 | 40 |
| [Single sign-on](plugins/sso.md) | 27 | 308 |
| [Stripe](plugins/stripe.md) | 119 | 193 |
| [Test utils](plugins/test-utils.md) | 0 | 42 |
| [Username](plugins/username.md) | 32 | 54 |

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
| [Polar](plugins/polar.md) | 0 | 58 |
