# Feature checklist

A checked item links to a local test for that behavior. An open parent means the feature still has unverified cases. Browser, protocol and storage options each have their own checkboxes.

## Implementation guides

| Capability | Documentation |
| --- | --- |
| Credentials, cookies and session lifecycle | [Authentication](../authentication.md) · [Account management](../account.md) |
| Passkey registration, login and credential management | [Passkeys](../passkeys.md) |
| Email link sign-in and single-use session transfer | [Magic links](../magic-link.md) · [One-time tokens](../one-time-token.md) |
| Breached-password screening for credential writes | [Password checks](../password-checks.md) |
| CAPTCHA verification and trusted request conditions | [CAPTCHA](../captcha.md) |
| Service tokens, key rotation and public verification keys | [JWT and JWKS](../jwt.md) |
| TOTP enrollment, challenge verification and backup codes | [Two-factor authentication](../2fa.md) |
| Runtime settings, key rotation and startup | [Environment](../environment.md) |
| OAuth sign-in, identity verification and account linking | [Social providers](../social.md) |
| Go client and router integrations | [HTTP client](../client.md) · [Routers](../routers.md) |
| Memory, SQLite, PostgreSQL and MySQL | [Databases](../databases.md) · [Schema generation and migrations](../schema.md) |
| Organization membership and invitations | [Organizations](../organizations.md) |
| Checkout, subscription listing and billing portal | [Recurring subscriptions](../subscriptions.md) · [Billing portal](../plugins.md#open-the-users-stripe-billing-portal) |
| CAPTCHA verification and host BotID integration | [CAPTCHA](../captcha.md) |
| Extension hooks, bearer sessions and login method | [Plugins](../plugins.md) |

## Authentication, storage and tools

- [ ] [Native Go client, routers and databases](go.md)
- [ ] [Core API, sign-in providers and CLI](runtime.md)
- [ ] [Database adapters](adapters.md)
- [ ] [Authentication](authentication.md)
- [ ] [Core concepts](concepts.md)
- [ ] [Managed infrastructure](infrastructure.md)
- [ ] [Framework integrations](integrations.md)
- [ ] [Reference and configuration](reference.md)

## Plugins and integrations

- [ ] [Two-factor authentication](plugins/2fa.md)
- [ ] [Access](plugins/access.md)
- [ ] [Additional fields](plugins/additional-fields.md)
- [ ] [Admin](plugins/admin.md)
- [ ] [Anonymous](plugins/anonymous.md)
- [ ] [API keys](plugins/api-key.md)
- [ ] [Bearer](plugins/bearer.md)
- [ ] [Captcha](plugins/captcha.md)
- [ ] [Client ID metadata documents](plugins/cimd.md)
- [ ] [Custom session](plugins/custom-session.md)
- [ ] [Device authorization](plugins/device-authorization.md)
- [ ] [Electron](plugins/electron.md)
- [ ] [Email otp](plugins/email-otp.md)
- [ ] [Expo](plugins/expo.md)
- [ ] [Generic OAuth](plugins/generic-oauth.md)
- [ ] [Have I Been Pwned](plugins/have-i-been-pwned.md)
- [ ] [Internationalization](plugins/i18n.md)
- [ ] [JSON Web Tokens](plugins/jwt.md)
- [ ] [Last login method](plugins/last-login-method.md)
- [ ] [Magic link](plugins/magic-link.md)
- [ ] [Model Context Protocol](plugins/mcp.md)
- [ ] [Multi session](plugins/multi-session.md)
- [ ] [OAuth popup](plugins/oauth-popup.md)
- [ ] [OAuth provider](plugins/oauth-provider.md)
- [ ] [OAuth proxy](plugins/oauth-proxy.md)
- [ ] [One tap](plugins/one-tap.md)
- [ ] [One time token](plugins/one-time-token.md)
- [ ] [OpenAPI](plugins/open-api.md)
- [ ] [Organization](plugins/organization.md)
- [ ] [Passkey](plugins/passkey.md)
- [ ] [Phone number](plugins/phone-number.md)
- [ ] [SCIM provisioning](plugins/scim.md)
- [ ] [Sign in with Ethereum](plugins/siwe.md)
- [ ] [Single sign-on](plugins/sso.md)
- [ ] [Stripe](plugins/stripe.md)
- [ ] [Test utils](plugins/test-utils.md)
- [ ] [Username](plugins/username.md)

## Third-party integrations

These integrations have independent release cycles.

- [ ] [Agent auth](plugins/agent-auth.md)
- [ ] [Autumn](plugins/autumn.md)
- [ ] [Chargebee](plugins/chargebee.md)
- [ ] [Commet](plugins/commet.md)
- [ ] [Community plugins](plugins/community-plugins.md)
- [ ] [Creem](plugins/creem.md)
- [ ] [Dodopayments](plugins/dodopayments.md)
- [ ] [Dub](plugins/dub.md)
- [ ] [Polar](plugins/polar.md)
