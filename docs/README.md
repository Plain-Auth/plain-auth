# Plain Auth guides

Each guide explains one capability and links to the tests that prove it. New to Plain Auth? Start with the [quickstart](../README.md#quickstart), then read [environment configuration](environment.md) and [router integrations](routers.md). The [feature checklist](parity/README.md) tracks what is finished and what remains.

## Set up

| Task | Guide |
| --- | --- |
| Load signing secrets, the public URL, and trusted origins from the environment | [Environment configuration](environment.md) |
| Mount on ServeMux, chi, Gorilla Mux, Gin, Echo, or Fiber | [Router integrations](routers.md) |
| Generate tables and migrate SQLite, PostgreSQL, or MySQL | [Databases and CLI](databases.md) |
| Keep users and sessions in your own database or service, and check the store with contract tests | [Custom stores](custom-store.md) |
| Generate optional organization, team, passkey, rate-limit, subscription, and two-factor tables | [Schema profiles](schema.md) |
| Call the API from a Go service | [Go client](client.md) |
| Create fixture users and organizations, capture email or SMS codes, or import a test login into a browser | [Test helpers](test-helpers.md) |

## Sign in

| Task | Guide |
| --- | --- |
| Configure users, cookies, origins, and session management | [Authentication](authentication.md) |
| Style the page that shows failed browser sign-ins | [Error page](authentication.md#style-the-error-page) |
| Configure profile updates, password reset, and verification email | [Account management and recovery](account.md) |
| Register a username and sign in with a password | [Username sign-in](username.md) |
| Let users sign in through a single-use email link | [Magic links](magic-link.md) |
| Verify an address, sign in or recover a password with an email code | [Email one-time passwords](email-otp.md) |
| Verify a phone number, link it to an account and recover a password by SMS | [Phone accounts](phone-number.md) |
| Register and use a WebAuthn passkey | [Passkeys](passkeys.md) |
| Configure browser sign-in, native ID tokens and linked provider credentials | [Social sign-in](social.md) |
| Configure tenant-specific sign-in with Auth0, Keycloak, Okta or Entra ID | [Provider setup](social.md#auth0-keycloak-and-okta) |
| Sign in through an OAuth popup from a top-level page or a cross-site iframe | [OAuth popup sign-in](oauth-popup.md) |
| Share a registered OAuth callback across trusted preview deployments | [OAuth proxy](oauth-proxy.md) |
| Integrate the Google One Tap prompt or sign-in button | [Google One Tap](one-tap.md) |
| Sign in with an Ethereum wallet | [Wallet sign-in](siwe.md) |
| Create a guest account and transfer its application records on sign-up | [Guest sessions](anonymous.md) |

## Sessions and devices

| Task | Guide |
| --- | --- |
| Share login cookies across approved sibling hosts | [Cookie configuration](authentication.md#share-a-session-across-subdomains) |
| Remember multiple accounts in one browser and switch or revoke them | [Account switching](multi-session.md) |
| Remember the last sign-in method in a browser or across a user's devices | [Login preferences](plugins.md#persist-the-last-login-method) |
| Authorize a TV, CLI or input-constrained device | [Device authorization](device-authorization.md) |
| Transfer an active session using a single-use credential | [One-time tokens](one-time-token.md) |
| Store application fields on users and control which values clients can read or write | [User fields](user-fields.md) |
| Store application fields on sessions | [Session fields](session-fields.md) |

## Security

| Task | Guide |
| --- | --- |
| Enroll an authenticator, deliver codes and manage backup codes | [Two-factor authentication](2fa.md) |
| Check new passwords against a breached-password service | [Password screening](password-checks.md) |
| Require a CAPTCHA verdict on selected routes | [CAPTCHA providers](captcha.md) |
| Share a request limit across server instances using Redis or Valkey | [Redis secondary storage](redis.md) |
| Return translated authentication errors in 22 bundled languages | [Localization](localization.md) |

## Organizations, roles and administration

| Task | Guide |
| --- | --- |
| Switch organizations and teams, read a shared organization directory, grant memberships and accept invitations | [Organizations](organizations.md) |
| Limit who can create organizations and how many each user may join | [Organization creation](organizations.md#control-who-can-create-organizations) |
| Delete an organization with its members, invitations and teams | [Organization deletion](organizations.md#delete-an-organization) |
| Page through an organization's member directory and filter by role or join date | [Member directory](organizations.md#list-organization-members) |
| Enforce fixed or application-defined membership and team limits | [Organization membership limits](organizations.md#limit-organization-membership) |
| Create, list, update, and retire organization roles over HTTP | [Organization role management](organizations.md#create-a-stored-role) |
| Check a member’s organization permissions or define roles for your own handlers | [Organization permissions](organizations.md#check-organization-permissions) · [Custom organization roles](organizations.md#configure-organization-roles) · [Application roles](access.md) |
| Deliver invitation emails from your application and accept grants over HTTP or Go | [Invitation delivery](organizations.md#deliver-invitation-email) · [Invitation acceptance](organizations.md#accept-an-invitation) |
| Manage users, ban accounts and grant administrative access | [Administrator accounts](admin.md) |
| Issue revocable API keys, check permissions, and enforce usage limits on application routes | [API keys](api-keys.md) |

## Enterprise

| Task | Guide |
| --- | --- |
| Register enterprise OIDC or SAML providers, verify their domains with DNS, and provision members | [Enterprise single sign-on](sso.md) |
| Provision directory Users and Groups and rotate or revoke scoped SCIM credentials | [Directory provisioning](scim.md) |
| Map directory Group memberships to application roles | [SCIM role mapping](scim.md#project-group-memberships-into-application-roles) |

## OAuth 2.0 and OpenID Connect provider

| Task | Guide |
| --- | --- |
| Sign in, choose an account, collect consent and exchange a PKCE code for access or offline refresh tokens | [Browser authorization and code exchange](oauth-authorization-code.md) |
| Sign a user into an OAuth client with a verifiable ID token, then renew it with an offline grant | [OpenID Connect code and refresh exchanges](oauth-authorization-code.md#receive-and-verify-an-openid-connect-id-token) |
| Include a host-approved entitlement in an ID token and reevaluate it on refresh | [Application-defined ID-token claims](oauth-authorization-code.md#add-application-claims-to-an-id-token) |
| Rotate a refresh token, narrow its scopes or check its session | [Refresh exchange](oauth-authorization-code.md#exchange-a-refresh-token) · [Refresh token introspection](machine-tokens.md#inspect-a-refresh-token) |
| Connect a relying party using the issuer URL and discover its public signing keys | [OpenID Connect discovery](oauth-issuer-discovery.md#connect-a-relying-party-using-the-issuer-url) |
| Discover machine grant endpoints, authentication methods and signing keys from an issuer URL | [Authorization-server discovery](oauth-issuer-discovery.md) |
| Add discovery fields to the OAuth provider through an extension | [OAuth provider extensions](oauth-extensions.md) |
| Read current OIDC profile and email claims using a signed or opaque access token | [OpenID Connect UserInfo](oauth-userinfo.md) |
| Publish OAuth issuers and scopes, verify DPoP proofs and return authentication challenges from a protected API | [Resource discovery and challenges](oauth-resource-discovery.md) |
| Verify the provider's signed access tokens and their scopes in your API or another service | [Protect your API](oauth-resource-server.md) |
| Protect a Model Context Protocol server with the provider's access tokens | [Model Context Protocol](mcp.md) |
| Register OAuth resources, change their policies, and link registered clients | [Resource management](oauth-resource-management.md) |
| Register OAuth clients and rotate confidential client secrets | [OAuth client registration](oauth-client-registration.md) |
| Grant or revoke machine-to-machine scopes from Go server code | [Machine scope management](oauth-client-registration.md#grant-machine-to-machine-scopes) |
| Authenticate an OAuth application with its own signing key and rotate its keys | [Signed client assertions](oauth-client-assertions.md) |
| List or delete registered applications and show client details on a consent screen | [Manage registered applications](oauth-client-directory.md) |
| List, inspect, update and remove a user’s OAuth consent grants | [Authorized applications](oauth-consents.md) |
| Issue signed or opaque machine tokens with resource audiences, scoped permissions and sender binding | [Machine access tokens](machine-tokens.md#request-access-to-a-resource) · [Token introspection](machine-tokens.md#check-whether-a-token-is-active) |
| Inspect a delegated opaque token using an application or resource server credential | [Delegated token introspection](machine-tokens.md#inspect-a-delegated-token-as-a-resource-server) |
| Check signed OAuth access tokens against current client, session and resource state | [Signed token introspection](machine-tokens.md#inspect-a-signed-access-token) |
| Revoke an OAuth token or invalidate a replayed refresh-token family | [Token revocation](oauth-token-revocation.md) |
| Let an OAuth client end the user's session with an ID token hint, with the user's confirmation when needed | [RP-initiated logout](oauth-logout.md#rp-initiated-logout) |
| Notify OAuth clients with a signed logout token when a user's session ends | [Back-channel logout](oauth-logout.md#back-channel-logout) |
| Issue signed service tokens and publish verification keys | [JWT and JWKS](jwt.md) |

## Billing

| Task | Guide |
| --- | --- |
| Start recurring Checkout, confirm plan changes, schedule a price for the next period, cancel or restore | [Subscription billing](subscriptions.md) |
| Bill organization seats monthly or annually and synchronize the quantity after membership changes | [Automatic seats](subscriptions.md#bill-by-organization-membership) |
| Verify Stripe webhooks and open an authenticated customer’s billing portal | [Plugins and Stripe](plugins.md) |
| Set up Polar checkout, billing state, the customer portal and signed webhooks | [Polar hosted checkout](polar.md) |

## Extend

| Task | Guide |
| --- | --- |
| Add a session-aware endpoint, authenticate clients with bearer tokens, or return an application-defined session view | [Plugins](plugins.md) |
| Reject, rewrite or answer requests before an endpoint runs, or change its result afterwards | [Endpoint hooks](hooks.md) |
| Edit, cancel or observe the users and sessions a sign-up or sign-in creates | [Database hooks](hooks.md#run-code-around-database-writes) |
| Generate an OpenAPI document and browse the routes enabled in this application | [OpenAPI reference](openapi.md) |
| Work on a feature, run checks, and update the checklist | [Contributing](../CONTRIBUTING.md) |
