# Plain Auth

Plain Auth embeds authentication in your Go API. Mount the auth handler on your router and use the same instance to read the signed-in user inside your own handlers. Your application owns its listener, database lifetime, middleware, and routes.

[Run locally](#run-it-locally) · [Install in a Go app](#mount-it-in-an-application) · [Supported workflows](#supported-workflows) · [Roadmap](docs/parity/README.md)

**Developer preview.** Start with email and password, persistent sessions, and a protected route in your own Go server. APIs and SQL migrations may change during the preview. Each supported workflow below links to its tests or guide. The [roadmap](docs/parity/README.md) tracks the remaining features and the evidence for each completed behavior.

## Run it locally

Use a currently patched Go 1.26 or newer toolchain and a C compiler for SQLite. The example creates its tables on first start. Clone the repository, generate a signing secret, and start the app.

```sh
git clone https://github.com/Plain-Auth/plain-auth.git
cd plain-auth
export "$(go run ./cmd/authctl secret)"
export AUTH_URL=http://127.0.0.1:3000
go run ./examples/basic
```

The example listens on `http://127.0.0.1:3000` and creates `auth.db` in the working directory. Set `AUTH_DB` to change the path. Keep the same secret and database when restarting the example to preserve sessions.

In another terminal, create an account, call an application-owned route, and sign out.

```sh
curl -sS -c cookies.txt http://127.0.0.1:3000/api/auth/sign-up/email \
  -H 'Content-Type: application/json' \
  -d '{"name":"Ada","email":"ada@example.com","password":"example-password"}'

curl -sS -b cookies.txt http://127.0.0.1:3000/me

curl -sS -b cookies.txt -c cookies.txt http://127.0.0.1:3000/api/auth/sign-out \
  -H 'Origin: http://127.0.0.1:3000' -H 'Content-Type: application/json' -d '{}'
```

## Mount it in an application

From your application's Go module, install the SQLite adapter and the core library from `main`.

```sh
go get github.com/Plain-Auth/plain-auth/adapters/sqlite@main
```

Import the library and mount it on your router.

```go
import (
    "strings"

    "github.com/Plain-Auth/plain-auth"
    "github.com/Plain-Auth/plain-auth/adapters/sqlite"
)
```

```go
store, err := sqlite.Open("auth.db")
if err != nil {
    return err
}
defer store.Close() // in the function that owns the application's lifetime

instance, err := plainauth.New(plainauth.Options{
    Store:            store,
    EmailAndPassword: true,
})
if err != nil {
    return err
}
mux.Handle(strings.TrimRight(instance.BasePath(), "/")+"/", instance)
```

This reads the signing secret and public URL from the host environment configured above. Explicit options, environment settings and their precedence are documented in the [configuration guide](docs/environment.md).

Go records the resolved commit in the consuming project’s `go.mod`. The module path is `github.com/Plain-Auth/plain-auth`. Its Go package name is `plainauth`. The SQLite adapter lives at `github.com/Plain-Auth/plain-auth/adapters/sqlite`. A complete host application, including a protected route and graceful shutdown, is in [examples/basic](examples/basic/main.go).

## Supported workflows

- [x] Register with email, sign in, read a session, and sign out. [Client lifecycle test](conformance/core.test.mjs)
- [x] Register a username, authenticate by handle, and apply account policies and MFA. [Username sign-in](docs/username.md)
- [x] Issue revocable API keys, check permissions, and enforce usage limits on application routes. [API keys](docs/api-keys.md)
- [x] Use the same handler with ServeMux, chi, Gorilla Mux, Gin, Echo, or Fiber. [Router tests](integrations/routers/routers_test.go)
- [x] Generate auth tables and persist sessions on SQLite, PostgreSQL, and MySQL. [Storage contract](adapters/sqlstore/engines_test.go)
- [x] Store application fields on users and sessions, control which values clients can read or write, and migrate their SQL columns with `authctl`. [User fields](docs/user-fields.md) · [Session fields](docs/session-fields.md) · [Schema commands](docs/schema.md)
- [x] Recover a password and verify an email address through an application-provided sender. [Account tests](account_test.go)
- [x] Register a passkey and authenticate with it. [Software authenticator tests](adapters/sqlstore/passkey_test.go)
- [x] Sign in with a built-in provider. Use `providers.Names()` for the current catalog. [Browser fixtures](providers/catalog_test.go) · [OpenID Connect fixtures](providers/issuer_test.go) · [Apple and Microsoft](providers/apple_microsoft_test.go)
- [x] Sign in through an OAuth popup from a top-level page or a cross-site iframe. [Popup setup and Chrome tests](docs/oauth-popup.md)
- [x] Share a registered OAuth callback across trusted previews and create the session on the preview that started sign-in. [OAuth proxy setup](docs/oauth-proxy.md)
- [x] Configure tenant-specific sign-in with Auth0, Keycloak, Okta or Entra ID and additional OAuth profiles including LINE and HubSpot. [Provider setup](docs/social.md#auth0-keycloak-and-okta)
- [x] Verify a phone number, link it to an account and recover a password through the application’s SMS sender. [Phone accounts](docs/phone-number.md)
- [x] Verify an email address, sign in, change an address and reset a password using single-use email codes. [Email OTP](docs/email-otp.md)
- [x] Approve or deny a device login from a signed-in browser. [Device authorization](docs/device-authorization.md)
- [x] Remember multiple accounts in one browser and switch or revoke them. [Account switching](docs/multi-session.md)
- [x] Create a guest account and transfer its application records on sign-up. [Guest sessions](docs/anonymous.md)
- [x] Verify an authenticator, delivered code or single-use backup code and remember a trusted browser. [Two-factor authentication](docs/2fa.md)
- [x] Create organizations and teams, enforce seat limits and accept scoped invitations. [Organization tests](plugins/organization/organization_test.go)
- [x] Open a Polar checkout or customer portal, read the customer’s billing state, and reconcile signed checkout updates. [Polar setup and recovery](docs/polar.md)
- [x] Verify Stripe webhook signatures and open an authenticated customer’s billing portal. [Webhook tests](plugins/stripe/stripe_test.go) · [Billing portal tests](plugins/stripe/portal_test.go)
- [x] Start recurring Checkout, confirm a personal plan change, schedule a price for the next billing period, cancel or restore the subscription. [Subscription billing](docs/subscriptions.md)
- [x] Choose licensed seat quantities for personal and organization checkout, review quantity changes in Stripe, and list confirmed subscriptions. [Organization billing](docs/subscriptions.md)
- [x] Bill organization seats monthly or annually, with an optional fixed base price, and synchronize the quantity after membership changes. [Automatic seats](docs/subscriptions.md#bill-by-organization-membership)
- [x] Register enterprise OIDC or SAML providers, optionally verify their domains with DNS, sign in with a browser, and provision members in the provider’s organization. [Enterprise single sign-on](docs/sso.md)
- [x] Provision directory Users and Groups, synchronize direct memberships and rotate or revoke scoped SCIM credentials. [Directory provisioning](docs/scim.md)
- [x] Map directory Group memberships to application roles and withdraw grants when their last source is removed. [SCIM role mapping](docs/scim.md#project-group-memberships-into-application-roles)

Stripe Checkout and signed billing updates support a single metered price or metered add-ons with a licensed base. IdP-initiated SAML, SAML single logout, and plan switches involving metered prices remain open. The [complete checklist](docs/parity/README.md) records which parts of each integration have passing tests.

For integration tests, create fixture users and organizations, capture email or SMS codes, or import an existing test login into a browser. [Test helpers](docs/test-helpers.md)

## Documentation

| Task | Guide |
| --- | --- |
| Load signing secrets, the public URL, and trusted origins from the environment | [Environment configuration](docs/environment.md) |
| Mount on ServeMux, chi, Gorilla Mux, Gin, Echo, or Fiber | [Router integrations](docs/routers.md) |
| Configure users, cookies, origins, and session management | [Authentication](docs/authentication.md) |
| Remember the last sign-in method in a browser or across a user's devices | [Login preferences](docs/plugins.md#persist-the-last-login-method) |
| Add account switching to a shared device | [Device sessions](docs/multi-session.md) |
| Share login cookies across approved sibling hosts | [Cookie configuration](docs/authentication.md) |
| Access application routes with revocable API keys | [API keys](docs/api-keys.md) |
| Define roles and check resource permissions in application handlers | [Role permissions](docs/access.md) |
| Share a request limit across server instances using Redis or Valkey | [Redis secondary storage](docs/redis.md) |
| Return translated authentication errors in 22 bundled languages | [Localization](docs/localization.md) |
| Generate an OpenAPI document and browse the routes enabled in this application | [OpenAPI reference](docs/openapi.md) |
| Authorize a TV, CLI or input-constrained device | [Device authorization](docs/device-authorization.md) |
| Transfer an active session using a single-use credential | [One-time tokens](docs/one-time-token.md) |
| Integrate the Google One Tap prompt or sign-in button | [Google One Tap](docs/one-tap.md) |
| Sign in with an Ethereum wallet | [Wallet sign-in](docs/siwe.md) |
| Register and use a WebAuthn passkey | [Passkeys](docs/passkeys.md) |
| Verify an address, sign in or recover a password with an email code | [Email one-time passwords](docs/email-otp.md) |
| Let users sign in through a single-use email link | [Magic links](docs/magic-link.md) |
| Enroll an authenticator and manage backup codes | [Two-factor authentication](docs/2fa.md) |
| Generate optional organization, team, passkey, rate-limit, subscription, and two-factor tables | [Schema profiles](docs/schema.md) |
| Require a CAPTCHA verdict on selected routes | [CAPTCHA providers](docs/captcha.md) |
| Read current OIDC profile and email claims using a signed or opaque access token | [OpenID Connect UserInfo](docs/oauth-userinfo.md) |
| Publish OAuth issuers and scopes, verify DPoP proofs and return authentication challenges from a protected API | [Resource discovery and challenges](docs/oauth-resource-discovery.md) |
| Discover machine grant endpoints, authentication methods and signing keys from an issuer URL | [Authorization-server discovery](docs/oauth-issuer-discovery.md) |
| Sign in, choose an account, collect consent and exchange a PKCE code for access or offline refresh tokens | [Browser authorization and code exchange](docs/oauth-authorization-code.md) |
| Register OAuth resources, change their policies, and link registered clients | [Resource management](docs/oauth-resource-management.md) |
| List, inspect, update and remove a user’s OAuth consent grants | [Authorized applications](docs/oauth-consents.md) |
| Register OAuth clients and rotate confidential client secrets | [OAuth client registration](docs/oauth-client-registration.md) |
| Grant or revoke machine-to-machine scopes from Go server code | [Machine scope management](docs/oauth-client-registration.md#grant-machine-to-machine-scopes) |
| Issue signed or opaque machine tokens with resource audiences, scoped permissions and sender binding | [Machine access tokens](docs/machine-tokens.md#request-access-to-a-resource) · [Token introspection](docs/machine-tokens.md#check-whether-a-token-is-active) |
| Authenticate an OAuth application with its own signing key and rotate its keys | [Signed client assertions](docs/oauth-client-assertions.md) |
| Rotate a refresh token, narrow its scopes or check its session | [Refresh exchange](docs/oauth-authorization-code.md#exchange-a-refresh-token) · [Refresh token introspection](docs/machine-tokens.md#inspect-a-refresh-token) |
| Inspect a delegated opaque token using an application or resource server credential | [Delegated token introspection](docs/machine-tokens.md#inspect-a-delegated-token-as-a-resource-server) |
| Check signed OAuth access tokens against current client, session and resource state | [Signed token introspection](docs/machine-tokens.md#inspect-a-signed-access-token) |
| Revoke an OAuth token or invalidate a replayed refresh-token family | [Token revocation](docs/oauth-token-revocation.md) |
| List or delete registered applications and show client details on a consent screen | [Manage registered applications](docs/oauth-client-directory.md) |
| Issue signed service tokens and publish verification keys | [JWT and JWKS](docs/jwt.md) |
| Check new passwords against a breached-password service | [Password screening](docs/password-checks.md) |
| Configure profile updates, password reset, and verification email | [Account management and recovery](docs/account.md) |
| Generate tables and migrate SQLite, PostgreSQL, or MySQL | [Databases and CLI](docs/databases.md) |
| Register a username and sign in with a password | [Username sign-in](docs/username.md) |
| Manage users, ban accounts and grant administrative access | [Administrator accounts](docs/admin.md) |
| Create organizations and teams, grant memberships, and accept invitations | [Organizations](docs/organizations.md) |
| Start recurring Checkout, synchronize subscription changes, cancel, and restore | [Subscription billing](docs/subscriptions.md) |
| Set up Polar checkout, billing state, the customer portal and signed webhooks | [Polar hosted checkout](docs/polar.md) |
| Add a custom endpoint, verify Stripe webhooks, or open the billing portal | [Plugins and Stripe](docs/plugins.md) |
| Configure browser sign-in, native ID tokens and linked provider credentials | [Social sign-in](docs/social.md) |
| Call the API from a Go service | [Go client](docs/client.md) |
| Work on a feature, run checks, and update the checklist in GitHub | [Contributing](CONTRIBUTING.md) |

## License

Maintained by Nabil Abu-Hadba and distributed under the [MIT license](LICENSE).
