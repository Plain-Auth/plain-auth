# FineStack Auth

FineStack Auth embeds authentication in your Go API. Mount the auth handler on your router and use the same instance to read the signed-in user inside your own handlers. Your application owns its listener, database lifetime, middleware, and routes.

**Development status.** The [feature checklist](docs/parity/README.md) lists supported behavior, passing tests, and planned features. Browse [authentication](docs/parity/authentication.md), [databases](docs/parity/adapters.md), [integrations](docs/parity/integrations.md), or [Stripe](docs/parity/plugins/stripe.md).

## Supported workflows

- [x] Register with email, sign in, read a session, and sign out. [Client lifecycle test](conformance/core.test.mjs)
- [x] Use the same handler with ServeMux, chi, Gorilla Mux, Gin, or Fiber. [Router tests](integrations/routers/routers_test.go)
- [x] Generate auth tables and persist sessions on SQLite, PostgreSQL, and MySQL. [Storage contract](adapters/sqlstore/engines_test.go)
- [x] Recover a password and verify an email address through an application-provided sender. [Account tests](account_test.go)
- [x] Register a passkey and authenticate with it. [Software authenticator tests](adapters/sqlstore/passkey_test.go)
- [x] Sign in using 36 built-in provider configurations. [Browser fixtures](providers/catalog_test.go) · [OpenID Connect fixtures](providers/issuer_test.go) · [Apple and Microsoft](providers/apple_microsoft_test.go)
- [x] Verify an email address, sign in, change an address and reset a password using single-use email codes. [Email OTP](docs/email-otp.md)
- [x] Approve or deny a device login from a signed-in browser. [Device authorization](docs/device-authorization.md)
- [x] Remember multiple accounts in one browser and switch or revoke them. [Account switching](docs/multi-session.md)
- [x] Sign in with an authenticator or a single-use backup code. [Two-factor tests](adapters/sqlstore/twofactor_test.go)
- [x] Create organizations and teams, enforce seat limits and accept scoped invitations. [Organization tests](plugins/organization/organization_test.go)
- [x] Verify Stripe webhook signatures and open an authenticated customer’s billing portal. [Webhook tests](plugins/stripe/stripe_test.go) · [Billing portal tests](plugins/stripe/portal_test.go)

Single sign-on, SCIM provisioning and automated subscription renewals remain open. The [complete checklist](docs/parity/README.md) records which parts of each integration have passing tests.

## Run it locally

Use Go 1.26 or newer and a C compiler for the SQLite driver. Clone this repository using a GitHub account with access. From the checkout, generate a signing secret once and start the example.

```sh
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

Import the current module to use the `fineauth` package.

```go
import (
    "github.com/FineStack/finestack-auth"
    "github.com/FineStack/finestack-auth/adapters/sqlite"
)
```

```go
store, err := sqlite.Open("auth.db")
if err != nil {
    return err
}
defer store.Close() // in the function that owns the application's lifetime

instance, err := fineauth.New(fineauth.Options{
    Store:            store,
    EmailAndPassword: true,
})
if err != nil {
    return err
}
mux.Handle(strings.TrimRight(instance.BasePath(), "/")+"/", instance)
```

This reads the signing secret and public URL from the host environment configured above. Explicit options, environment settings and their precedence are documented in the [configuration guide](docs/environment.md).

During private development, authenticate Git for the FineStack repository and run the following in the consuming module.

```sh
GOPRIVATE=github.com/FineStack/finestack-auth go get github.com/FineStack/finestack-auth@main
```

Go records the resolved commit in the consuming project’s `go.mod`. The module path is `github.com/FineStack/finestack-auth`. Its Go package name is `fineauth`. The SQLite adapter lives at `github.com/FineStack/finestack-auth/adapters/sqlite`. A complete host application, including a protected route and graceful shutdown, is in [examples/basic](examples/basic/main.go).

| Task | Guide |
| --- | --- |
| Load signing secrets, the public URL, and trusted origins from the environment | [Environment configuration](docs/environment.md) |
| Mount on ServeMux, chi, Gorilla Mux, Gin, or Fiber | [Router integrations](docs/routers.md) |
| Configure users, cookies, origins, and session management | [Authentication](docs/authentication.md) |
| Remember the last sign-in method in a browser or across a user's devices | [Login preferences](docs/plugins.md#persist-the-last-login-method) |
| Add account switching to a shared device | [Device sessions](docs/multi-session.md) |
| Authorize a TV, CLI or input-constrained device | [Device authorization](docs/device-authorization.md) |
| Transfer an active session using a single-use credential | [One-time tokens](docs/one-time-token.md) |
| Integrate the Google One Tap prompt or sign-in button | [Google One Tap](docs/one-tap.md) |
| Register and use a WebAuthn passkey | [Passkeys](docs/passkeys.md) |
| Verify an address, sign in or recover a password with an email code | [Email one-time passwords](docs/email-otp.md) |
| Let users sign in through a single-use email link | [Magic links](docs/magic-link.md) |
| Enroll an authenticator and manage backup codes | [Two-factor authentication](docs/2fa.md) |
| Generate optional organization, team, passkey, rate-limit, subscription, and two-factor tables | [Schema profiles](docs/schema.md) |
| Require a CAPTCHA verdict on selected routes | [CAPTCHA providers](docs/captcha.md) |
| Issue signed service tokens and publish verification keys | [JWT and JWKS](docs/jwt.md) |
| Check new passwords against a breached-password service | [Password screening](docs/password-checks.md) |
| Configure profile updates, password reset, and verification email | [Account management and recovery](docs/account.md) |
| Generate tables and migrate SQLite, PostgreSQL, or MySQL | [Databases and CLI](docs/databases.md) |
| Create organizations and teams, grant memberships, and accept invitations | [Organizations](docs/organizations.md) |
| Start recurring Checkout and list subscriptions | [Subscription billing](docs/subscriptions.md) |
| Add a custom endpoint, verify Stripe webhooks, or open the billing portal | [Plugins and Stripe](docs/plugins.md) |
| Configure browser sign-in, native ID tokens and linked provider credentials | [Social sign-in](docs/social.md) |
| Call the API from a Go service | [Go client](docs/client.md) |
| Work on a feature, run checks, and update the checklist in GitHub | [Contributing](CONTRIBUTING.md) |

## License

Maintained by Nabil Abu-Hadba and distributed under the [MIT license](LICENSE).
