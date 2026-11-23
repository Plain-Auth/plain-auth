# Plain Auth

[![Verify](https://github.com/Plain-Auth/plain-auth/actions/workflows/verify.yml/badge.svg?branch=main)](https://github.com/Plain-Auth/plain-auth/actions/workflows/verify.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Plain-Auth/plain-auth.svg)](https://pkg.go.dev/github.com/Plain-Auth/plain-auth)

Plain Auth is an authentication library for Go servers. Mount its `http.Handler` on your router, then use the same instance in your own handlers to read the signed-in user. Your application keeps its listener, middleware, routes, database and screens, and any frontend or HTTP client can call the JSON API.

> **Developer preview.** APIs and SQL migrations may change before the first tagged release. The [roadmap](docs/parity/README.md) shows what is finished and what remains, with a test linked to every completed behavior.

## What it does

- **Sign in** with email and password, usernames, magic links, email or SMS codes, passkeys, social providers, Google One Tap, Ethereum wallets or guest accounts.
- **Sessions** that are database-backed and revocable, with optional cookie caching, several accounts per browser, device authorization and cross-subdomain cookies.
- **Security**: two-factor authentication, rate limits shared through Redis or Valkey, CAPTCHA, breached-password checks and trusted origins.
- **Organizations and teams** with roles, permissions, invitations and member limits, plus administrator accounts and API keys.
- **Enterprise**: OIDC and SAML single sign-on, and SCIM directory provisioning.
- **OAuth 2.0 and OpenID Connect provider**: authorization code with PKCE, refresh tokens, client registration, introspection, revocation and JWKS.
- **Billing** with Stripe subscriptions and seats, or Polar checkout.
- **Storage and tools**: SQLite, PostgreSQL and MySQL, the `authctl` schema CLI, an OpenAPI document, error messages in 22 languages and test helpers.
- **Extend** with Go plugins and endpoint hooks that reject, rewrite or answer requests and change their results.

Every capability has a guide in the [documentation index](docs/README.md).

## Quickstart

Use a patched Go 1.26 or newer toolchain and a C compiler (for SQLite). Clone the repository, generate a signing secret and start the example app.

```sh
git clone https://github.com/Plain-Auth/plain-auth.git
cd plain-auth
export "$(go run ./cmd/authctl secret)"
export AUTH_URL=http://127.0.0.1:3000
go run ./examples/basic
```

The example listens on `http://127.0.0.1:3000` and creates `auth.db` in the working directory (set `AUTH_DB` to change it). In another terminal, create an account, call a protected route and sign out:

```sh
curl -sS -c cookies.txt http://127.0.0.1:3000/api/auth/sign-up/email \
  -H 'Content-Type: application/json' \
  -d '{"name":"Ada","email":"ada@example.com","password":"example-password"}'

curl -sS -b cookies.txt http://127.0.0.1:3000/me

curl -sS -b cookies.txt -c cookies.txt http://127.0.0.1:3000/api/auth/sign-out \
  -H 'Origin: http://127.0.0.1:3000' -H 'Content-Type: application/json' -d '{}'
```

## Add it to your app

Install the SQLite adapter, which also brings in the core library, from `main`:

```sh
go get github.com/Plain-Auth/plain-auth/adapters/sqlite@main
```

Create one instance and mount it under its base path (`/api/auth` by default):

```go
import (
    "strings"

    "github.com/Plain-Auth/plain-auth"
    "github.com/Plain-Auth/plain-auth/adapters/sqlite"
)

store, err := sqlite.Open("auth.db")
if err != nil {
    return err
}
defer store.Close() // in the function that owns the application's lifetime

auth, err := plainauth.New(plainauth.Options{
    Store:            store,
    EmailAndPassword: true,
})
if err != nil {
    return err
}
mux.Handle(strings.TrimSuffix(auth.BasePath(), "/")+"/", auth)
```

Inside your own handlers, `auth.GetSession(r.Context(), r.Header)` returns the signed-in user, or `nil` when the request is anonymous. `New` reads `AUTH_SECRET` and `AUTH_URL` from the environment; see [environment configuration](docs/environment.md) for every setting. The module path is `github.com/Plain-Auth/plain-auth` and the package name is `plainauth`.

- [examples/basic](examples/basic/main.go): a complete host app with a protected route and graceful shutdown
- [Router integrations](docs/routers.md): ServeMux, chi, Gorilla Mux, Gin, Echo and Fiber
- [Databases and the CLI](docs/databases.md): PostgreSQL, MySQL and schema migrations
- [Go client](docs/client.md): call the API from another Go service

## Project

- [Documentation](docs/README.md): every guide, grouped by task
- [Roadmap](docs/parity/README.md): the feature checklist and its test evidence
- [Contributing](CONTRIBUTING.md): local setup, source layout and checks
- [Security](SECURITY.md): report a vulnerability privately
- [MIT license](LICENSE), maintained by Nabil Abu-Hadba

<sub>A hosted Plain Auth service is coming soon for teams that would rather not run it themselves.</sub>
