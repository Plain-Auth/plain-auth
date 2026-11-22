# Register an OAuth client

Enable dynamic registration when other applications need to obtain their own OAuth client IDs from your service. A signed-in user can register a web or native application. A host-defined initial access token can authorize a registration without a browser session. Open registration is optional.

## Enable registration

Set `AUTH_URL` to your auth service's public base URL and `AUTH_SECRET` to its secret. Use the `oauth-provider` database profile with SQLite, PostgreSQL or MySQL. This example returns an HTTP handler you can mount in your existing Go server. The application owns the store and closes it during shutdown. [Environment](environment.md) · [Schema and migrations](schema.md#oauth-authorization-server-tables) · [Router examples](routers.md)

```go
package example

import (
    "context"

    auth "github.com/Plain-Auth/plain-auth"
    "github.com/Plain-Auth/plain-auth/adapters/sqlstore"
    "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
    "github.com/Plain-Auth/plain-auth/schema"
)

func Open(ctx context.Context, dialect, dsn string) (*auth.Auth, *sqlstore.Store, error) {
    plugin, err := oauthprovider.New(oauthprovider.Options{
        Scopes: []string{"openid", "reports:read"},
        Registration: oauthprovider.RegistrationOptions{
            Enabled: true,
            DefaultScopes: []string{"openid"},
            AllowedScopes: []string{"reports:read"},
            DefaultApplicationType: "infer",
        },
    })
    if err != nil {
        return nil, nil, err
    }
    store, err := sqlstore.OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
    if err != nil {
        return nil, nil, err
    }
    api, err := auth.New(auth.Options{
        Store: store, EmailAndPassword: true, Plugins: []auth.Plugin{plugin},
    })
    if err != nil {
        store.Close()
        return nil, nil, err
    }
    return api, store, nil
}
```

The plugin also installs application lookup and the signed-in user's consent management endpoints. A custom store supporting registration implements both `oauthprovider.ConsentStore` and `oauthprovider.RegistrationStore`. [Managing authorized applications](oauth-consents.md) · [Reading registered applications](oauth-client-directory.md)

## Choose who can register

| Configuration or credential | What happens |
| --- | --- |
| Default (`Enabled: false`) | The endpoint rejects registration with HTTP 403. |
| `Enabled: true` and a signed-in account owner | The client's owner is the session user. Use `MayCreate` to check application permissions and `ClientReference` to assign a tenant or other owner. A session takes precedence over a bearer token. |
| `ValidateInitialToken` and an `Authorization: Bearer` header | The host validates its own initial access token. Returning an `InitialAuthorization` admits the request and can assign a trusted reference ID. Returning `nil, nil` denies it. |
| `AllowUnauthenticated: true` | A caller without credentials can register a client. Requesting a machine-to-machine grant still requires authentication. An invalid bearer token is rejected. |

When authentication is required, a request without credentials receives HTTP 401 and a `WWW-Authenticate: Bearer` challenge. An invalid initial token receives 401 with `invalid_token`. A malformed bearer header receives 400. With host rate limiting enabled, the route accepts five requests per minute per client IP by default. Set `Registration.RateLimit` to override the route rule.

## Register from a browser or Go

Send JSON to `POST /api/auth/oauth2/register` on the default mount. For example, this request registers a public native app using a signed-in user's session.

```js
const response = await fetch("/api/auth/oauth2/register", {
  method: "POST",
  credentials: "same-origin",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    client_name: "Reports Mobile",
    application_type: "native",
    redirect_uris: ["com.example.reports:/oauth/return"],
    token_endpoint_auth_method: "none",
    scope: "reports:read"
  })
})
if (response.status !== 201) throw new Error(await response.text())
const { client_id } = await response.json()
```

With the example server configuration, the client's scope ceiling is `openid reports:read`. The server validates the requested `scope` against the union of default and allowed scopes, then stores and returns that union. Choose defaults and allowed scopes that every eligible application can request. Each new client starts with an empty machine-to-machine scope grant.

The Go SDK accepts the same metadata. Pass a signed-in SDK client, or use `WithBearerToken` to register on behalf of an integration whose initial token the host recognizes.

```go
func registerIntegration(ctx context.Context, api *client.Client, initialToken string) (oauthprovider.RegisteredClient, error) {
    caller, err := api.WithBearerToken(initialToken)
    if err != nil {
        return oauthprovider.RegisteredClient{}, err
    }
    return caller.RegisterOAuthClient(ctx, oauthprovider.RegistrationMetadata{
        GrantTypes: []string{"client_credentials"},
        TokenEndpointAuthMethod: "client_secret_post",
    })
}
```

Import `github.com/Plain-Auth/plain-auth/client` for the SDK. A successful response has HTTP 201, a generated `client_id`, the issue time in Unix seconds, and the accepted metadata. Responses carrying credentials use `Cache-Control: no-store`. Capture an issued secret at registration and keep it on the confidential application's server.

## Configure client metadata and storage

| Setting | Behavior |
| --- | --- |
| Client authentication | `client_secret_basic` (default) and `client_secret_post` issue a random secret. `none` registers a public client. `private_key_jwt` accepts either an inline public asymmetric JWK Set or a public HTTPS `jwks_uri` on a trusted origin. |
| Redirects | Web clients normally use HTTPS. Native clients may use HTTPS, exact HTTP loopback redirects or private-use application schemes. `DefaultApplicationType` accepts `web`, `native` or `infer`. The `AllowHTTPRedirect` callback can approve a specific development URI. |
| PKCE and subject identifiers | PKCE is required by default. Setting `RequirePKCE` to a pointer to false permits confidential clients to opt out. Public clients retain the requirement. For pairwise subject metadata, configure a `PairwiseSecret` of at least 32 bytes and use redirect URIs on one host. |
| Resource links | Seed or create resources first. `DefaultResources` links every new client to those resources. `AllowedResources` permits additional requested links. A missing, disabled or disallowed resource fails the whole registration. The SQL adapter commits the client and all links in one transaction. |
| Secret handling | By default, SQL stores the base64url SHA-256 digest. The optional `SecretPrefix` appears on the issued credential. A custom `StoreSecret` callback receives the unprefixed value. Shared secrets currently have no expiry and return `client_secret_expires_at: 0`. |
| Other metadata | The server also stores display information, contacts, software metadata, post-logout URIs and DPoP preferences. Client credentials, ownership and privilege fields are assigned by the server. |

A registered confidential application can exchange a shared secret or a signed client assertion for an opaque machine token after an operator grants it machine scopes. [Machine access tokens](machine-tokens.md) · [Signed client assertions](oauth-client-assertions.md) · [Resource management](oauth-resource-management.md) · [Feature checklist](parity/plugins/oauth-provider.md) · [Registration tests](../conformance/oauth-registration.mjs)

## Rotate a shared secret

A personal owner or an authorized member of the owning tenant can rotate a confidential application's credential. Send a signed-in session to `POST /api/auth/oauth2/client/rotate-secret` with the JSON body `{"client_id":"your-client-id"}`. Rotation also works when dynamic registration is disabled. Native and browser clients that use `none` or `private_key_jwt` use different credential mechanisms.

On success, HTTP 200 returns the owner-visible client metadata and the replacement in `client_secret`. Capture the replacement in your application's secret manager, then use it for the next client authentication. The previous secret stops authenticating as soon as the transaction commits. If the one-time response is lost, the owner can rotate again. Rotation changes the credential used for future token requests. Previously issued tokens follow their own expiration and revocation policies.

The Go SDK accepts a signed-in client. This helper hands the issued credential directly to the host's secret manager.

```go
func rotate(ctx context.Context, signedIn *client.Client, id string, save func(context.Context, string, string) error) error {
    updated, err := signedIn.RotateOAuthClientSecret(ctx, id)
    if err != nil {
        return err
    }
    return save(ctx, id, updated.ClientSecret)
}
```

Configure the host's `ClientPrivileges` callback to restrict the `rotate` action. Set `Options.ImmutableClientIDs` for credentials managed exclusively by the operator. Both the client ID and action are available to the privilege callback. Rotation uses the same credential generator, secret prefix and storage hook as registration. A custom generator should return a fresh random credential each time.

| Response | Meaning |
| --- | --- |
| 400 `invalid_client` | The client is operator-managed or has no shared credential to rotate. |
| 401 | The session is absent, the caller lacks the rotate privilege, or the registration belongs to another owner. |
| 403 `OWNER_SESSION_REQUIRED` | The caller uses an impersonation session or delegated application credential. |
| 404 `not_found` | The client is missing or requires an unresolved discovery provider. |

The SQL adapters recheck ownership and authentication method under a database lock. A failed storage operation rolls back. If multiple rotations succeed, the last committed credential is the active one. A custom adapter implements `oauthprovider.SecretRotationStore` for the same transaction guarantee. [Client directory and tenant authorization](oauth-client-directory.md) · [Database concurrency tests](../adapters/sqlstore/oauth_secret_rotation_test.go) · [Protocol tests](../conformance/oauth-registration.mjs)

## Grant machine-to-machine scopes

A newly registered confidential client starts with zero machine permissions. Give it the `client_credentials` grant at registration and configure its scopes from trusted Go server code. The ordinary `scope` field describes user-delegated access. The machine grant is stored separately.

Use the same `oauthprovider.Options` for `oauthprovider.New` and `oauthprovider.NewClientManager`. Include each allowed machine scope in `Options.Scopes`. The example policy reserves client management for one operator. An application with multiple roles can check its own permission store using the session user, action and client ID.

```go
func operatorOptions(operatorID string) oauthprovider.Options {
    return oauthprovider.Options{
        Scopes: []string{"openid", "reports:read", "reports:write"},
        ClientPrivileges: func(_ context.Context, actor oauthprovider.ClientAccess) (bool, error) {
            return actor.User.ID == operatorID, nil
        },
    }
}

func grantReportAccess(ctx context.Context, headers http.Header, api *auth.Auth, store *sqlstore.Store, opts oauthprovider.Options, id string) ([]string, error) {
    manager, err := oauthprovider.NewClientManager(api, store, opts)
    if err != nil {
        return nil, err
    }
    return manager.SetClientCredentialsScopes(ctx, headers, id, []string{"reports:read"})
}
```

`headers` carries the caller's signed-in session. The method replaces the whole machine grant and returns the stored list. Pass an empty slice to revoke every scope. Each name must contain a non-whitespace character. The manager trims names and removes duplicates in input order. User scopes such as `openid`, `profile`, `email` and `offline_access` cannot be assigned to a machine.

Changes apply to subsequent token exchanges. When a client omits `scope`, the issuer uses its machine grant. The Go token endpoint accepts Basic and form credentials for opaque machine tokens. The comparison tests verify issued tokens at an independent authorization server. [Issue a machine access token](machine-tokens.md)

| Caller and operation | Required policy decisions |
| --- | --- |
| Personal or tenant owner clears the grant | `update` |
| Owner assigns scopes | `update` and `configure-client-credentials-scopes` |
| Operator assigns or clears another owner's grant | `update` and `configure-client-credentials-scopes` |

With no privilege callback, an owner can clear a grant. Assigning scopes requires explicit approval. An impersonated session cannot change grants. Operator-managed IDs are immutable. SQLite, PostgreSQL and MySQL recheck ownership, grant type and client authentication method in the write transaction. An application exposing its own browser-facing management route must verify the request origin before forwarding a cookie-authenticated mutation. [Database and privilege tests](../adapters/sqlstore/oauth_client_scopes_test.go) · [Issuer comparison](../conformance/oauth-registration.mjs) · [OAuth checklist](parity/plugins/oauth-provider.md)
