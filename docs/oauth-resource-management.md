# Manage OAuth resources

An OAuth resource identifies a protected API, for example `https://api.example.com/reports` or `urn:example:billing`. Use `oauthprovider.ResourceManager` in your application’s server code to register an audience, edit its policy, and link it to registered clients. The manager uses your existing signed-in session and the same database as your auth handler. Its methods are available from any Go router.

## Configure the store and permissions

Enable the `oauth-provider` SQL profile on SQLite, PostgreSQL, or MySQL. The application owns the store and closes it at shutdown. Configure the auth instance with `AUTH_URL` and `AUTH_SECRET` or the corresponding Go options. [Schema and CLI commands](schema.md#oauth-authorization-server-tables) · [Environment settings](environment.md)

```go
import (
    "context"

    auth "github.com/Plain-Org/plain-auth"
    "github.com/Plain-Org/plain-auth/adapters/sqlstore"
    "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
    "github.com/Plain-Org/plain-auth/schema"
)

func openRegistry(ctx context.Context, dialect, dsn, operatorID string) (*sqlstore.Store, *auth.Auth, *oauthprovider.ResourceManager, error) {
    store, err := sqlstore.OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
    if err != nil {
        return nil, nil, nil, err
    }
    api, err := auth.New(auth.Options{Store: store, EmailAndPassword: true})
    if err != nil {
        store.Close()
        return nil, nil, nil, err
    }
    registry, err := oauthprovider.NewResourceManager(api, store, oauthprovider.ResourceManagerOptions{
        Privileges: func(ctx context.Context, access oauthprovider.ResourceAccess) (bool, error) {
            return access.User.ID == operatorID, nil
        },
    })
    if err != nil {
        store.Close()
        return nil, nil, nil, err
    }
    return store, api, registry, nil
}
```

Mount `api` on your application’s auth route. Keep `registry` in the server code handling your administrative actions. Each call accepts the request context and headers from your application. The auth handler exposes no public resource-management endpoints. An unauthenticated or revoked session receives a 401. With no `Privileges` callback, any authenticated session passed by the host application can perform all seven operations. Install a callback to restrict access as in the example.

The callback receives the user, session, headers and action. The actions are `create`, `list`, `read`, `update`, `delete`, `link` and `unlink`. The last five include the affected resource identifier. A denied caller receives a 401 before the registry reads or changes the resource. A callback error propagates to the host.

## Register and edit an audience

Pass an absolute URI with no fragment. A URN is valid. To use application-defined names, set `ResourceManagerOptions.IdentifierValidator` to a function accepting `(context.Context, string)` and returning `(bool, error)`. The function replaces the URI check on creation. Lookups accept the exact stored identifier, including case, query and literal percent escapes. When forwarding an identifier from a Go HTTP route, pass the decoded path parameter, such as `r.PathValue("identifier")`.

```go
func registerReports(ctx context.Context, h http.Header, registry *oauthprovider.ResourceManager) (oauthprovider.Resource, error) {
    return registry.Create(ctx, h, "https://api.example.com/reports", oauthprovider.ResourcePatch{
        Name:           oauthprovider.Set("Reports"),
        AllowedScopes:  oauthprovider.Set([]string{"reports:read"}),
        AccessTokenTTL: oauthprovider.Set(int64(300)),
    })
}
```

The example uses `net/http` for `http.Header`. The name defaults to the identifier. A new row has a generated ID, creation and update timestamps, policy version 1, and both boolean flags set to false. `Get` returns one resource by identifier and `List` returns all stored resources. A duplicate identifier returns a 400. Missing resources return a 404 on read, update or delete.

| Policy field | Values |
| --- | --- |
| `Name` | Display name, including an explicitly empty name |
| `AccessTokenTTL`, `RefreshTokenTTL` | Positive 32-bit token lifetimes in seconds |
| `SigningAlgorithm`, `SigningKeyID` | A signing algorithm and optional key identifier. Supported algorithm values are EdDSA, ES256, ES512, PS256 and RS256. |
| `AllowedScopes` | A list of scope names. The registry preserves an empty list and SQL NULL as distinct values. |
| `CustomClaims`, `Metadata` | JSON objects expressed in Go as `map[string]json.RawMessage` |
| `DPoPBoundAccessTokensRequired`, `Disabled` | Boolean resource-policy flags |

On update, omit a field to preserve its stored value. Use `Set` to write a value, including false or an empty list. Use `Clear` on a nullable setting to restore inheritance. A JSON patch follows the same rules for omitted properties and explicit nulls. The identifier and policy version are immutable through this API.

```go
updated, err := registry.Update(ctx, headers, resource.Identifier, oauthprovider.ResourcePatch{
    AllowedScopes:   oauthprovider.Set([]string{"reports:read", "reports:export"}),
    RefreshTokenTTL: oauthprovider.Clear[int64](),
})
```

## Seed resources at startup

Declare audiences in `ResourceManagerOptions.Resources` when an application needs the same initial policies on each installation. Call `Seed(ctx)` after applying the SQL migrations. The call uses trusted application configuration and can run before a user signs in.

```go
func seedResources(ctx context.Context, api *auth.Auth, store *sqlstore.Store, operatorID string) (*oauthprovider.ResourceManager, error) {
    registry, err := oauthprovider.NewResourceManager(api, store, oauthprovider.ResourceManagerOptions{
        Privileges: func(_ context.Context, access oauthprovider.ResourceAccess) (bool, error) {
            return access.User.ID == operatorID, nil
        },
        SeedMode: oauthprovider.SeedInsertOnly,
        Resources: []oauthprovider.ResourceDefinition{
            {Identifier: "urn:example:billing"},
            {Identifier: "https://api.example.com/reports", Policy: oauthprovider.ResourcePatch{
                Name:           oauthprovider.Set("Reports"),
                AccessTokenTTL: oauthprovider.Set(int64(300)),
                AllowedScopes:  oauthprovider.Set([]string{"reports:read"}),
            }},
        },
    })
    if err != nil {
        return nil, err
    }
    return registry, registry.Seed(ctx)
}
```

JSON configuration accepts both a string identifier and a flat object. For example, decode `["urn:example:billing", {"identifier":"urn:example:reports","accessTokenTtl":300}]` into `[]oauthprovider.ResourceDefinition`. The manager takes a snapshot of this configuration when it is constructed.

| Mode | Behavior for an existing resource |
| --- | --- |
| `SeedInsertOnly` (default) | Preserves the existing row, including administrative edits and its update time. |
| `SeedMerge` | Updates the supplied fields. An explicit null clears a nullable setting. |
| `SeedOverwrite` | Replaces every policy field. Omitted fields return to defaults and policy version returns to 1. The identifier, row ID and creation time are preserved. |

All three modes insert missing resources. Concurrent application starts can seed the same identifier. If another process inserts it first, merge and overwrite still apply the configured policy. An invalid identifier is skipped and logged. An unsupported signing algorithm is logged and omitted from the seed, so other audiences and valid fields can still be applied.

If a table or connection is unavailable, `Seed` returns an error. A later call to `Seed` or an authorized registry operation retries unfinished entries. Completed entries keep subsequent administrative edits during that retry.

By default the manager remembers its completed configuration. For applications that construct a manager per request, allocate one `new(oauthprovider.ResourceSeedCache)` for each logical database and pass it as `ResourceManagerOptions.SharedSeeds` to each manager using that database. Each successful entry is remembered by its configuration and seed mode for the lifetime of that cache. Changed declarations and previously rejected identifiers can still run. Custom adapters that support overwrite implement `ResourcePolicyReplacer` as well as `ResourceStore`. [Concurrent startup and migration recovery tests](../adapters/sqlstore/oauth_resource_seed_test.go) · [Startup comparison tests](../conformance/resource-seeds.mjs)

### Declare resources on the provider

`oauthprovider.Options.Resources` declares the same definitions on the provider itself, with `ResourceSeedMode` and `SharedResourceSeeds` in the roles of `SeedMode` and `SharedSeeds`. The provider seeds them on the first request to any auth endpoint, as another runtime seeds its declared resources at startup, because a Go plugin has no store-backed startup step. Declared identifiers follow the standard rule: the provider, and so `mcp.New`, takes no identifier validator, where another runtime's provider takes `identifierValidator`; declare application-defined names through a `ResourceManager` with `IdentifierValidator` instead. A failure there is logged and the request goes on; resource-targeted machine token issuance and a registration that links resources retry an unfinished seed first and fail if it fails again. Registration `DefaultResources` and `AllowedResources` must be declared here, and `New` refuses one that is not. The store must implement `ResourceStore`, and `ResourcePolicyReplacer` for overwrite. The provider reads resource policy from the store on every lookup, so another runtime's resource and trusted-client caches have no counterpart. [Provider seeding tests](../adapters/sqlstore/oauth_provider_seed_test.go)

## Grant or remove client access

Pass the public client ID from a registered OAuth client. `Link` verifies that both the resource and client exist and persists one link per pair. First-time success returns `Linked: true`. Repeated or concurrent calls return `AlreadyLinked: true` for the existing link.

```go
grant, err := registry.Link(ctx, headers, resource.Identifier, clientID)
```

`Unlink(ctx, headers, identifier, clientID)` succeeds when the pair is already absent. `Delete(ctx, headers, identifier)` removes the resource and its client links. Policy and grant changes are visible to other processes using the same database. Token issuance and enforcement of these policies have their own progress entries. [OAuth provider checklist](parity/plugins/oauth-provider.md) · [Database lifecycle tests](../adapters/sqlstore/oauth_resources_test.go) · [Cross-runtime registry tests](../conformance/resource-registry.mjs)
