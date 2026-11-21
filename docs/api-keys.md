# API keys

A signed-in user can issue a personal or organization-owned application credential, see its name and starting characters, disable it or revoke it. Creation returns the full secret once. The database keeps its SHA-256 digest in unpadded base64url form. The management endpoints derive ownership from the current direct session and check it again inside the database transaction. User deletion removes that user's keys. A banned user’s keys fail verification.

## Set up the service

Apply the schema profile to your database.

```sh
AUTH_DSN=auth.db go run ./cmd/authctl migrate --dialect sqlite --plugins api-key
```

Import `github.com/Stonewrit/stonewrit-auth` and `github.com/Stonewrit/stonewrit-auth/plugins/apikey`. Pass the same SQL store to the host and key service.

```go
keys, err := apikey.New(apikey.Options{
    Store: store,
    DefaultPrefix: "app_",
    EnableMetadata: true,
    DefaultPermissions: apikey.Permissions{"reports": {"read"}},
})
if err != nil {
    return err
}
auth, err := stonewrit.New(stonewrit.Options{
    Store: store, BaseURL: baseURL, Secret: secret,
    EmailAndPassword: true, Plugins: []stonewrit.Plugin{keys.Plugin()},
})
if err != nil {
    return err
}
mux.Handle("/api/auth/", auth)
mux.Handle("/reports", keys.Middleware(apikey.Permissions{"reports": {"read"}}, reportHandler))
```

The application handler can call `apikey.FromContext(r.Context())` for the verified key ID, owner ID and permissions. Middleware reads `X-API-Key` by default. Set `Options.Headers` to accept other header names. Requests carrying more than one configured credential are rejected. Rate-limited requests receive HTTP 429 and a `Retry-After` header.

## Apply an application validation policy

Set `apikey.Options.ValidateKey` on the configuration whose credentials you want to check. For example, a worker service can consult an application-owned revocation store before it accepts a request.

```go
keys, err := apikey.New(apikey.Options{
    Store: store,
    ValidateKey: func(ctx context.Context, key string) (bool, error) {
        revoked, err := revocations.Contains(ctx, apikey.Digest(key))
        return !revoked, err
    },
})
if err != nil {
    return err
}
```

The callback receives the request context and the presented credential. Keep the credential out of logs. Returning `false, nil` denies the request. Returning an error lets a trusted caller distinguish a policy outage through `Service.Verify`. HTTP routes return a generic server error. Accepted credentials still have to satisfy ownership, expiry, scope and usage checks. Callback rejection and errors consume no uses. When session authentication is enabled and multiple configurations share a header, only the matching configuration’s validator runs. [Validation tests](../adapters/sqlstore/apikey_validator_test.go)

## Manage keys

| Method and path under the auth mount | Use |
| --- | --- |
| `POST /api-key/create` | Accepts `name`, `prefix`, optional `expiresIn` in seconds and opted-in `metadata`. Returns the secret in `key`. |
| `GET /api-key/get?id=…` | Returns one owned key’s metadata and policy. |
| `GET /api-key/list` | Returns `apiKeys` and `total`. Accepts `offset`, `limit`, `sortBy` and `sortDirection`. |
| `POST /api-key/update` | Accepts `keyId`, `name`, `enabled`, `expiresIn` and `metadata`. Send `expiresIn: null` to remove the expiry when custom expiration is enabled. |
| `POST /api-key/delete` | Accepts `keyId` and revokes the credential. |

The Go client exposes `CreateAPIKey`, `GetAPIKey`, `ListAPIKeys`, `UpdateAPIKey` and `DeleteAPIKey`. Retrieval and listing omit the secret and digest. Store the creation response in the destination application's secret store.

## Verify and set policies

A trusted server can call `keys.Verify(ctx, secret, required)`. Check the returned error for storage failures, then check `result.Valid`. A successful result includes the key metadata. A credential must grant every requested resource and action.

`Service.Create` and `Service.Update` take an owner ID selected by trusted server code. Use their `Policy` argument for permissions, remaining uses, refill interval and amount, or per-key rate limits. Browser requests cannot assign these fields. Without overrides, keys have 64 random ASCII letters, show their first six characters, have unlimited lifetime uses and allow ten requests per 24-hour inactivity window. A successful request moves the window’s start to the time of that request. An expiring key can use a configured default, or an explicit lifetime between one and 365 days by default.

Verification locks the owner and key in one transaction. Permission, expiry, budget and rate checks complete before usage counters commit. Separate application instances share the same budget. `keys.DeleteExpired(ctx)` purges expired keys in the service’s configured namespace. `Options.ConfigID` selects that namespace, with `default` used when omitted.


## Organization-owned keys

Apply the `api-key,organization` schema profiles. Register the organization plugin and give the personal and organization key services separate configuration IDs. Pass the same store instance to the host and both services.

```go
personal, err := apikey.New(apikey.Options{Store: store, EnableSession: true})
if err != nil {
    return err
}
teams, err := apikey.New(apikey.Options{
    Store: store, ConfigID: "teams", DefaultPrefix: "team_",
    Organization: &apikey.OrganizationOptions{
        Roles: map[string][]string{
            "admin": {"create", "read", "update", "delete"},
            "member": {"read"},
        },
    },
})
if err != nil {
    return err
}
keyPlugin, err := apikey.NewPlugin(personal, teams)
if err != nil {
    return err
}
orgPlugin, err := organization.New(organization.Options{Store: store})
if err != nil {
    return err
}
opts.Plugins = append(opts.Plugins, orgPlugin, keyPlugin)
```

Create an organization key with `{"configId":"teams","organizationId":"…","name":"Build worker"}`. Its `referenceId` identifies the organization. To list organization keys, supply `organizationId` and optionally `configId`. Omit `organizationId` for personal keys. Retrieval, update and deletion accept `configId` and the key ID.

The database checks current membership and the requested action for every management operation. The creator role (`owner` by default) can manage all organization keys. Other roles receive only actions explicitly granted in `Roles`. Multiple roles on a member combine their grants. Existing custom role names can be used in this map. Using the organization HTTP API to assign custom role names and loading dynamic role definitions remain open.

Each configuration ID retains its ownership type across restarts. Use a fresh configuration ID when switching between personal and organization ownership. A deleted user’s personal keys stop working. An organization’s keys continue to belong to the organization when the issuing user leaves.

## Authenticate an auth request with a key

Session authentication is opt-in per key service. Enable `Options.EnableSession` on a personal configuration. Present the secret in its key header to `GET /get-session`, or pass those headers to `Auth.GetSession`. Use a single credential source per request. A request containing both a key and a browser session receives `AMBIGUOUS_CREDENTIALS`. If multiple configurations share a header, exactly one matching stored credential may use that header. Ambiguous imported keys are rejected.

The result identifies the owner and sets `session.id` to the key ID, `session.token` to the presented secret, and `session.credentialType` to `application`. Treat the response as a secret. The reported expiry is the key expiry or, for a nonexpiring key, the configured session lifetime from the request time. Each request revalidates the key and consumes its budget once. The server keeps these sessions out of browser-session storage and issues no login cookie.

| Operation | Authorization |
| --- | --- |
| Read the current session | An enabled, valid personal key whose owner can sign in. |
| Update a name or image | `user:update`. The SQL write rechecks the credential and its current scope. |
| List or read organizations | `organization:read` and the owner’s current membership. Supply an explicit organization ID or slug to read a specific organization. |
| Invite an organization member | `invitation:create` and the owner’s current authority to invite the requested role. |
| Enroll an authenticator | `twoFactor:enable`, the owner’s current password and confirmation with the same key and a valid authenticator code. Apply the `two-factor` profile and enable the plugin. Enrollment keeps the credential scoped. |

When permissions are omitted entirely, a key may use each supported operation. An explicit permissions map restricts it to the listed grants. Personal logins continue to authorize key management, identity changes, factor recovery and browser-session management. Organization keys identify a group and can authorize application middleware. Supplying one to an enabled session resolver returns `INVALID_REFERENCE_ID_FROM_API_KEY`.

Secondary or custom storage, pluggable key generators and custom credential-extraction callbacks remain open. Phone number replacement with an application key also remains open. [Feature checklist](parity/plugins/api-key.md) · [Key policy tests](../adapters/sqlstore/apikey_test.go) · [Ownership and session tests](../adapters/sqlstore/apikey_session_test.go) · [Client conformance](../conformance/core.test.mjs)
