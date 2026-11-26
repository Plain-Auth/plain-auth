# API keys

A signed-in user can issue a personal or organization-owned application credential, see its name and starting characters, disable it or revoke it. Creation returns the full secret once. The database keeps its SHA-256 digest in unpadded base64url form. The management endpoints derive ownership from the current direct session and check it again inside the database transaction. User deletion removes that user's keys. A banned user’s keys fail verification.

## Set up the service

Install the API-key tables and prepare the permanent digest ledger before starting the application.

```sh
AUTH_DSN=auth.db go run ./cmd/authctl migrate --dialect sqlite --api-key-ledger
```

Import `github.com/Plain-Org/plain-auth` and `github.com/Plain-Org/plain-auth/plugins/apikey`. Pass the same SQL store to the host and key service.

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
auth, err := plainauth.New(plainauth.Options{
    Store: store, BaseURL: baseURL, Secret: secret,
    EmailAndPassword: true, Plugins: []plainauth.Plugin{keys.Plugin()},
})
if err != nil {
    return err
}
mux.Handle("/api/auth/", auth)
mux.Handle("/reports", keys.Middleware(apikey.Permissions{"reports": {"read"}}, reportHandler))
```

The application handler can call `apikey.FromContext(r.Context())` for the verified key ID, owner ID and permissions. Middleware reads `X-API-Key` by default. Set `Options.Headers` to accept other header names. Requests carrying more than one configured credential are rejected. Rate-limited requests receive HTTP 429 and a `Retry-After` header.

## Custom key generation and credential extraction

Set `Options.GenerateKey` to a function with signature `func(context.Context, apikey.Generation) (string, error)`. Its input carries the acting user ID, optional organization ID, configuration ID, effective prefix and configured key length. A nonempty request prefix takes priority over the default. Return the entire secret, including any desired prefix. The service records the requested prefix as metadata and preserves the returned bytes. Use cryptographically random secret material. Generated credentials must contain between `KeyLength` and 4,096 printable ASCII bytes, with no spaces. The usual digest, starting-character display, expiration and policy settings apply.

The SQL store checks issuance authority before invoking the generator, then rechecks the account, session and organization role when writing the key. The hook runs outside database locks. A generator failure or canceled request leaves no key. Repeated output yields HTTP 409 with `API_KEY_ALREADY_ISSUED`: someone holding a revoked secret must never acquire another owner’s privileges if the generator repeats that value.

### Upgrade existing SQL key stores

The adapter keeps an additional table, `plainauth_api_key_digest`, with a binary primary key and no owner, timestamps or expiry. Each credential contributes a 32-byte SHA-256 fingerprint of its stored digest. A separate one-byte completion marker allows subsequent service starts to skip the historical scan. New issuance reserves the digest and inserts the live key in the same transaction. Deleting a key or its owner retains that reservation. Verification cleanup cannot remove it. Back up and restore the ledger with the canonical `apikey` table.

For a coordinated upgrade, pause every process that creates, rotates or deletes API keys, including jobs and older applications that share the database. Run `authctl migrate --dialect postgres --api-key-ledger` with your migration credentials and target dialect, or call `store.PrepareAPIKeyLedger(ctx)` from Go. The first key service on a store also initializes it automatically. Replace all key writers with ledger-aware adapters before resuming writes and enabling custom generators. Applications using restricted database roles can provision the table first and grant the adapter access for backfill and reservation.

Backfill is repeatable. It reserves every distinct digest still present, preserving exact bytes across database collations. It leaves duplicate historical key records intact. Ambiguous records remain unusable under the existing lookup rules. A repeat backfill captures live keys added during a transition. Older writers and raw SQL clients can bypass the ledger, and a historical secret deleted before capture cannot be reconstructed. Imports using plaintext or another hashing format require a separate credential rotation before switching to this service. Existing read operations against the canonical table continue using their prior ownership and ambiguity checks. [Three-engine migration tests](../adapters/sqlstore/apikey_ledger_test.go)

### Extract credentials from requests

Set `Options.ExtractKey` to a function with signature `func(*http.Request) (key string, present bool, err error)`. It replaces header lookup for its configuration and receives a read-only request. Inspect its headers, cookies, method or URL, and use `r.Context()` for cancellation. Leave the body available to the handler. Native `GetSession(ctx, headers)` supplies those headers, the caller’s context, and an empty method and URL.

| Extractor return | Result |
| --- | --- |
| `"", false, nil` | No credential was presented through this configuration. Other configured sources or a browser session can proceed. |
| `key, true, nil` | Verify the supplied printable credential. An empty or malformed value rejects the request. |
| A non-nil error | Stop authentication. HTTP responses hide the callback’s error detail. Native callers can use `errors.Is` to identify their own error. |

`VerifyRequest`, application middleware and enabled API-key session routes use the extractor. `Verify(ctx, key, permissions)` checks its explicit key directly. Presenting a recognized application key alongside a browser credential is ambiguous. Different key sources are also ambiguous. Configurations that share a header, or custom extractors returning the same key, resolve it only when the digest identifies exactly one candidate. Detection runs before usage counters change. [Hook and concurrency tests](../adapters/sqlstore/apikey_hooks_test.go)

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

## Errors

Each error carries its status, code and message from the API key error table.

| Code | Status | When |
| --- | ---: | --- |
| `KEY_NOT_FOUND` | 404, or a verification result | No key has this ID or secret, or the key lacks a required permission |
| `UNAUTHORIZED_SESSION` | 401 | Create or update without a session |
| `USER_BANNED` | 401, or a verification result | The key's owner is banned |
| `INVALID_PREFIX_LENGTH` | 400 | The prefix is shorter or longer than the configured bounds |
| `VALIDATION_ERROR` | 400 | The prefix has characters other than letters, digits, `_` and `-`, or another field has the wrong type |
| `INVALID_NAME_LENGTH` | 400 | The name is outside the configured bounds, including an empty name on update |
| `NAME_REQUIRED` | 400 | `RequireName` is set and the key has no name |
| `EXPIRES_IN_IS_TOO_SMALL`, `EXPIRES_IN_IS_TOO_LARGE` | 400 | `expiresIn` is outside the configured bounds |
| `KEY_DISABLED_EXPIRATION` | 400 | `DisableCustomExpiration` is set and the request names an expiry |
| `INVALID_METADATA_TYPE` | 400 | `metadata` is not an object |
| `METADATA_DISABLED` | 400 | `EnableMetadata` is off and the request sends metadata |
| `SERVER_ONLY_PROPERTY` | 400 | A browser request sets a server-only field such as `remaining` |
| `REFILL_AMOUNT_AND_INTERVAL_REQUIRED`, `REFILL_INTERVAL_AND_AMOUNT_REQUIRED` | 400 | A refill interval without an amount, or an amount without an interval |
| `INVALID_REMAINING` | 400 | A trusted `Policy.Remaining` is out of range; a Go policy has no body validator, so the declared code is the typed answer, where another runtime's validator answers `VALIDATION_ERROR` |
| `NO_VALUES_TO_UPDATE` | 400 | An update changes nothing |
| `INVALID_API_KEY` | 403 for a session key shorter than `KeyLength` or refused by `ValidateKey`, 401 otherwise, or a verification result | The secret is not a key |
| `KEY_DISABLED`, `KEY_EXPIRED`, `USAGE_EXCEEDED` | Verification results; 401 or 429 on a session read | The key is disabled, expired or used up |
| `RATE_LIMITED` | A verification result with `tryAgainIn` in milliseconds; 429 on a session read | The key's rate budget for the window is spent; the message is `Rate limit exceeded.` |
| `INVALID_REFERENCE_ID_FROM_API_KEY` | 401 | An organization key is sent as a session credential |
| `ORGANIZATION_ID_REQUIRED`, `USER_NOT_MEMBER_OF_ORGANIZATION`, `INSUFFICIENT_API_KEY_PERMISSIONS`, `ORGANIZATION_PLUGIN_REQUIRED` | 400, 403, 403, 500 | See [Organization-owned keys](#organization-owned-keys) |

`API_KEY_ALREADY_ISSUED` (409) is this library's own. When a request has several faults, the first one reported may differ from another runtime's; each fault alone gets the code listed here. [Error code tests](../adapters/sqlstore/apikey_errors_test.go)

## Verify and set policies

A trusted server can call `keys.Verify(ctx, secret, required)`. Check the returned error for storage failures, then check `result.Valid`. A successful result includes the key metadata. A credential must grant every requested resource and action.

`Service.Create` and `Service.Update` take an owner ID selected by trusted server code. Use their `Policy` argument for permissions, remaining uses, refill interval and amount, or per-key rate limits. Browser requests cannot assign these fields. Without overrides, keys have 64 random ASCII letters, show their first six characters, have unlimited lifetime uses and allow ten requests per 24-hour inactivity window. A successful request moves the window’s start to the time of that request. An expiring key can use a configured default, or an explicit lifetime between one and 365 days by default.

A key whose stored rate maximum or window is empty has no rate limit and keeps its last request time. A remaining count drops by one per use; at zero the next use answers `USAGE_EXCEEDED` and deletes a key without a refill, while a refillable key is kept and resets its count to the refill amount once the interval has passed since creation or the last refill. A key with a refill policy but no remaining count stays uncapped. [Usage budget tests](../adapters/sqlstore/apikey_budget_test.go)

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

API keys live in the `Store` passed to `apikey.Options`. `Options.SecondaryStorage` does not hold or cache them, because every verification locks the key and its owner's account in one database transaction, and an expired or used-up key is deleted in the transaction that refuses it. Keeping keys in secondary storage, on its own or in front of the database, remains open, as does custom key-value storage. Phone number replacement with an application key also remains open. [Feature checklist](parity/plugins/api-key.md) · [Key policy tests](../adapters/sqlstore/apikey_test.go) · [Ownership and session tests](../adapters/sqlstore/apikey_session_test.go) · [Client conformance](../conformance/core.test.mjs)
