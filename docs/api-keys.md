# API keys

A signed-in user can issue an application credential, see its name and starting characters, disable it or revoke it. Creation returns the full secret once. The database keeps its SHA-256 digest in unpadded base64url form. The management endpoints derive ownership from the current direct session and check it again inside the database transaction. User deletion removes that user's keys. A banned user’s keys fail verification.

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

The current profile covers user-owned database keys and application-route middleware. Organization ownership, browser-session authentication from a key, secondary storage and custom key generators remain open in the [feature checklist](parity/plugins/api-key.md). [Three-engine tests](../adapters/sqlstore/apikey_test.go) · [Client conformance](../conformance/core.test.mjs)
