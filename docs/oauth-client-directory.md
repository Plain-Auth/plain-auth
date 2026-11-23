# Manage registered OAuth applications

Use the owner endpoints to list, inspect and delete applications from an account dashboard. Use the public endpoint to show the application name, logo and policy links on a consent screen. Each endpoint uses a session from the existing auth handler.

## Enable lookup

Mount the plugin returned by `oauthprovider.New` with the `oauth-provider` database profile. Lookup works with SQLite, PostgreSQL and MySQL even when dynamic registration is disabled. For applications that allow self-registration, the same plugin handles registration and lookup. A custom adapter provides `oauthprovider.ClientDirectoryStore` for these reads. [Server setup and registration](oauth-client-registration.md#enable-registration) · [Router examples](routers.md)

| Request under the default `/api/auth` mount | Caller | Response |
| --- | --- | --- |
| `GET /oauth2/get-client?client_id=…` | Personal owner or a member of the owning tenant | Application configuration, owner, registered scopes, redirect URIs, public signing keys, flags and application-specific metadata |
| `GET /oauth2/get-clients` | Signed-in account owner | The current tenant’s registrations when a tenant is active, or the user's personal registrations otherwise. An empty list is `[]`. |
| `GET /oauth2/public-client?client_id=…` | Any signed-in user | The enabled application's ID and available display fields: name, URI, logo, contacts, terms and privacy policy. The `redirect_uris` array is empty. |
| `POST /oauth2/delete-client` | Personal owner or authorized member of the owning tenant | Deletes the local registration. Returns HTTP 200 with an empty body. |

The owner views omit shared secrets, stored digests and machine-to-machine scope grants. A secret's expiry indicator can appear in the owner view. A disabled registration remains visible to its owner. Looking it up through the public endpoint gives the same 404 as an unknown ID. Credential and impersonation sessions cannot perform account-owner operations.

## Read a registration in Go

Pass a signed-in SDK client. The client takes care of URL-encoding the ID and attaching the session cookie.

```go
package example

import (
    "context"

    "github.com/Plain-Org/plain-auth/client"
    "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

func dashboard(ctx context.Context, signedIn *client.Client) ([]oauthprovider.ClientDetails, error) {
    return signedIn.OAuthClients(ctx)
}

func registration(ctx context.Context, signedIn *client.Client, id string) (oauthprovider.ClientDetails, error) {
    return signedIn.OAuthClient(ctx, id)
}

func consentScreen(ctx context.Context, signedIn *client.Client, id string) (oauthprovider.PublicClient, error) {
    return signedIn.PublicOAuthClient(ctx, id)
}
```

For browser code, call the public endpoint from the application origin. URL-encode the client ID and check the status before rendering any fields.

```js
const url = "/api/auth/oauth2/public-client?" + new URLSearchParams({ client_id: id })
const response = await fetch(url, { credentials: "same-origin" })
if (!response.ok) throw new Error(`Client lookup failed (${response.status})`)
const app = await response.json()
document.querySelector("#application-name").textContent = app.client_name ?? app.client_id
```

## Delete an application

Call `signedIn.DeleteOAuthClient(ctx, clientID)` from Go. From a browser, send the client ID to the auth mount using the owner's session.

```js
async function deleteApplication(clientID) {
    const response = await fetch("/api/auth/oauth2/delete-client", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ client_id: clientID }),
    })
    if (!response.ok) throw new Error(`Deletion failed (${response.status})`)
}
```

SQLite, PostgreSQL and MySQL delete the registration, consents, refresh tokens, stored access tokens, and links to protected resources in one transaction. The user can keep using the same session and other applications. An API that validates a signed token offline may continue to accept it until expiry.

Deleting an unknown or already deleted registration returns 404. An unrelated account or tenant receives 401. Operator-managed IDs in `Options.ImmutableClientIDs` return 400. Deletion works with dynamic registration disabled. A custom storage adapter implements `oauthprovider.ClientDeletionStore` and checks the current owner atomically with the delete. [Database tests](../adapters/sqlstore/oauth_client_deletion_test.go)

## Tenant ownership and access rules

Use `Options.ClientReference` when tenants can own registrations. Resolve the active tenant from the signed-in user's verified membership. Return an empty string for a personal account. The resolver also applies to authenticated registration. If the top-level resolver is unset, `Registration.ClientReference` supplies it.

Use `Options.ClientPrivileges` to restrict authenticated `create`, `read`, `list`, `rotate` and `delete` operations. The callback receives the session, user, request headers and action. Reads, rotations and deletions also supply the client ID. Returning false denies access with HTTP 401. An approved owner operation still requires ownership. The public display endpoint requires a session and bypasses the management privilege check.

A host can supply membership and permission functions from its own application.

```go
type AppPermissions interface {
    ActiveTenant(ctx context.Context, userID, sessionID string) (string, error)
    AllowClients(ctx context.Context, userID, action, clientID string) (bool, error)
}

func directoryOptions(permissions AppPermissions) oauthprovider.Options {
    return oauthprovider.Options{
        ClientReference: func(ctx context.Context, access oauthprovider.RegistrationAccess) (string, error) {
            return permissions.ActiveTenant(ctx, access.User.ID, access.Session.ID)
        },
        ClientPrivileges: func(ctx context.Context, access oauthprovider.ClientAccess) (bool, error) {
            return permissions.AllowClients(ctx, access.User.ID, access.Action, access.ClientID)
        },
    }
}
```

A personal owner takes precedence if a stored record contains both an owner and a tenant reference. Ownership comparisons use exact IDs across all three SQL databases. Owner lookups and public display lookups currently resolve locally registered applications. An individual lookup for a client that requires an external discovery provider returns 404. The owner list can show a saved registration snapshot. Pre-login display and discovery providers have separate checklist entries. [OAuth checklist](parity/plugins/oauth-provider.md) · [HTTP comparison tests](../conformance/oauth-client-directory.mjs) · [SQL and Go SDK tests](../adapters/sqlstore/oauth_client_directory_test.go)
