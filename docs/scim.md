# SCIM directory provisioning

An identity provider can provision Users and Groups under the application's auth mount. Each connection owns its directory resources and authenticates with a bearer credential. Discovery is public. The SQL adapter supports SQLite, PostgreSQL and MySQL.

## Mount a directory

Generate the `scim` profile alongside your existing profiles. Wrap your auth handler and mount the wrapper once. Both directory requests and ordinary authentication requests enter through the same application server.

```go
ddl, err := schema.Generate("postgres", []string{"scim"})
if err != nil {
    return err
}
store, err := sqlstore.OpenWithSchema(ctx, "postgres", databaseDSN, ddl)
if err != nil {
    return err
}
defer store.Close() // Keep this store open while serving requests.

host, err := stonewrit.New(stonewrit.Options{
    BaseURL: "https://accounts.example.org", BasePath: "/identity",
    Secret: authSecret, Store: store,
})
if err != nil {
    return err
}
directory, err := scim.New(host, scim.Options{
    Store: store,
    Connections: []scim.Connection{{
        Directory: scim.Directory{ID: "hr-directory", ProvisioningDomainID: "company"},
        Credentials: []scim.Credential{{
            ID: "directory-sync", Token: directoryToken,
            Scopes: []string{scim.UsersRead, scim.UsersWrite, scim.GroupsRead, scim.GroupsWrite},
        }},
    }},
})
if err != nil {
    return err
}
mux.Handle("/identity/", directory)
```

Import the root `github.com/Stonewrit/stonewrit-auth` package and its `schema`, `adapters/sqlstore` and `plugins/scim` packages. Configure the identity provider's directory URL as `https://accounts.example.org/identity/scim/v2` for this example. Return links use the configured public URL. Supply the directory credential through your application's secret configuration.

A credential can have an absolute `ExpiresAt`. An omitted scope list permits reads and writes for this directory. Configure both old and new credentials during rotation, then remove the old entry from each serving process. Tokens must be unique across connections. The first authenticated lookup fixes the connection's provisioning domain in the shared database. Reassigning an existing connection ID to a different domain returns HTTP 409.

## Verify application-issued bearer tokens

Set `Options.VerifyBearerToken` to a trusted callback when your application owns directory credential issuance and revocation. The callback receives the request context, bearer value, a copy of the headers, HTTP method and SCIM route template such as `/scim/v2/Users/:userId`. Your callback can use its normal credential store or token verifier. A matching active static credential takes priority.

Return a `BearerVerification` with the verified credential ID, explicit operation scopes and its expiry when available. Set `ConnectionID` to use a declared connection. Alternatively, set `Connection` to the verified directory ID and provisioning domain. This form supports a deployment without any static connections. The server rejects empty or duplicate scopes, expired tokens, mixed connection forms, reserved IDs and resolved identities that collide with a declared connection.

Returning `nil, nil` rejects the credential. An error produces a generic server error so an issuer outage can be distinguished from a rejected credential. The callback runs for each application credential request. Revocation in the application's credential store takes effect on the next request. Your store can read the verified credential ID, directory, scope and expiry using `scim.PrincipalFromContext(ctx)`. The signed-in application session plays no part in this exchange. [Dynamic verification and SQL tests](../adapters/sqlstore/scim_dynamic_test.go) · [Cross-runtime callback tests](../conformance/scim-contract.mjs)

## Issue and rotate directory credentials

Use the `scim-managed` schema profile to add a credential catalog to the directory tables. Configure the same high-entropy `CredentialHashSecret` on each serving instance. Use a separate secret of at least 32 characters for this purpose.

```go
directory, err := scim.New(host, scim.Options{
    Store: store,
    Managed: &scim.ManagedOptions{CredentialHashSecret: directoryHashSecret},
})
if err != nil {
    return err
}

// The host has authenticated the administrator and checked access to domainID.
catalog := directory.Catalog()
issued, err := catalog.Create(ctx, domainID, creationRequestID, administratorID,
    scim.CredentialPolicy{
        Scopes: []string{scim.UsersRead, scim.UsersWrite},
        ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
    })
if err != nil {
    return err
}
// Deliver issued.Token to the identity provider through a secure channel.
```

A creation request ID must be unique and contain 16 to 255 characters. Reusing it returns `scim.ErrCreationRequestConflict`. Only the successful creating or rotating call receives the bearer secret. The database stores a keyed digest. Every credential needs distinct recognized scopes and a future expiry.

The catalog methods run inside your trusted Go application. Authorize the caller for the provisioning domain before using them. `List` takes a domain. `Get`, `Rotate`, `Revoke` and `Events` take a `scim.Directory` with both the connection and domain IDs. During rotation, the old and new credentials can overlap while you update the identity provider. Revoke the previous credential by its ID after the provider switches. Repeating a successful revocation preserves the original actor and audit event. SQL resource operations recheck the managed credential inside the directory transaction.

The default limit is five active credentials per connection. Set `MaxActiveCredentials` to a value from 1 to 100 to change it. Expired credentials free a slot on the next issuance. Successful verification updates the last-use timestamp at most once every five minutes by default. A non-nil `LastUsedWriteInterval` overrides that interval. Audit events include the actor and sequence number. `EventQuery` supports a page limit of 1 to 100, an offset, and ascending or descending sequence order. The default returns the latest page in chronological order. [Three-database credential tests](../adapters/sqlstore/scim_managed_test.go) · [Cross-runtime credential tests](../conformance/scim-managed.mjs)

## Permanently retire a directory

For a static or application-verified directory, call `directory.Decommission(ctx, scope)`. For a managed directory, call `directory.Catalog().Decommission(ctx, scope, administratorID)`. Both are trusted server methods. Supply the connection ID and provisioning domain in `scope` after checking the administrator's access to that directory. You can retire a connection before its first provisioning request. Its terminal binding prevents later use of the same ID.

Managed retirement first disables the connection and its active credentials together and records the initiating administrator. Other instances immediately reject subsequent directory requests and rotations. The SQL adapter reconciles subjects in batches of 50 using a persisted lease and cursor. A second worker observing an active lease returns `reconciling` with `RetryAfter`. Retry the same operation at or after that time. A worker can resume from the committed cursor after a process failure. Completion records the finishing administrator and an audit event. A later call returns the recorded state.

Retirement preserves directory and application records, releases profile ownership for retired sources, and revokes SQL sessions when an account loses its last active directory source. Accounts with another participating source keep their sessions. An existing externally managed role grant that requires an application role reconciler returns a conflict. The connection stays disabled, and retirement can resume after the grant has been reconciled. [Database retirement and recovery tests](../adapters/sqlstore/scim_decommission_test.go) · [Cross-runtime retirement tests](../conformance/scim-managed.mjs)

## Provision and synchronize

| Route relative to the directory URL | Behavior |
| --- | --- |
| `GET /ServiceProviderConfig` | Publishes bearer authentication, PATCH and filter capabilities |
| `GET /Schemas` and `GET /Schemas/{id}` | Describe the supported core User and Group attributes |
| `GET /ResourceTypes` and `GET /ResourceTypes/{id}` | Discover the Users and Groups resources |
| `POST /Users` | Create a directory User and an unverified application user, or reprovision by a retained external ID |
| `GET /Users/{id}` and `GET /Users` | Read a User or page through resources owned by this connection |
| `PUT /Users/{id}` | Replace the mutable core profile |
| `PATCH /Users/{id}` | Apply a set of attribute changes in a single transaction |
| `DELETE /Users/{id}` | Remove the directory resource and retain its scoped external identity for future provisioning |

Send `Authorization: Bearer <directory credential>` with resource requests. The read and write scopes are independent. Browser session cookies confer no directory privileges. POST, PUT and PATCH accept `application/scim+json` and `application/json`. The handler returns SCIM JSON and the protocol's string-valued `status` in error responses.

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "externalId": "employee-2049",
  "userName": "employee-2049",
  "name": {"givenName": "Rae", "familyName": "Doe"},
  "emails": [{"value": "rae@example.org", "type": "work", "primary": true}]
}
```

Creation returns 201 with `Location` and `Content-Location`. Reads and updates return 200. Deletion returns 204. The server normalizes email addresses to lowercase and uses the explicit primary email, the work email or the first email, in that order. When emails are omitted, the username must be an email address. A new directory identity cannot take ownership of an existing application's account by providing its email. Conflicts with existing usernames, external IDs and managed emails return 409. A connection requesting another connection's User ID receives 404.

The managed profile updates the owning application's name and primary email. Changing that email clears its verified flag. Setting `active` to false or deleting the last active directory source revokes existing SQL sessions. Other configured sign-in methods retain their own policies. Reprovisioning an inactive User with the same scoped external ID reuses its resource ID. Reprovisioning after deletion allocates a new resource ID and restores the binding to the same application user. Deleting the application account removes the associated directory records.

## User queries and updates

Collections accept one-based `startIndex` and `count` up to 100. Use equality filters on `id`, `userName`, `externalId`, `emails.value` and `emails[type eq "work"].value`. Combine up to ten conditions with `and`. Choose `attributes` or `excludedAttributes` for a comma-separated list of top-level fields. Responses always include `id` and `schemas`.

PATCH accepts `add`, `replace` and `remove` for supported top-level attributes and individual name subattributes, plus pathless add and replace maps. Whole email arrays can be replaced and individual entries appended. The handler supports the core name, display name, external ID, username, active flag, emails, title, user type, preferred language, locale and timezone. For example, send this body to `PATCH /Users/{id}` to deactivate the User.

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{"op": "replace", "path": "active", "value": false}]
}
```

A malformed filter, invalid attribute, unsupported patch path or invalid JSON body returns 400. Missing, expired or unknown credentials return 401 with a bearer challenge. Valid credentials without the required scope return 403. Unsupported request media returns 415. Internal storage errors return a generic protocol error.

A User imported with existing application role grants returns 409 on a directory mutation so its configured role reconciler can handle the change.

## Groups and memberships

The SQL adapter exposes `POST /Groups`, `GET /Groups` and `GET`, `PUT`, `PATCH` and `DELETE` on `/Groups/{id}`. The directory credential needs `scim.groups.read` to retrieve groups and `scim.groups.write` to change them. When using a custom Go store, implement `scim.GroupStore` to enable Group routes and discovery.

Each Group belongs to the issuing connection and its provisioned domain. Display names are unique within a connection, ignoring case. External IDs have a separate, case-sensitive uniqueness constraint within that connection. A different connection can use the same identifiers. Members must be direct directory Users from the same connection, including when two connections share a domain. Each Group may contain up to 1,000 distinct members.

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "externalId": "dept-12",
  "displayName": "Operations",
  "members": [{"value": "directory-user-id", "type": "User"}]
}
```

Listings accept equality filters for `id`, `displayName` and `externalId`, bounded pagination and projections such as `attributes=displayName,members.value`. The server builds member display names and User links from the stored directory identity and its public auth mount.

PUT replaces the Group profile and its direct member set. PATCH supports scalar changes, pathless attribute updates, adding or replacing a list of members, removing listed members, clearing the entire membership and removing one member with `members[value eq "directory-user-id"]`. Changes are atomic. Repeating an existing membership addition leaves the Group's last modification time intact. Deleting the Group removes its edges and preserves the Users. Deleting a directory User removes that User's group memberships. Groups imported with externally managed role grants return 409 on changes that need their role reconciler.

To accept Microsoft's classic Entra Group schema marker on creation, set `AcceptLegacyEntraGroupSchema: true` in `scim.Options`. The response and discovery documents use the core Group schema. [Group lifecycle and concurrency tests](../adapters/sqlstore/scim_groups_test.go) · [Group PATCH and compatibility tests](../plugins/scim/groups_test.go)

Role projection, Enterprise User attributes, nested User response projections, filtered User PATCH paths and SSO identity linking are tracked separately. [Provisioning checklist](parity/plugins/scim.md) · [SQL ownership and concurrency tests](../adapters/sqlstore/scim_test.go) · [Cross-runtime directory tests](../conformance/scim-contract.mjs)
