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

host, err := plainauth.New(plainauth.Options{
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

Import the root `github.com/Plain-Org/plain-auth` package and its `schema`, `adapters/sqlstore` and `plugins/scim` packages. Configure the identity provider's directory URL as `https://accounts.example.org/identity/scim/v2` for this example. Return links use the configured public URL. Supply the directory credential through your application's secret configuration.

A credential can have an absolute `ExpiresAt`. An omitted scope list permits reads and writes for this directory. Configure both old and new credentials during rotation, then remove the old entry from each serving process. Tokens must be unique across connections. The first authenticated lookup fixes the connection's provisioning domain in the shared database. Reassigning an existing connection ID to a different domain returns HTTP 409.

## Verify application-issued bearer tokens

Set `Options.VerifyBearerToken` to a trusted callback when your application owns directory credential issuance and revocation. The callback receives the request context, bearer value, a copy of the headers, HTTP method and SCIM route template such as `/scim/v2/Users/:userId`. Your callback can use its normal credential store or token verifier. A matching active static credential takes priority.

Return a `BearerVerification` with the verified credential ID, explicit operation scopes and its expiry when available. Set `ConnectionID` to use a declared connection. Alternatively, set `Connection` to the verified directory ID and provisioning domain. This form supports a deployment without any static connections. The server rejects empty or duplicate scopes, expired tokens, mixed connection forms, reserved IDs and resolved identities that collide with a declared connection. A connection's first authenticated request binds it to its provisioning domain. Each later request checks that binding, as another runtime's authentication middleware does: a read or deletion before its query is read, and a write once its body is valid, so a malformed body still answers 400 or 415. A connection bound to another domain answers 409 and a retired one 401. The bearer token and its scopes are checked before anything else, where another runtime reads and validates the body first: an unauthenticated caller learns nothing about how the body would be read.

Returning `nil, nil` rejects the credential. An error produces a generic server error so an issuer outage can be distinguished from a rejected credential. Issue application tokens with a prefix distinct from `ba_scim_credential_`, which is reserved for managed credentials. After checking static credentials, the server calls your verifier on each request that uses an application token. Revoking an application token takes effect on its next request. Your store can read the verified credential ID, directory, scope and expiry using `scim.PrincipalFromContext(ctx)`. The signed-in application session plays no part in this exchange. [Dynamic verification and SQL tests](../adapters/sqlstore/scim_dynamic_test.go) · [Cross-runtime callback tests](../conformance/scim-contract.mjs)

## Issue and rotate directory credentials

Use the `scim-managed` schema profile to add a credential catalog to the directory tables. Configure the same high-entropy `CredentialHashSecret` on each serving instance. Use a separate secret of at least 32 characters for this purpose, counted in UTF-16 code units as another runtime counts them. [Secret length test](../plugins/scim/managed_test.go)

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

A creation request ID must be unique and contain 16 to 255 characters. The catalog methods trim the provisioning domain, actor and creation request ID as JavaScript trims and count code points, as another runtime's request schemas do. They take managed connection and credential IDs as given, so an ID without its prefix, or with a leading space, answers 400 `invalidValue` and one with a trailing space is not found. The retirement method trims its connection and domain IDs, and a blank domain answers 400 `invalidValue`, while code-defined and verified connection, provisioning domain and credential IDs must already be trimmed and fit 255 UTF-16 code units, as another runtime checks them. Reusing it returns `scim.ErrCreationRequestConflict`. Only the successful creating or rotating call receives the bearer secret. The database stores a keyed digest. Every credential needs distinct recognized scopes and a future expiry.

The catalog methods run inside your trusted Go application. Authorize the caller for the provisioning domain before using them. `List` takes a domain. `Get`, `Rotate`, `Revoke` and `Events` take a `scim.Directory` with both the connection and domain IDs. During rotation, the old and new credentials can overlap while you update the identity provider. Revoke the previous credential by its ID after the provider switches. Repeating a successful revocation preserves the original actor and audit event. SQL resource operations recheck the managed credential inside the directory transaction.

The default limit is five active credentials per connection. Set `MaxActiveCredentials` to a value from 1 to 100 to change it. Expired credentials free a slot on the next issuance. Successful verification updates the last-use timestamp at most once every five minutes by default. A non-nil `LastUsedWriteInterval` overrides that interval: zero records every use, and a negative one is refused. Audit events include the actor and sequence number. `EventQuery` supports a page limit of 1 to 100, an offset, and ascending or descending sequence order. The default returns the latest page in chronological order. [Three-database credential tests](../adapters/sqlstore/scim_managed_test.go) · [Cross-runtime credential tests](../conformance/scim-managed.mjs)

## Permanently retire a directory

For a static or application-verified directory, call `directory.Decommission(ctx, scope)`. For a managed directory, call `directory.Catalog().Decommission(ctx, scope, administratorID)`; `directory.Decommission` answers 400 `invalidValue` for a `ba_scim_connection_` ID, where another runtime retires its binding and leaves the catalog row active, so a managed connection's credentials always end with it. Both are trusted server methods. Supply the connection ID and provisioning domain in `scope` after checking the administrator's access to that directory. The domain may be left empty to retire the domain the connection is bound to; a connection never bound, configured or not, then answers `scim.ErrNoBinding`, as in another runtime. A configured connection given a domain other than its configured one answers `scim.ErrDomain`, so a mistyped domain cannot bind it to another domain for good, where another runtime retires it in the domain supplied. [Retirement tests](../adapters/sqlstore/scim_decommission_test.go) You can retire a connection before its first provisioning request. Its terminal binding prevents later use of the same ID.

Managed retirement first disables the connection and its active credentials together and records the initiating administrator. Other instances immediately reject subsequent directory requests and rotations. The SQL adapter reconciles subjects in batches of 50 using a persisted lease and cursor. A second worker observing an active lease returns `reconciling` with `RetryAfter`. Retry the same operation at or after that time. A worker can resume from the committed cursor after a process failure. Completion records the finishing administrator and an audit event. A later call returns the recorded state.

Retirement preserves directory and application records, releases profile ownership for retired sources, and revokes SQL sessions when an account loses its last active directory source. Accounts with another participating source keep their sessions. An existing externally managed role grant that requires an application role reconciler returns a conflict. The connection stays disabled, and retirement can resume after the grant has been reconciled. [Database retirement and recovery tests](../adapters/sqlstore/scim_decommission_test.go) · [Cross-runtime retirement tests](../conformance/scim-managed.mjs)

## Provision and synchronize

| Route relative to the directory URL | Behavior |
| --- | --- |
| `GET /ServiceProviderConfig` | Publishes bearer authentication, PATCH and filter capabilities |
| `GET /Schemas` and `GET /Schemas/{id}` | Describe the core User, Enterprise User and Group schemas, in that order |
| `GET /ResourceTypes` and `GET /ResourceTypes/{id}` | Discover the Users and Groups resources; the User resource type declares the optional Enterprise extension |
| `POST /Users` | Create a directory User and an unverified application user, reprovision by a retained external ID, or with `Identity.ResolveUser` link an existing account |
| `GET /Users/{id}` and `GET /Users` | Read a User or page through resources owned by this connection |
| `PUT /Users/{id}` | Replace the mutable core profile |
| `PATCH /Users/{id}` | Apply a set of attribute changes in a single transaction |
| `DELETE /Users/{id}` | Remove the directory resource and retain its scoped external identity for future provisioning |

`ServiceProviderConfig` publishes bearer authentication only and reports bulk, sorting, ETags and password changes as unsupported. Bulk, `/Me`, POST search, sorting, ETags and cursors are not supported: unknown routes, schema IDs and resource types return a SCIM 404, and `POST /Users/.search` returns 405 with an `Allow` header, where another runtime answers it with 404. Only Bearer credentials are accepted; Basic credentials answer 401 with a `Bearer` challenge, and mutual TLS and a built-in token endpoint are not supported. [Discovery and refused-route tests](../plugins/scim/http_test.go) Send `Authorization: Bearer <directory credential>` with resource requests. The read and write scopes are independent. Browser session cookies confer no directory privileges. POST, PUT and PATCH accept `application/scim+json` and `application/json`. The handler returns SCIM JSON and the protocol's string-valued `status` in error responses.

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "externalId": "employee-2049",
  "userName": "employee-2049",
  "name": {"givenName": "Rae", "familyName": "Doe"},
  "emails": [{"value": "rae@example.org", "type": "work", "primary": true}]
}
```

A null attribute or subattribute in a User or Group POST or PUT body counts as omitted, and so does an object that only holds nulls; a PATCH value that only holds nulls is checked like any other value, except a null subattribute of a Group member entry, which is omitted, while a null `userName`, `active`, Group `displayName` or email entry answers 400. Custom schema extensions return 400 `invalidValue`. Attribute names are case-insensitive, so two spellings of one declared attribute, even when one is null, return 400 `invalidSyntax`, also in any User PATCH value, checked before the User is looked up and before its null keys become removals, and in a Group PATCH value, checked before the Group is looked up. Two spellings of an undeclared key are not compared, and a value whose path cannot be resolved answers the path error instead. `id` and `meta` are never stored, but two spellings of either are refused too. A User has no `groups` attribute; read memberships from the Group resources. `password`, `ims`, `photos` and `x509Certificates` are ignored on input and never stored or returned. [Attribute tests](../adapters/sqlstore/scim_attributes_test.go) Creation returns 201 with `Location` and `Content-Location`. Reads and updates return 200. Deletion returns 204. The server normalizes email addresses to lowercase and uses the explicit primary email, the work email or the first email, in that order. When emails are omitted, the username must be an email address. A new directory identity cannot take ownership of an existing application's account by providing its email. Conflicts with existing usernames, external IDs and managed emails return 409. A connection requesting another connection's User ID receives 404.

The directory User that supplies an account’s profile can update its name and primary email. Changing that email clears its verified flag. With either the `scim` or `scim-managed` schema, deactivating or deleting a directory User revokes the account’s SQL sessions when it loses its last active, participating directory source. An account with another active source keeps its sessions. Other configured sign-in methods retain their own policies. A `scimUser` row written before `serializedAttributes` existed is read from its name and email mirror columns, and its next change writes the canonical attributes. Reprovisioning an inactive User with the same scoped external ID reuses its resource ID. Reprovisioning after deletion allocates a new resource ID and restores the binding to the same application user. Deleting the application account removes the associated directory records.

### Link an existing account

By default a POST creates an account owned by the directory, and an email another account already uses answers 409. Set `scim.Options.Identity` with `ResolveUser` to link an incoming User to an existing account instead:

```go
scim.Options{Identity: &scim.Identity{ResolveUser: func(ctx context.Context, in scim.IdentityResolutionInput) (scim.IdentityResolution, error) {
	userID, found, err := app.DirectoryAccount(ctx, in.ConnectionID, in.Resource.ExternalID)
	if err != nil || !found {
		return scim.IdentityResolution{}, err
	}
	return scim.IdentityResolution{Action: "link", UserID: userID, Profile: "preserve"}, nil
}}}
```

| Decision | Effect |
| --- | --- |
| zero value or `Action: "create"` | Creates an account managed by this source. |
| `link` with `Profile: "manage"` | Links the existing account and lets this source manage its email and name; a changed email becomes unverified. Only one source manages an account, so a second managing link answers 409 `uniqueness`. |
| `link` with `Profile: "preserve"` | Links the existing account without changing its email or name, also on later PATCH and PUT. Separate connections may link preserved sources to one account; one connection cannot link two. |

The input carries the `ConnectionID`, the `ProvisioningDomainID` and a copy of the normalized User in `Resource`: userName, displayName, externalId, primary email, active and the canonical attributes. Never link by an unverified email match. `ResolveUser` runs before the directory transaction, so read through the store or your own database. It does not run for a POST whose externalId reclaims an inactive SCIM User or a deleted User's account, and `ValidateUserInfo` still checks every POST, linked or not. A link to an account that does not exist answers 409 `The resolved user does not exist`. An error, a panic or an invalid decision answers 500 `SCIM identity resolution failed`, and a `*scim.Error` is answered as is; another runtime reads an invalid decision as a preserved link. A link the data no longer allows when the transaction runs, such as an externalId reclaimed meanwhile, answers 409. A reclaim whose inactive User or deleted account vanished before the write is retried from the start, resolver included, up to three times, and then answers 409 `The SCIM identity changed concurrently; retry the request`. It needs a store implementing `scim.IdentityStore`, as the SQL store does. A lifecycle reconciler for linked accounts is not available yet. [Identity tests](../adapters/sqlstore/scim_identity_test.go)

## Sign in provisioned users with SSO

To let only provisioned, active directory Users sign in through an enterprise provider, pair the SCIM connection with the provider's [user resolver](sso.md#resolve-enterprise-users). Configure the directory to send the provider's immutable, case-exact subject as `externalId`. The resolver looks the User up with the SQL store's `SCIMActiveUserLink` and links the sign-in to its account:

```go
sso.Options{ResolveUser: func(ctx context.Context, in sso.UserResolutionInput) (sso.UserResolution, error) {
	ref := scim.UserExternalIDReference{ConnectionID: "workforce", ExternalID: in.AccountKey.AccountID}
	link, err := store.SCIMActiveUserLink(ctx, ref)
	if errors.Is(err, scim.ErrNotFound) {
		return sso.UserResolution{Action: sso.ResolveReject, Code: "SCIM_USER_NOT_ACTIVE"}, nil
	}
	if err != nil {
		return sso.UserResolution{}, err
	}
	return sso.UserResolution{Action: sso.ResolveLink, UserID: link.UserID, Profile: "preserve", RequireActiveSCIMUser: &ref}, nil
}}
```

`SCIMActiveUserLink` matches the connection ID and externalId exactly and never falls back to the userName, an email, another connection or a deleted User; it answers `scim.ErrNotFound` for a missing, inactive, tombstoned or orphaned User or a retired connection. The lookup runs outside the sign-in transaction; with `RequireActiveSCIMUser`, the store checks the SCIM User again under the account's lock in the transaction that links the identity and creates the session, where another runtime fences it inside one transaction. A User deactivated in between fails the sign-in with `error=SSO_USER_RESOLUTION_FAILED`; such a sign-in creates no account or session, and the user starts a fresh sign-in. [Gated sign-in tests](../adapters/sqlstore/sso_scim_link_test.go)

## User queries and updates

Collections accept one-based `startIndex` and `count` up to 100. Use equality filters on `id`, `userName`, `externalId`, `emails.value` and `emails[type eq "work"].value`. Combine up to ten conditions with `and`. `attributes` and `excludedAttributes` take comma-separated, case-insensitive paths such as `name.givenName`, `emails.value`, `roles.type` or `members.value`, optionally core-schema qualified; an unknown path selects nothing, and an empty part or a path with inner whitespace, as JavaScript defines it, answers 400 `invalidValue`. The two parameters cannot be combined, an empty value counts as absent, a repeated key merges its lists, and POST, PUT and PATCH apply the selection to their response too. A collection read answers 400 `invalidValue` to a repeated `filter`, `startIndex` or `count` before the binding check; other routes ignore those keys. Responses always include `id` and `schemas`. [Selection tests](../adapters/sqlstore/scim_attributes_test.go)

PATCH accepts `add`, `replace` and `remove` for supported top-level attributes and individual name subattributes, plus pathless add and replace maps. Operation names are case-insensitive and an omitted op means replace; a null op or path answers 400 before the binding check, as a non-string does. An empty Operations array or an empty pathless value is a valid no-op, and a PATCH that changes nothing keeps `meta.lastModified`; only the request body size limits the number of operations. A pathless remove returns `noTarget`; `id`, `schemas` and `meta` are read-only. `name` add and replace merge into the stored name, and an unknown name subattribute returns `invalidPath`. A display name equal to the formatted name follows a new formatted name, and removing `name.formatted` derives it from the given and family names, the display name, then the primary email. Removing `displayName` falls back to the formatted name, and removing `name` keeps a formatted name from the display name or the primary email. These fallbacks apply at once, so a later operation in the same request sees them. Single-valued PATCH values may be sent as a one-element array; `active` unwraps only a JSON Boolean, and a string Boolean must be bare. A pathless value applies its keys in sorted key order, where another runtime applies them in request order. [Name PATCH tests](../adapters/sqlstore/scim_attributes_test.go) An `emails` add takes an array and appends the type and value pairs not stored yet; repeated pairs coalesce, and an added primary clears primary on the others. A replace needs at least one email, and `emails` cannot be removed. `emails.value` replaces the value of every email, `emails[type eq "work"].value` selects emails by type and `emails[primary eq true].value` the primary email. A type selector that matches nothing appends a non-primary email of that type, and removing it drops that type; removing the last email or a value path answers 400 `invalidValue`. Other email paths answer `invalidPath`. Each email operation leaves the emails normalized, with a primary chosen, so a later operation in the same request selects from them. [Email PATCH tests](../adapters/sqlstore/scim_attributes_test.go) A null add or replace value removes its target like `remove`; `active`, `userName` and `emails` cannot be removed, so a null on them answers 400. A null key in a pathless value, a `name` value, the Enterprise extension, `manager` or a filtered value removes that attribute after the operation's other keys apply, and a null subattribute inside a whole `emails` or `roles` value is treated as omitted. Null keys inside one value are removed in sorted key order with a formatted name last, so the name it composes sees the other removals; another runtime removes them in request order. An add or replace without a `value` answers 400 `invalidValue`, where another runtime treats some such operations as removals. [Null PATCH tests](../adapters/sqlstore/scim_attributes_test.go) The account name follows a patched display name. [Scalar PATCH tests](../adapters/sqlstore/scim_attributes_test.go) The handler supports the core name, display name, external ID, username, active flag, emails, title, user type, preferred language, locale, timezone, phone numbers, addresses, directory roles and entitlements. String limits count Unicode code points and values are trimmed like JavaScript strings, so a name of emoji another runtime accepts is accepted here. For example, send this body to `PATCH /Users/{id}` to deactivate the User.

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{"op": "replace", "path": "active", "value": false}]
}
```

A malformed filter, invalid attribute, unsupported patch path or invalid JSON body returns 400. Missing, expired or unknown credentials return 401 with a bearer challenge. Valid credentials without the required scope return 403. Unsupported request media returns 415. Internal storage errors return a generic protocol error.

A User imported with existing application role grants returns 409 on a directory mutation so its configured role reconciler can handle the change.

## User profile roles

Send `roles` as an array on a User. Each entry requires `value` and can include `display`, `type` and `primary`. The handler trims role text, lowercases defined types and accepts Boolean flags or the strings `"true"` and `"false"` without regard to case. A User may have up to ten entries, at most one primary and at most one entry per defined type. Multiple entries may omit their type. Values and display names allow 1,024 Unicode code points, and types allow 256. The serialized User attribute limit is 65,535 UTF-16 code units, measured on the parsed attributes, so unknown subattributes, surrounding spaces and the primary flags the server assigns to emails do not count. MySQL's canonical `TEXT` column also limits the stored UTF-8 payload to 65,535 bytes. A User over either limit answers 400 `invalidValue` with the body checks, before the connection binding; another runtime checks the stored payload in its handler and answers 500.

`phoneNumbers`, `addresses` and `entitlements` follow the same rules as roles: up to ten entries each, trimmed text, lowercased and unique defined types and at most one primary. A phone number or entitlement requires `value`; phone numbers and entitlement values allow 1,024 code points. An address needs at least one of `formatted`, `streetAddress`, `locality`, `region`, `postalCode` and `country`; `formatted` and `streetAddress` allow 1,024 code points and the others 256. They are stored in the canonical attributes another runtime reads, returned on reads and replaced by PUT. PATCH supports the same paths as roles for each of them: the whole array, a subattribute such as `addresses.locality`, and exact `type eq` or `primary eq` selectors, as in `phoneNumbers[type eq "work"].value`. [Multi-valued attribute tests](../adapters/sqlstore/scim_attributes_test.go)

The Enterprise User extension, `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`, supports `employeeNumber`, `costCenter`, `organization`, `division`, `department` and `manager`. Declare its URI in `schemas` to send the object under that URI; `schemas` holds the core User schema once and the extension at most once, and is returned core first. The URI may be declared alone and stays in the response, and an object whose fields are all null, directly or in nested values, counts as omitted. Scalars may be one-element arrays, and `employeeNumber` and `costCenter` allow 256 code points and the others 1,024. A `manager` accepts an identifier string, an object with `value` or `$ref`, or a one-element array of that object; its `displayName` is read-only and never stored, and the manager is an external reference that needs no local User. The extension is stored under the canonical `enterprise` key another runtime reads. `attributes=manager` and URN-qualified paths such as `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department` select its fields. [Enterprise User tests](../adapters/sqlstore/scim_attributes_test.go)

PATCH accepts the URN, URN-qualified attributes such as `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department`, the `enterprise` alias, flat URN keys in pathless values and the classic `manager`, `manager.value` and `manager.$ref` aliases; responses keep the manager under the URN. An object value merges into the stored extension and its manager, an unknown Enterprise attribute answers `invalidPath`, and `manager.displayName` answers `mutability`. The `manager` alias and the Enterprise URN forms are not core attributes, so behind the core User schema prefix they answer `invalidPath`, while `enterprise` and `enterprise.<attribute>` still work there, as in another runtime. A write declares the extension in `schemas`, and removing the URN or its last field removes the extension and its declaration. A `manager` replace with an empty string clears it, as Entra sends, and a manager value needs `value` or `$ref`. A null Enterprise or manager key removes that field after the other keys apply, and a null `manager.displayName` is ignored. [Enterprise PATCH tests](../adapters/sqlstore/scim_attributes_test.go)

For example, this PATCH assigns a directory role and marks it primary. The preceding primary entry becomes secondary.

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {"op": "add", "path": "roles", "value": {"value": "finance-reader", "type": "work", "primary": true}}
  ]
}
```

A PATCH can replace or remove the whole array, one selected entry or a subattribute. Use `roles[type eq "work"].display` to select a label or `roles[primary eq true]` to select explicitly primary entries. A matching complex record merges supplied fields. A missing selection can create an entry if the result supplies its required value. Removing a missing selection succeeds. To clear roles, use `remove` on `roles` or replace it with `null`. Assigning `[]` preserves an explicit empty array.

A PUT or a same-external-ID POST that reactivates an inactive User replaces the role profile. Changing only `active` via PATCH preserves the existing roles. Other connections cannot access the directory record. Application account roles, organization memberships and authorization grants keep their existing values when directory profile roles change. [Wire comparison](../conformance/scim-roles.mjs) · [Three-database tests](../adapters/sqlstore/scim_roles_test.go)

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

To accept Microsoft's classic Entra Group schema marker on creation, set `AcceptLegacyEntraGroupSchema: true` in `scim.Options`. The response and discovery documents use the core Group schema. The marker is accepted only by `POST /Groups`; PUT and PATCH bodies that carry it return 400. Group paths may carry the core Group schema prefix; a null value removes `externalId` or `members`, and `displayName` cannot be null. [Group PATCH form tests](../adapters/sqlstore/scim_groups_test.go) [Group lifecycle and concurrency tests](../adapters/sqlstore/scim_groups_test.go) · [Group PATCH and compatibility tests](../plugins/scim/groups_test.go)

The checklist tracks Group-to-application role mapping. [Provisioning checklist](parity/plugins/scim.md) · [SQL ownership and concurrency tests](../adapters/sqlstore/scim_test.go) · [Cross-runtime directory tests](../conformance/scim-contract.mjs)

## Project Group memberships into application roles

Apply the `scim` or `scim-managed` SQL profile. Enable a policy for each provisioning domain that your application owns. Pass the returned store to both the auth host and `scim.New`, including server-side operations that delete accounts or retire directories. A configured store uses the original database pool. Close that pool once.

```go
policy := scim.Projection{
    PolicyID: "workforce-v1",
    Map: func(ctx context.Context, tx scim.ProjectionTx, m scim.RoleMapping) ([]string, error) {
        if m.Directory.ID == workforceDirectoryID && m.Group.ID == engineeringGroupID {
            return []string{"engineering"}, nil
        }
        return nil, nil
    },
    Exists: func(ctx context.Context, tx scim.ProjectionTx, lookup scim.RoleLookup) (bool, error) {
        var exists bool
        err := tx.QueryRowContext(ctx, tx.Bind(
            `SELECT EXISTS(SELECT 1 FROM "applicationRole" WHERE `+tx.Exact(`"tenant"`)+`=? AND `+tx.Exact(`"role"`)+`=?)`,
        ), lookup.ProvisioningDomainID, lookup.Role).Scan(&exists)
        return exists, err
    },
    ReconcileUser: func(ctx context.Context, tx scim.ProjectionTx, u scim.ProjectedUser) error {
        _, err := tx.ExecContext(ctx, tx.Bind(
            `DELETE FROM "directoryAssignment" WHERE `+tx.Exact(`"tenant"`)+`=? AND `+tx.Exact(`"userId"`)+`=?`,
        ), u.ProvisioningDomainID, u.UserID)
        if err != nil { return err }
        for _, g := range u.Grants {
            _, err = tx.ExecContext(ctx, tx.Bind(
                `INSERT INTO "directoryAssignment" ("tenant","userId","grantKey","role") VALUES (?,?,?,?)`,
            ), u.ProvisioningDomainID, u.UserID, g.GrantKey, g.Role)
            if err != nil { return err }
        }
        return nil
    },
}
configured, err := store.EnableSCIMProjection(ctx, workforceDomainID, policy)
```

The example assumes the application owns an `applicationRole` catalog and a separate `directoryAssignment` table with a byte-exact unique `grantKey`. Use case-sensitive identifiers for tenant, user and grant keys on the application tables. Keep manually assigned privileges in their own rows. Role mapping receives the connection and provisioning domain IDs, application and directory User IDs, and the Group's immutable ID, external ID and display name. Use trusted Group IDs for privileged mappings. Display names and external IDs can change through directory requests.

`Map` returns candidate roles. The store trims them, ignores empty values and deduplicates repeated roles from the same source. `Exists` validates each distinct role per connection and subject reconciliation. Two Groups that grant the same role retain distinct provenance. `ReconcileUser` receives the complete source and grant sets for one domain and application user, including inactive participating sources. Treat the slices as sets. Use the supplied transaction for application writes so a failed callback rolls back directory changes, the grant ledger and application state together. A callback that returns a `*scim.Error` has it answered as is, so it can refuse a change with its own status and detail; any other error answers 500 with a generic detail. [Callback error tests](../adapters/sqlstore/scim_projection_test.go) External network calls and writes through another database pool cannot participate in that rollback.

The first activation reconciles existing directory sources and validates imported grants. Unknown provenance returns a conflict and leaves existing grants intact. A lifecycle-only policy can omit both role callbacks when the domain has no existing role grants. An imported grant must identify its actual directory Group, source User, domain and application account. Changes to Group membership or metadata, User deactivation and reprovisioning, deletion and directory retirement recompute affected assignments from active sources. Retirement closes directory access before processing its resumable batches. A failed batch preserves the prior application assignments for that batch. Retry retirement after the host callback recovers. Linked sources share a subject only when they already have the same stored application user ID. Directory emails and `User.roles` do not establish identity or grant application privileges.

After changing a mapping or the application role catalog, call `replay, err := configured.ReconcileSCIMProjection(ctx, domainID)`. The domain is trimmed, and an empty or overlong one answers 400 `invalidValue`. It returns the domain, the number of reconciled users, each account counted once however many sources it has, and the committed batch count; the SQL store replays a domain in one transaction, so it reports one batch, or none for a domain without linked users. [Replay summary tests](../adapters/sqlstore/scim_projection_test.go) Call `configured.DisableSCIMProjection(ctx, domainID)` to submit empty grant sets to the current reconciler and release the domain. User activity and source metadata still describe the current directory facts during withdrawal. Activation, withdrawal and explicit replay each run in a single transaction across the domain. Plan a maintenance window for large domains. Paged replay, an application lifecycle reconciler and a built-in organization-role policy remain open.

The first activation creates the small `plainauthSCIMProjectionPolicy` table. Its keys have no expiry. Transaction-scoped PostgreSQL locks, MySQL connection locks held through commit, and SQLite’s immediate transactions serialize domain writes with policy changes. A MySQL connection with an uncertain transaction or lock-release result is discarded. Expiring verification records has no effect on policy ownership. Updated Go nodes sharing a domain must use the same policy ID and equivalent callbacks. While a policy is active, an unconfigured node can read the directory, and its writes receive a conflict. Older binaries, external SQL writers and other directory implementations cannot enforce this extension. Route writes and account deletion through the configured Go store when those processes share the database. [Three-database projection and failure tests](../adapters/sqlstore/scim_projection_test.go) · [MySQL connection lifecycle tests](../adapters/sqlstore/scim_projection_mysql_test.go) · [Shared SQLite HTTP comparison](../conformance/scim-contract.mjs)
