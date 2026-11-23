# Organizations

Enable the organization schema in the same store used by the auth handler. The plugin creates organizations with the configured creator role (owner by default), lists the organizations a user belongs to, and stores the active organization on each individual session.

```go
ddl, err := schema.Generate("sqlite", []string{"organization"})
if err != nil {
    return err
}
store, err := sqlstore.OpenWithSchema(ctx, "sqlite", "auth.db", ddl)
if err != nil {
    return err
}
defer store.Close()

org, err := organization.New(organization.Options{
    Store: store,
    RequireVerifiedEmail: true,
    SendInvitationEmail: func(ctx context.Context, mail organization.InvitationDelivery) error {
        link := origin + "/join?" + url.Values{"invitationId": {mail.Invitation.ID}}.Encode()
        return sendInvitation(ctx, mail.Email, mail.Inviter.User.Name, mail.Organization.Name, link)
    },
})
if err != nil {
    return err
}
auth, err := plainauth.New(plainauth.Options{
    Store: store, BaseURL: origin, Secret: secret, EmailAndPassword: true,
    Plugins: []plainauth.Plugin{org},
})
```

The application provides `sendInvitation`, its configured public `origin` and its `secret`. The example uses Go’s `net/url` package to build a link to the application’s join page. Invitation IDs are opaque. New invitations and resends use a 48-hour lifetime by default. Set `InvitationExpiresIn` on `organization.Options` to choose another duration, for example `30 * time.Minute`. Resending a live invitation refreshes its deadline and preserves its ID, creation time, role and teams. Once it expires, inviting the recipient again creates a new ID. The signed-in recipient must match the invitation email. Set `RequireVerifiedEmail` to also require a verified account.

| Method | Path under the auth mount | Behavior |
| --- | --- | --- |
| POST | `/organization/create` | Create an organization with `name` and `slug` and select it on the creator's session |
| GET | `/organization/list` | List the current user's organizations |
| GET | `/organization/list-members` | List public member profiles and a filtered total for an organization you belong to. |
| GET | `/organization/get-organization` | Read the organization profile by ID, slug or active selection |
| GET | `/organization/get-full-organization` | Read the profile together with members, visible invitations and configured teams |
| GET | `/organization/get-active-member` | Read your membership, role and public profile in this session's active organization. Requires a signed-in session. |
| POST | `/organization/has-permission` | Check the signed-in member’s permissions in an explicit or active organization. |
| POST | `/organization/create-role` | Create a stored role using the configured resource vocabulary and the caller’s own grants. |
| GET | `/organization/list-roles` | Read up to 100 stored definitions when dynamic access control is enabled. |
| GET | `/organization/get-role` | Read a stored definition by exact name or ID. Requires dynamic access control. |
| POST | `/organization/update-role` | Replace grants or rename a stored role with the organization's `ac.update` permission. |
| POST | `/organization/delete-role` | Retire an unassigned stored role with the organization's `ac.delete` permission. |
| GET | `/organization/get-active-member-role` | Read a user's role in an organization you both belong to. Omit all query parameters for your own role in the active organization. |
| POST | `/organization/set-active` | Select by ID or slug. Send `{"organizationId":null}` to clear the current selection |
| GET | `/organization/get-invitation` | Read one pending, unexpired invitation addressed to the signed-in account |
| GET | `/organization/list-user-invitations` | Read pending invitations for the signed-in account’s verified email across organizations |
| GET | `/organization/list-invitations` | List invitations visible to an owner or admin in the named or active organization |
| POST | `/organization/invite-member` | Invite by email and role, using an explicit organization ID or the active selection |
| POST | `/organization/cancel-invitation` | Withdraw an invitation as an owner or admin of the destination organization. |
| POST | `/organization/reject-invitation` | Decline a pending invitation as its recipient. |
| POST | `/organization/accept-invitation` | Accept by invitation ID, create the membership, and select the organization |
| POST | `/organization/remove-member` | Remove by membership ID or email. Omit `organizationId` to use the active organization. |
| POST | `/organization/check-slug` | Check whether a slug is available to register. Requires a signed-in user. |
| POST | `/organization/update` | Update an organization's name, slug, logo or metadata as an owner or admin. |
| POST | `/organization/update-member-role` | Replace roles by membership ID in the supplied or active organization. |
| POST | `/organization/leave` | End the signed-in user's own membership in the supplied `organizationId`. |

The role names in the workflow descriptions below describe the default policy. Hosts can [configure organization roles](#configure-organization-roles). An owner can invite members, admins or other owners. An admin can invite members or admins. The member role grants no invitation permission. The SQL store commits invitation acceptance and the resulting membership together. The [organization feature checklist](parity/plugins/organization.md) tracks additional role policies and operations.

Browser membership changes check the acting account and session inside the database transaction. Acceptance reads the current account email and verification status. Account deletion removes invitations that user sent, their organization and team memberships, and updates affected team counts. Other members keep their memberships and invitations.

## Switch organizations and teams from any client

Selection belongs to the current authenticated session. A web app, native app, server-rendered form or command-line client can use the same JSON API. Your application decides how to present the choices and what to display after a switch. The organization and team endpoints work independently of the OAuth provider plugin.

To populate a picker, call `GET /organization/list` for the signed-in user's organizations. After selecting one, call `GET /organization/list-user-teams?organizationId=org_a` for that user's teams in the selected organization. All paths below are relative to your auth mount.

To read the caller's role after a switch, send `GET /organization/get-active-member` with the same session cookie and no parameters. The JSON response contains the membership's `id`, `organizationId`, `userId`, `role` and `createdAt`, plus a `user` object with `id`, `name`, `email` and nullable `image`. A team switch preserves the organization membership. When the session has no selected organization the response is HTTP 400 with code `NO_ACTIVE_ORGANIZATION`. A stored selection whose membership has been removed yields HTTP 400 with code `MEMBER_NOT_FOUND`. Go callers can use `client.ActiveOrganizationMember(ctx)`.

For just the role, call `GET /organization/get-active-member-role`. For example, `?organizationSlug=studio&userId=user_123` returns an object such as `{"role":"admin,member"}`. A nonempty slug takes precedence over an organization ID, which takes precedence over the session selection. Omit `userId` to query yourself. Any current member can read a fellow member's role. If either user lacks membership the response is HTTP 403. Looking up another organization preserves the session's active organization and team. In Go, pass these optional selectors to `client.OrganizationMemberRole(ctx, organization.MemberRoleQuery{OrganizationSlug: "studio", UserID: "user_123"})`.

| Request | Successful response and session effect |
| --- | --- |
| `POST /organization/set-active` with `{"organizationId":"org_a"}` | Returns the selected organization. Switching organizations clears the previous team's selection. Selecting the same organization preserves its active team. |
| `POST /organization/set-active` with `{"organizationSlug":"studio"}` | Selects by slug and returns the organization. Use a string for the slug. |
| Either selection endpoint with `{}` | Returns the current organization or team, or JSON `null` when that session has none. An empty-string `teamId` also uses the current team. |
| `POST /organization/set-active-team` with `{"teamId":"team_a"}` | Returns the selected team. The user must belong to the team and the team must belong to the active organization. Enable teams to use this endpoint. |
| `POST /organization/set-active-team` with `{"teamId":null}` | Returns JSON `null` and clears the active team. The current organization stays selected. |
| `POST /organization/set-active` with `{"organizationId":null}` | Returns JSON `null` and clears both selections. |

For example, use a cookie jar from a prior sign-in and the origin configured for your application. Browser clients supply their origin on these writes. Update the jar from the response so the client retains any refreshed session cookie.

```sh
curl --fail-with-body -b cookies.txt -c cookies.txt \
  -H 'Origin: https://app.example.com' -H 'Content-Type: application/json' \
  --data '{"organizationId":"org_a"}' \
  https://app.example.com/api/auth/organization/set-active
```

A nonempty `organizationId` takes precedence over `organizationSlug`. An explicit null ID clears the selection even if you also send a valid slug. An unknown slug returns HTTP 400 with `ORGANIZATION_NOT_FOUND` and preserves the current selection. Selecting an unknown ID or an organization the user does not belong to returns HTTP 403 with `USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION` and clears this login's organization and team. Other logins keep their selections. Invalid field types return HTTP 400 with `VALIDATION_ERROR` and leave the session untouched. [Selection contract tests](../conformance/organization-selection.mjs)

In Go, pass an `organization.OrganizationSelection` to the client. The returned organization is nil when the session has no selection.

```go
selected, err := authClient.SetActiveOrganization(ctx, &organization.OrganizationSelection{
    OrganizationSlug: "studio",
})
```

Use `OrganizationID: id` to select by ID. Pass `&organization.OrganizationSelection{}` to use the current organization or `nil` to clear it. SQL adapters authorize and save the selection in a single transaction. Custom stores can implement `organization.OrganizationSelectionStore` for the same transactional behavior. [Go client and concurrent switch tests](../adapters/sqlstore/organization_selector_test.go)

Read `GET /get-session` under the auth mount for the active organization and team. A second login for the same user has its own selection. Creating an organization selects it by default. Pass `keepCurrentActiveOrganization: true` to retain the current selection when creating another organization. [Plain HTTP session-isolation tests](../adapters/sqlstore/organization_selection_http_test.go) · [Organization and team switching on six routers](../integrations/routers/routers_test.go)

Applications acting as an OAuth issuer can also configure a host-owned page for organization or team selection during authorization. A signed OAuth request can then return a protocol redirect or a JSON destination. [Post-login authorization](oauth-authorization-code.md#select-an-organization-or-team-after-login)

If you generate a client from OpenAPI, the ordinary response is a nullable `Organization` or `Team`. A host that enables signed post-login selection also exposes the optional `oauth_query` input, a JSON result with `redirect` and `url`, and an HTTP 302 response for navigation. [OpenAPI reference](openapi.md) · [Configured schema tests](../plugins/openapi/organization_selection_test.go)

## Check organization permissions

Send `POST /organization/has-permission` with the session cookie and a JSON object such as `{"permissions":{"invitation":["create"],"member":["update"]},"organizationId":"org_a"}`. Omit `organizationId` to use the current session’s active organization. The response is `{"success":true,"error":null}` when one of the member’s roles grants every requested action. A denied permission returns HTTP 200 with `success: false`. Unknown resources, unknown actions and empty requests yield a negative decision.

| Resource | Owner | Admin | Member |
| --- | --- | --- | --- |
| `organization` | update, delete | update | — |
| `member` | create, update, delete | create, update, delete | — |
| `invitation` | create, cancel | create, cancel | — |
| `team` | create, update, delete | create, update, delete | — |
| `ac` (role definitions) | create, read, update, delete | create, read, update, delete | read |

A signed-in caller with no active organization needs an explicit ID. A caller outside the selected organization receives HTTP 401 with `USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION`. A lookup preserves the session’s current organization and team. Applications can use the result to decide which actions to display. Each protected mutation checks authority and its own conditions when it runs.

In Go, call `authClient.HasOrganizationPermission(ctx, orgID, access.Statements{"invitation": {"create"}})` using `plugins/access`. For a local calculation with known built-in role names, use `organization.DefaultRoleHasPermission("admin,member", requested)`. The HTTP method also reads the current membership, including role changes and removals. The supported HTTP field is `permissions`. The legacy singular `permission` form yields a negative decision. [Role and request comparisons](../conformance/organization-permissions.mjs) · [Go client and database tests](../adapters/sqlstore/organization_selection_http_test.go)

## Configure organization roles

Set `organization.Options.Roles` in the Go host. The same policy governs live permission checks and writes. For example, a newsroom can let editors invite members and publish reports while reserving team management for other roles.

```go
roles := organization.DefaultRoles()
roles["editor"] = access.Statements{
    "invitation": {"create"},
    "reports":    {"read", "publish"},
}
groups, err := organization.New(organization.Options{Store: store, Roles: roles})
```

Import `plugins/organization` and `plugins/access` from the Plain Auth module. Register `groups` in the auth instance’s `Plugins`. A client can submit `{"permissions":{"reports":["publish"]}}` to the permission endpoint. A host route that publishes reports must enforce the same decision for the signed-in user. To evaluate grants locally when you already have a trusted membership, build a policy with `organization.NewRolePolicy("", roles)` and call `policy.HasPermission(membership.Role, requested)`.

`DefaultRoles()` gives you a fresh copy of the owner, admin and member grants. To define all grants yourself, supply a fresh `map[string]access.Statements`. Built-in names remain assignable, and any name you omit has no grants. A non-nil empty map removes all grants. One role must cover the entire requested set of actions, even when the membership has several roles. Running services keep their own copy of the policy. Configure each replica that serves the same application with the same roles.

Set `CreatorRole: "founder"` to assign that name to new organization creators. Include `"founder"` in the role map with the actions founders should have. Only someone holding the creator role can grant it, change a creator's membership, or invite another creator. A creator can update member roles even without an explicit `member.update` grant. Other operations, including sending that invitation, require their configured actions. To transfer the role, grant it to another member before removing it from the original creator. [Role and succession tests](../conformance/organization-custom-roles.mjs)

Team creation, renaming and deletion use `team.create`, `team.update` and `team.delete`. Adding a member to a team or listing another member’s teams requires `member.update`. Removing a team member requires `member.delete`. Sending and listing invitations require `invitation.create`, and cancellation requires `invitation.cancel`. Only holders of the creator role can see invitations that grant that role in organization listings. Permission changes take effect on the next operation using the stored membership. [Storage isolation and callback tests](../adapters/sqlstore/organization_custom_roles_test.go)

## Use roles stored by an organization

Install the `organization-roles` schema profile and set `DynamicAccessControl` on the organization plugin. Add `organization-teams` to the migration and configure `Teams` on the plugin if the host uses teams. [Database setup](schema.md#organization-role-storage)

```go
groups, err := organization.New(organization.Options{
    Store: store,
    DynamicAccessControl: true,
    RoleControl: organization.DefaultRoleControl(),
    Teams: &organization.TeamOptions{},
})
```

The HTTP role API creates definitions in the organization's `organizationRole` table. Trusted provisioning code can also write that table directly. For example, this PostgreSQL statement gives one organization's `desk` role permission to create teams. Supply the role definition ID and organization ID as parameters from trusted server code.

```sql
INSERT INTO "organizationRole" ("id", "organizationId", "role", "permission", "createdAt")
VALUES ($1, $2, 'desk', '{"team":["create"]}', CURRENT_TIMESTAMP);
```

Assign `desk` through the ordinary invitation or member-role endpoints. A different organization can grant different actions to the same name. A database definition can also extend a host-defined role in that organization. One named role must still grant the whole request. The permission endpoint resolves the session, membership and grants in one database snapshot. Organization mutations load the grants in their transaction, including a fresh check when control returns from an invitation callback.

Editing or removing a stored grant takes effect on the next request across replicas. A host using only static roles on the same database continues to use its configured grants. Local `RolePolicy.HasPermission` evaluates the definitions supplied to that policy. Use the HTTP permission check for a current user's database-backed decision. [Cross-application role test](../conformance/organization-stored-roles.mjs) · [SQLite, PostgreSQL and MySQL tests](../adapters/sqlstore/organization_stored_roles_test.go)

### Create a stored role

Enable `DynamicAccessControl` and set `RoleControl` as above. The built-in vocabulary covers organizations, members, invitations, teams, and role administration. For a custom vocabulary, build an `access.Control` with `access.New` and pass its address as `RoleControl`. Configure the actions an actor can grant through the organization's static or stored roles. With no configured control, role creation returns HTTP 501 with `MISSING_AC_INSTANCE`.

Send `POST /organization/create-role` with a signed-in session. For example, this request creates a role that can create teams in one organization.

```json
{"organizationId":"org_a","role":"Desk","permission":{"team":["create"]}}
```

A successful response contains `success: true`, the stored definition in `roleData`, and the granted resource-action map in `statements`. Names are stored in lowercase. Use a single nonempty membership label with no commas or surrounding whitespace. Each name is unique within its organization. Host-defined role names are reserved. Both predefined and duplicate names produce HTTP 400 with `ROLE_NAME_IS_ALREADY_TAKEN`.

Omit `organizationId` to use the active organization. The caller needs `ac.create` and must already hold every requested action in that organization. Actions can come from different roles held by that member. An unknown resource returns HTTP 400 with `INVALID_RESOURCE`. Attempting to delegate an unavailable action returns HTTP 403 and lists the missing resource-action pairs in `missingPermissions`. An empty permission object creates a role with no grants. Go clients can use `errors.As` with `*plainauth.MissingPermissionsError` to inspect the denied grants.

```go
created, err := authClient.CreateOrganizationRole(ctx, organization.CreateRoleRequest{
    OrganizationID: organizationID,
    Role:           "Desk",
    Permission:     access.Statements{"team": {"create"}},
})
```

There is no default limit on the number of stored roles. Set `RoleLimit: &organization.RoleLimit{Maximum: 20}` on the plugin to cap each organization at 20. An explicit zero prevents new roles. Set `Resolve: func(ctx context.Context, organizationID string) (int, error)` instead for a per-organization limit. The host callback runs outside the database transaction. On return the server rechecks the actor, destination, current grants, and remaining capacity. A full organization gets HTTP 400 with `TOO_MANY_ROLES`. [HTTP creation tests](../conformance/organization-create-role.mjs) · [Concurrent creation and quota tests](../adapters/sqlstore/organization_create_role_test.go)

### Read stored roles from any client

With dynamic access control enabled, any client with a signed-in session and the `ac.read` permission can read the organization's stored definitions. The built-in owner, admin, and member roles grant this permission. The directory returns roles saved in the database. Use the [permission check](#check-organization-permissions) to evaluate the combined grants from the database and the host configuration.

| Request relative to the auth mount | Result |
| --- | --- |
| `GET /organization/list-roles` | Up to 100 stored role definitions in the active organization. An empty directory returns `[]`. |
| `GET /organization/list-roles?organizationId=org_a` | The directory of another organization where the caller has read access. |
| `GET /organization/get-role?organizationId=org_a&roleName=desk` | The stored definition with the exact, case-sensitive name `desk`. |
| `GET /organization/get-role?roleId=role_123` | One role in the active organization, including roles outside the returned list. |

For example, a successful lookup returns this JSON.

```json
{
  "id": "role_123",
  "organizationId": "org_a",
  "role": "desk",
  "permission": {"team": ["create"]},
  "createdAt": "2026-01-05T12:00:00.000Z",
  "updatedAt": null
}
```

Supply a nonempty name or ID for a lookup. A nonempty name takes precedence when both are supplied. Omit `organizationId` to use the current session's selection. An explicit empty organization ID returns HTTP 400 with `NO_ACTIVE_ORGANIZATION`. An unknown role in an authorized organization returns HTTP 400 with `ROLE_NOT_FOUND`. A caller without membership or read permission gets HTTP 403. Reading another organization preserves the session's active organization and team.

Go callers can use `client.ListOrganizationRoles(ctx, organizationID)` and `client.GetOrganizationRole(ctx, organization.RoleQuery{OrganizationID: organizationID, RoleName: "desk"})`. Both methods use the client's session. [Client and database tests](../adapters/sqlstore/organization_role_directory_test.go) · [HTTP behavior tests](../conformance/organization-role-directory.mjs)

### Update a stored role

Send `POST /organization/update-role` with a signed-in session and a `data` object. For example, this request replaces every grant on one role. The next permission check by a member holding that role uses the new grants, including checks from an already-open session.

```json
{"organizationId":"org_a","roleId":"role_123","data":{"permission":{"team":["create"]}}}
```

You can select a role by its exact name or ID. A nonempty `roleName` takes precedence when you supply both. Omit `organizationId` to use the active organization. Updating a role in an explicitly selected organization preserves the session's active organization and team.

Omit `data.permission` to retain grants, or send `"permission": {}` to clear them. Include `data.roleName` to rename the definition while keeping its ID. New names are lowercase, unique in the organization, and must be a single membership label. A collision with the current name, another stored name, or a host-defined name returns HTTP 400 with `ROLE_NAME_IS_ALREADY_TAKEN`. Members and pending invitations keep their assigned labels. If members should receive the renamed role's grants, assign the new label through the member-role API.

The caller needs `ac.update` and must be able to delegate each replacement grant. A name-only edit checks the grants being moved to the new label. A failed check returns HTTP 403 with the missing resource-action pairs and leaves the definition intact. Set `RoleControl` on the plugin to configure the resource vocabulary.

A successful write returns `success: true` and the resulting name and grants in `roleData`. Its `updatedAt` is the timestamp from before the write. Read the role again for the stored modification time. An empty `data` object touches that timestamp. Go clients can apply both changes in one request.

```go
updated, err := authClient.UpdateOrganizationRole(ctx,
    organization.RoleQuery{OrganizationID: organizationID, RoleID: roleID},
    organization.RoleUpdate{RoleName: "Copy Desk", Permission: access.Statements{"team": {"create"}}},
)
```

[HTTP and membership tests](../conformance/organization-update-role.mjs) · [Concurrent update and delegation tests](../adapters/sqlstore/organization_update_role_test.go)

### Add fields to organization roles

To attach application data such as a display color to a role, declare the fields on both the schema and the organization plugin. The server stores the values in typed columns. Clients use the logical field names over HTTP. The application decides how to display them.

```go
fields := map[string]organization.RoleField{
    "color": {Type: plainauth.FieldString, Column: "display_color", Default: "blue"},
    "rank":  {Type: plainauth.FieldNumber},
}
store, err := sqlstore.OpenWithAdditionalFields(ctx, "postgres", dsn,
    []string{"organization-roles"}, schema.AdditionalFields{OrganizationRole: fields})
if err != nil {
    return err
}
groups, err := organization.New(organization.Options{
    Store: store, DynamicAccessControl: true,
    RoleControl: organization.DefaultRoleControl(), RoleAdditionalFields: fields,
})
```

On creation, send `{"role":"editor","permission":{},"additionalFields":{"color":"amber","rank":0}}`. On update, send `{"roleName":"editor","data":{"color":"green"}}`. Create, update, get and list return public custom properties directly on the role object. The Go SDK accepts `AdditionalFields` on `organization.CreateRoleRequest` and `organization.RoleUpdate`. Results expose them on `organization.RoleDefinition.AdditionalFields`.

Scalar fields accept strings, booleans, signed 32-bit integers, and RFC 3339 date-times. An omitted optional field gets its creation default or `null`. An update preserves omitted fields, and explicit `null` clears an optional value. A required column always retains a value. Inside a supplied creation envelope, include all required writable fields. Omitting the entire envelope allows configured creation defaults to supply them.

Use `ServerOnly` for values the host supplies. Use `Hidden` for values that must stay out of responses, including the write acknowledgement. Unknown input fields are ignored. The generated OpenAPI description includes writable fields on requests and returned fields on responses. [Migrations](schema.md#organization-role-storage) · [Cross-application HTTP tests](../conformance/organization-role-fields.mjs) · [SDK and database tests](../adapters/sqlstore/organization_role_fields_test.go)

#### Store JSON and arrays on roles

Use `organization.RoleJSON`, `organization.RoleStringArray`, or `organization.RoleNumberArray` as a field's `Type`. The CLI type names are `json`, `string[]`, and `number[]`. For example, a host can store display preferences and ranking weights with these declarations.

```json
{
  "display": {"type":"json","column":"role_display"},
  "tags": {"type":"string[]","default":["review"]},
  "weights": {"type":"number[]"}
}
```

To replace these values, send the following request to `POST /organization/update-role`.

```json
{"roleName":"editor","data":{"display":{"color":"amber","featured":false},"tags":[],"weights":[0,-1.75,2.125]}}
```

Each supplied value replaces the whole field. An empty array is stored as an array. Explicit `null` clears an optional field. Omitting it preserves the saved value. String arrays accept strings, and number arrays accept finite numbers including fractions. JSON accepts objects, arrays, strings, numbers, booleans, and nullable fields accept null. Keys and strings must be free of NUL characters for portability across databases. The OpenAPI description publishes array item types. PostgreSQL stores these fields as `jsonb`, MySQL as `json`, and SQLite as JSON text. [Cross-application comparisons](../conformance/organization-role-fields.mjs) · [SQL round trips](../adapters/sqlstore/organization_role_fields_test.go)

### Remove a stored role

Send `POST /organization/delete-role` with a signed-in session that has `ac.delete` in the destination organization. Supply a case-sensitive role name or ID. A nonempty name takes precedence if both are present. Omit `organizationId` to use the active organization.

```json
{"organizationId":"org_a","roleName":"desk"}
```

If anyone in that organization still holds `desk`, even alongside another role, the server returns HTTP 400 with `ROLE_IS_ASSIGNED_TO_MEMBERS`. Reassign those members with `POST /organization/update-member-role` before retrying. Looking up a predefined role by name returns HTTP 400 with `CANNOT_DELETE_A_PRE_DEFINED_ROLE`. A successful removal returns `{"success":true}`. Repeating it returns HTTP 400 with `ROLE_NOT_FOUND`.

The operation preserves the caller's active organization and team. A role with the same name in a different organization keeps its grants. In Go, call `client.DeleteOrganizationRole(ctx, organization.RoleQuery{OrganizationID: organizationID, RoleID: roleID})`. [Role removal HTTP tests](../conformance/organization-delete-role.mjs) · [Concurrent assignment and removal tests](../adapters/sqlstore/organization_delete_role_test.go)

## Read an organization and its directory

Send `GET /organization/get-full-organization` with a session cookie. A nonempty `organizationSlug` selects the destination first, followed by `organizationId`, then the session's active organization. With no selector and no active organization, the response is HTTP 200 with JSON `null`. Looking up another organization you belong to preserves your active organization and team.

```sh
curl --fail-with-body -b cookies.txt --get \
  https://app.example.com/api/auth/organization/get-full-organization \
  --data-urlencode 'organizationSlug=studio' --data-urlencode 'membersLimit=20'
```

The response includes the organization's profile fields and these collections, all read from the same database snapshot.

| Field | What the signed-in user can see |
| --- | --- |
| `members` | Each membership and its user's public `id`, `name`, `email` and `image`. `membersLimit` controls this collection only. The default is the fixed membership limit, or 100. Use `list-members` to filter or page through the roster. |
| `invitations` | Owners see invitations across all statuses. Admins can see invitations for roles they may grant. Invitations containing the owner role are visible only to an owner. Other members receive an empty array. The endpoint reads up to 100 invitations before applying role visibility. |
| `teams` | When teams are enabled, every member can read the first 100 teams in the organization, including teams they have not joined. An empty organization returns `[]` for this field. With teams disabled the field is omitted. |

The member list, team list and invitation list each sort by creation time, then ID. Membership permission is checked even if the caller falls outside the requested member page. An unknown ID or slug returns HTTP 400 with `ORGANIZATION_NOT_FOUND`. An existing organization the caller does not belong to returns HTTP 403 with `USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION` and clears the calling session's observed organization and team selection. Other sessions retain their selections. Your client decides which screen to display after either response.

```go
view, err := authClient.FullOrganization(ctx, organization.FullOrganizationQuery{
    OrganizationSlug: "studio",
    MembersLimit:     20,
})
```

With an empty query, a nil result and nil error indicate a signed-in session without a selection. [Client comparison](../conformance/organization-full.mjs) · [Three-database visibility tests](../adapters/sqlstore/organization_full_test.go)

## List organization members

Send `GET /organization/list-members` with a session cookie. Any member can read the directory. It uses the active organization by default. Pass `organizationId` or `organizationSlug` to read another organization you belong to. A nonempty slug takes precedence. This request preserves the session's organization and team selections.

```sh
curl --fail-with-body -b cookies.txt --get \
  https://app.example.com/api/auth/organization/list-members \
  --data-urlencode 'organizationSlug=studio' \
  --data-urlencode 'filterField=role' --data-urlencode 'filterOperator=in' \
  --data-urlencode 'filterValue=owner' --data-urlencode 'filterValue=admin' \
  --data-urlencode 'sortBy=createdAt' --data-urlencode 'sortDirection=desc' \
  --data-urlencode 'limit=20'
```

The response contains `members` and `total`. Each member has `id`, `organizationId`, `userId`, `role`, `createdAt` and a `user` object with `id`, `name`, `email` and nullable `image`. The total counts all matching memberships before pagination. A page beyond the last result returns an empty array and the same filtered total.

| Query parameter | Behavior |
| --- | --- |
| `limit`, `offset` | Use nonnegative integers. The first page starts at offset 0. Its default size is the fixed membership limit, or 100 when the application uses a resolver or leaves the limit unset. A zero limit uses the default. Larger explicit pages can include every matching member. |
| `sortBy`, `sortDirection` | Sort by `id`, `organizationId`, `userId`, `role` or `createdAt`. Choose `asc` (default) or `desc`. The SQL adapters use the membership ID to break ties. |
| `filterField`, `filterValue` | Use one of the same five membership fields. Supply timestamps as RFC 3339 or a date as `YYYY-MM-DD` for date comparisons. |
| `filterOperator` | Defaults to `eq`. Comparisons also support `ne`, `lt`, `lte`, `gt` and `gte`. Repeat `filterValue` for `in` and `not_in`. The pattern operators `contains`, `starts_with` and `ends_with` support the SQL wildcards `%` and `_`. |

```go
page, err := authClient.ListOrganizationMembers(ctx, organization.MemberListQuery{
    OrganizationSlug: "studio",
    SortBy: "createdAt", SortDirection: "desc",
    FilterField: "role", FilterOperator: "in", FilterValues: []string{"owner", "admin"},
    Limit: 20,
})
```

An unsigned request receives HTTP 401. A session with no active organization needs an explicit selector. An unknown slug returns HTTP 400 with `ORGANIZATION_NOT_FOUND`. A caller without membership receives HTTP 403, including when a filter would match zero members. [Client comparison](../conformance/organization-directory.mjs) · [Database snapshot tests](../adapters/sqlstore/organization_directory_test.go)

## Update an organization's profile

An owner or admin can change the profile in one request. Use the signed-in Go client or send `POST /organization/update` under your auth mount. Supply `organizationId` to select a specific organization. Omit it to use the organization selected on the current session.

```json
{"organizationId":"org_example","data":{"name":"Customer Support","slug":"support","logo":null,"metadata":{"region":"west"}}}
```

Only the supplied fields change. A JSON null clears the logo. Metadata replaces the entire object. The response contains the updated organization with its original ID and creation time. A slug collision returns `400 ORGANIZATION_SLUG_ALREADY_TAKEN` and rolls back every field in the request. An ordinary member receives `403 YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION`.

Set `organization.Options.BeforeUpdateOrganization` to inspect submitted profile fields, the signed-in user and their current membership. Return a `*organization.ProfileUpdate` to replace selected fields or return nil to accept the request. Its `Metadata` replaces the entire metadata object. Set `ClearLogo` to remove the logo. Initial validation, membership permission and the requested slug's availability are checked before the callback. Only explicitly returned overrides change the request.

`AfterUpdateOrganization` receives the committed organization and the actor and membership snapshots from the request. A before-hook error prevents the update. An after-hook error reaches the caller after the change has committed. Retrying a request runs the hooks again. The SQL adapter supplies the updated row. A custom adapter that cannot return an updated row can supply nil to the after hook.

The SQL adapter releases its locks while host callbacks run. Before writing, it checks the original organization and membership, their creation times, the acting session, current role and account status. An implicitly selected organization must still be active. An explicit organization ID remains the target if the browser switches its active selection. A concurrent update to an unrelated profile field survives when the request and returned overrides omit that field. The Go service enforces the same checks for native calls. A custom store that enables either callback must implement `organization.ObservedProfileStore`.

A signed-in user can call `POST /organization/check-slug` with `{"slug":"support"}`. It returns `{"status":true}` for an available slug. Another request can claim the slug before the update. Check the update’s result when saving. The Go client exposes both methods.

```go
name := "Customer Support"
updated, err := c.UpdateOrganization(ctx, orgID, organization.ProfileUpdate{
    Name: &name, ClearLogo: true,
    Metadata: map[string]any{"region": "west"},
})
```

SQL adapters check the live session and current membership in the update transaction. The authenticated native service accepts the same change through `service.UpdateOrganization`. [Browser and role tests](../conformance/organization-profile.mjs) · [Concurrent slug claims](../adapters/sqlstore/organization_profile_test.go)

## Delete an organization

A member whose role grants `organization.delete` can delete the organization. The built-in `owner` role has it, and `admin` does not. Send `POST /organization/delete` with `{"organizationId":"org_example"}`, or call `c.DeleteOrganization(ctx, orgID)` from the Go client. The response contains the deleted organization's profile.

The SQL adapter deletes the organization with its members, invitations, teams and team memberships, stored roles and organization-owned API keys in one transaction. Every session that selected the organization or one of its teams loses that selection, including other users' sessions. User accounts remain.

| Result | Status and code |
| --- | --- |
| Missing or non-string `organizationId` | `400 VALIDATION_ERROR` |
| Empty `organizationId` | `400 ORGANIZATION_NOT_FOUND` |
| No session | `401 UNAUTHORIZED` |
| Caller is not a member, or the organization does not exist | `400 USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION` |
| Caller's role lacks `organization.delete` | `403 YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION` |
| `DisableOrganizationDeletion: true` | `404 ORGANIZATION_DELETION_DISABLED` |

Set `BeforeDeleteOrganization` to inspect the organization and the signed-in user after the permission check. Returning an error cancels the deletion. The adapter checks the session and permission again in the deleting transaction, so a member demoted while the hook runs cannot delete. `AfterDeleteOrganization` runs after the deletion commits; its error reaches the caller and the organization stays deleted. A custom store must implement `organization.OrganizationDeletionStore` to serve the route.

Stripe organization subscriptions are not checked yet. Cancel an organization's subscription before deleting it. [HTTP, hook and cleanup tests on three SQL engines](../adapters/sqlstore/organization_deletion_test.go)

## Change membership roles

Send the membership ID in `memberId` and the replacement roles in `role`. The endpoint accepts a string or an array of strings, trims whitespace, splits comma-separated entries and preserves their order. Omit `organizationId` to use the organization selected on this session. The response is the updated member with its ID, organization ID, user ID, role and creation time.

| Acting membership | Authorized changes |
| --- | --- |
| Owner | Set any built-in role, including granting ownership to another member. The organization must retain an owner. |
| Admin | Change a member or admin to any combination of `admin` and `member`, including changing their own membership. |
| Member | No role changes. |

To transfer ownership, grant `owner` to the new owner, then replace the previous owner's role. Both members hold ownership between these two requests. Permissions take effect on the next request, including requests from another server process using the same database.

```go
change := organization.UpdateMemberRoleRequest{
    OrganizationID: organizationID,
    MemberID:       membershipID,
    Roles:          []string{"admin"},
}
updated, err := authClient.UpdateOrganizationMemberRole(ctx, change)
```

A Go server can call `organizations.UpdateMemberRole(ctx, session.Session, change)` with a signed-in session returned by `auth.GetSession`. Both entry points recheck the session and current membership before committing. The built-in policy covers `owner`, `admin` and `member`. Hosts can [configure custom roles](#configure-organization-roles). Role-change hooks remain open on the [organization checklist](parity/plugins/organization.md). [Released client comparison](../conformance/organization-role.mjs) · [Database concurrency tests](../adapters/sqlstore/organization_role_test.go)

## Remove a member or leave

Owners and admins can remove a member or an admin. Only an owner can remove another owner, and these membership operations preserve at least one owner. A member can leave using their signed-in session. The SQL store serializes the final-owner check with each membership change.

Deleting the entire user account also removes its memberships. If that account held an organization's only owner role, the organization stays in the database and its other members keep their current roles. To retain an owner, grant another account the owner role before deleting the existing owner's account. [Database test](../adapters/sqlstore/organization_cleanup_test.go)

Pass a membership ID or the account's email as `memberIdOrEmail`. IDs are case-sensitive and belong to the named organization. Email lookup accepts mixed case. A membership from another organization returns `MEMBER_NOT_FOUND`. The removal response contains `member`. Email lookup also includes that member's public user profile. Leaving returns the caller's membership and public user profile directly.

The Go HTTP client provides `RemoveOrganizationMember(ctx, memberIDOrEmail, organizationID)` and `LeaveOrganization(ctx, organizationID)`. An empty organization ID on removal uses that client's active selection.

Removal releases the member's team seats in that organization and clears its organization and team selections from every affected session. This also works when the handling process uses the organization plugin without teams while sharing a team-enabled database. Sessions selecting another organization retain that selection. [Client comparison](../conformance/organization-removal.mjs) · [Three-database concurrency tests](../adapters/sqlstore/organization_removal_test.go)

## List organization invitations

Use a signed-in owner or admin session to call `GET /organization/list-invitations`. The optional `organizationId` selects another organization you belong to. Without an ID, the request uses the current session's active organization. This endpoint preserves both organization and team selections on success and on error.

```sh
curl --fail-with-body -b cookies.txt --get \
  https://app.example.com/api/auth/organization/list-invitations \
  --data-urlencode 'organizationId=org_a'
```

The JSON response is an array. Each entry includes the invitation ID, organization ID, inviter ID, recipient email, granted roles, status, creation time and expiry. The list includes expired invitations and all stored statuses. Branch on `status` and `expiresAt` when displaying actions. With teams enabled, `teamId` is null for an organization-wide invitation or a string containing its team IDs separated by commas. The field is absent when teams are disabled.

The database reads up to 100 invitations in creation order, using the ID to break ties. Owners can see the whole page. Admins see only invitations whose roles exclude `owner`. Ordinary members receive HTTP 403 with `YOU_ARE_NOT_ALLOWED_TO_LIST_INVITATIONS`, including when the organization has no invitations. A missing selection returns HTTP 400. An unknown organization or one the caller does not belong to returns HTTP 403.

In Go, call `authClient.ListOrganizationInvitations(ctx, organizationID)`, using an empty string for the active organization. To require recipients to verify their account email before accepting an invitation, set `RequireVerifiedEmail: true` in the organization options. [HTTP client comparison](../conformance/organization-invitations.mjs) · [Go client and session tests](../adapters/sqlstore/organization_selection_http_test.go)

## Issue an invitation

Call `POST /organization/invite-member` with a membership that grants `invitation.create`. The request must include `email` and `role`. Supply an `organizationId` to choose the destination, or omit it to use the current session’s active organization. An explicit destination leaves the sender’s selection in place.

The handler lowercases the recipient address. Send a single role, a comma-separated string, or an array of strings. It trims role names, drops empty entries and keeps their submitted order. The built-in roles are `owner`, `admin` and `member`. Granting the configured creator role requires a caller who holds it. The SQL adapter checks membership and permission to invite before validating the requested role names. A nonmember receives `MEMBER_NOT_FOUND`, and an ordinary member receives HTTP 403. A sender with permission to invite receives an error identifying any unknown roles.

Omit `teamId` to invite someone to the organization alone. An explicit JSON `null` in the request returns HTTP 400 with `VALIDATION_ERROR`. With teams enabled, send a team ID or an array of IDs from the destination organization. Accepting a single-team invitation selects that team for the accepting session. Accepting an invitation to several teams grants membership in each and leaves the active team empty. The client can then select one with `POST /organization/set-active-team`.

| `teamId` in the request | Result when teams are enabled |
| --- | --- |
| Omitted or `[]` | Creates an organization-wide invitation. The saved `teamId` is `null`. |
| `""` | Creates an organization-wide invitation and preserves the empty string in the response. |
| A team ID or a list of IDs | Each team must belong to the destination and have capacity. The saved string preserves the submitted order, including repeats. |
| A list containing an empty ID | Returns `TEAM_NOT_FOUND`. |
| An ID containing a comma | Returns `INVALID_TEAM_ID`. |

Repeating a team ID grants one membership in that team. Sending two entries leaves the active team unset, even when the IDs are identical. Resending a live grant preserves its saved team targets. It still validates the JSON type of the submitted field.

A host with teams disabled accepts a string or a list of strings, creates an organization-wide grant and omits `teamId` from the response. Its before-creation callback can inspect the submitted IDs. A team-enabled host sharing that database sees the saved grant as organization-wide. [Team target comparison](../conformance/invitation-team-targets.mjs) · [Mixed-node database tests](../adapters/sqlstore/organization_topology_test.go)

```go
invite, err := authClient.InviteOrganizationMember(ctx, client.InviteOrganizationMemberRequest{
    Email: "guest@example.com",
    Roles: []string{"member"},
    OrganizationID: studioID,
    TeamIDs: []string{designTeamID, researchTeamID},
})
if err != nil {
    return err
}
return recordPendingGrant(ctx, invite.ID)
```

The example’s `recordPendingGrant` belongs to the host. Set `Resend: true` to renew a live grant for the same mailbox and destination. The response contains the saved ID, roles, team targets and deadline. A fresh organization-wide grant has `teamId: null` when teams are enabled. [Request and response comparison](../conformance/invitation-input.mjs) · [Native client tests on three databases](../adapters/sqlstore/organization_selection_http_test.go)

## Customize an invitation before saving it

Set `BeforeCreateInvitation` on `organization.Options` to review a new grant. The callback receives the normalized recipient address and roles, the ordered team targets, the destination organization, and the issuing user's public profile. For example, this host gives new invitations seven days to expire.

```go
groups, err := organization.New(organization.Options{
    Store: store,
    BeforeCreateInvitation: func(ctx context.Context, event organization.InvitationCreationEvent) (*organization.InvitationChanges, error) {
        deadline := time.Now().UTC().Add(7 * 24 * time.Hour)
        return &organization.InvitationChanges{ExpiresAt: &deadline}, nil
    },
})
```

Return `nil, nil` to accept the proposal as submitted. Return an error to stop issuance. Set `Email`, `Roles`, `TeamIDs`, or `ExpiresAt` in the returned changes to override those values. An empty `[]string{}` for `TeamIDs` makes the grant organization-wide. A nil slice keeps the proposed teams. `event.Invitation.TeamID` identifies the first proposed team when present.

The SQL adapter checks the sender, destination, teams, and available invitation slots before the callback. It releases database locks while host code runs, then checks eligibility again before saving the grant. An implicitly selected organization must still be active in the issuing session. A changed recipient must be eligible for a fresh invitation. The host's final roles and teams must be within the sender's authority. A failed replacement preserves the original pending invitation.

A successful write delivers the saved values to the configured email sender and then to `AfterCreateInvitation`. A resend of a live grant goes straight to renewal and delivery. A resend that creates a new grant runs the full creation sequence. Custom stores that support the before callback implement `organization.PreparedInvitationStore`. [HTTP lifecycle tests](../conformance/invitation-preparation.mjs) · [Concurrent database changes](../adapters/sqlstore/organization_invitation_preparation_test.go)

## Deliver invitation email

Set `SendInvitationEmail` on `organization.Options` to deliver mail or enqueue a message in your own system. The callback receives the committed invitation, its destination organization, the sending membership with its public user profile, and the normalized recipient address in `Email`. Use `Request` for request metadata such as a language header. JSON serialization excludes the request. Your application chooses the mail provider, template and link destination.

On a resend, `Inviter` identifies the member sending the new message. `Invitation.InviterID` still identifies the person who issued the original grant. The original ID, role and targeted teams remain available in `Invitation`. The SQL adapter captures these fields in the transaction that saves the grant. Delivery runs after commit, so the callback can read the invitation through another connection.

The handler waits for `SendInvitationEmail`. If it returns an error, Plain Auth logs a delivery failure and returns the committed invitation. A successful invite response confirms the grant was saved. To retry delivery, send the same invitation request with `resend: true`. Applications that need delivery confirmation can record the mail provider’s receipt in their callback. The simpler `SendInvitation(ctx, invitation)` callback returns HTTP 500 on delivery failure and also preserves the grant. Configure one sender. Custom stores using `SendInvitationEmail` implement `organization.InvitationDeliveryStore`. Its result sets `Resent` to true when it renews an existing grant. [HTTP delivery and resend tests](../conformance/invitation-delivery.mjs) · [Three-engine delivery tests](../adapters/sqlstore/organization_delivery_test.go)

## Observe newly issued invitations

Set `AfterCreateInvitation` on `organization.Options` to record a new invitation in your application. The callback receives the committed invitation, its destination organization and the public account of the member who issued it. For example, store an audit record using `event.Invitation.ID`, `event.Organization.ID` and `event.Actor.ID`.

The callback runs after the configured sender. With `SendInvitationEmail`, it also runs when delivery returns an error, since the grant still exists. With no sender configured, it runs immediately after commit. A replacement has a fresh ID and triggers the callback. Explicitly resending a live invitation renews its deadline and delivers mail without triggering another creation callback. A resend request that finds no live grant creates one and triggers the callback.

A creation callback error fails the HTTP request. The invitation remains pending and can be retrieved with `ListOrganizationInvitations`. Resending that saved grant leaves the creation callback’s invocation count unchanged. [Creation and delivery order tests](../conformance/invitation-creation.mjs)

## Limit outstanding invitations

Each organization can have 100 unexpired pending invitations by default. Configure `InvitationLimit: &organization.InvitationLimit{Maximum: 10}` for a fixed cap. An explicit maximum of zero prevents new grants. An explicit resend renews an existing live invitation without consuming a slot. A successful replacement uses the previous grant’s slot. Expired, accepted, rejected and canceled invitations consume no slots.

To choose a limit using application policy, set a resolver on the organization plugin.

```go
groups, err := organization.New(organization.Options{
    Store: store,
    InvitationLimit: &organization.InvitationLimit{
        Resolve: func(ctx context.Context, input organization.InvitationLimitInput) (int, error) {
            return invitationAllowance(ctx, input.Organization.ID, input.Member.Role)
        },
    },
})
```

The host implements `invitationAllowance`. The resolver receives the inviter’s core account, current membership and destination organization after the server checks permission. It runs outside database locks. The SQL adapter rechecks those inputs and counts live invitations in the transaction that issues the grant. Competing issuers share the same quota. At capacity the API returns HTTP 403 with `INVITATION_LIMIT_REACHED`. Changed resolver inputs can return HTTP 409 with `INVITATION_POLICY_INPUT_CHANGED`. A failed replacement leaves the previous invitation usable. [Client comparison](../conformance/invitation-limits.mjs) · [Three-engine quota tests](../adapters/sqlstore/organization_invitation_limit_test.go)

## Replace an outstanding invitation

By default, inviting the same email address to the same organization again returns `USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION` while the earlier invitation is pending and unexpired. To send the original invitation again, pass `"resend": true` to `POST /organization/invite-member`. The recipient keeps the original ID, roles and team targets.

Set `CancelPendingInvitationsOnReInvite: true` on `organization.Options` when a fresh invitation should replace the previous grant. An ordinary invite request then cancels the old invitation and issues a new ID with the requested roles and teams. An explicit resend still renews the original grant. Invitations for the same email in other organizations are independent.

The SQL adapter commits the cancellation and replacement in one transaction. A rejected team assignment leaves the earlier invitation pending. Concurrent replacements for the same organization and mailbox leave one live grant. A custom store enabling this option implements `organization.InvitationReplacementStore`. [Client comparison](../conformance/invitation-expiration.mjs) · [Database concurrency and rollback tests](../adapters/sqlstore/organization_replacement_test.go)

## Accept an invitation

After the recipient signs in, send the invitation ID from your delivery callback to the auth handler. Treat the ID as an opaque, case-sensitive string. The same request works from a browser, a native app or a command-line client.

```sh
curl --fail-with-body -b cookies.txt -c cookies.txt \
  -H 'Origin: https://app.example.com' -H 'Content-Type: application/json' \
  --data '{"invitationId":"invite_123"}' \
  https://app.example.com/api/auth/organization/accept-invitation
```

The JSON response contains an `invitation` with status `accepted` and a `member` with its own ID, organization ID, user ID, role and creation time. The SQL adapter grants the organization and targeted team memberships together. The accepting session selects the organization. An invitation to one team also selects that team. In a team-enabled organization, an organization-wide invitation returns `teamId: null`. Your application decides what the recipient sees next.

The signed-in account's email must match the invitation address, ignoring case. Enable `RequireVerifiedEmail` to also require a verified address. An expired or previously decided invitation returns HTTP 400 with `INVITATION_NOT_FOUND`. If an organization or team is full, the grant stays pending so the recipient can retry when a seat opens.

Go callers use `joined, err := authClient.AcceptOrganizationInvitation(ctx, invitationID)` and read `joined.Invitation` and `joined.Member` after success. [HTTP and session tests](../conformance/organization-invitations.mjs) · [Go client example](../plugins/organization/organization_test.go)

## Cancel an invitation

An owner or admin can send `POST /organization/cancel-invitation` with `{"invitationId":"invite_123"}` to withdraw an invitation sent by any member of that organization. The server checks the caller’s current membership in the invitation’s destination. The caller can have a different organization selected.

On success the response is the invitation itself with `status: "canceled"`. Cancellation works for pending, expired, rejected and accepted invitations. Repeating it returns the canceled invitation. If the recipient has already joined, their organization membership, team memberships and session selections stay in effect. To end that access, use the membership removal endpoint.

An unknown ID returns HTTP 400 with `INVITATION_NOT_FOUND`. An account outside the destination organization receives HTTP 400 with `MEMBER_NOT_FOUND`. A member without cancellation permission receives HTTP 403 with `YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION`. Go clients call `authClient.CancelOrganizationInvitation(ctx, invitationID)`. [Client comparison](../conformance/organization-invitations.mjs) · [Database tests](../adapters/sqlstore/organization_decision_test.go)

## Decline an invitation

Send `POST /organization/reject-invitation` from the recipient’s signed-in session. Supply the invitation’s exact ID in a JSON body.

```sh
curl --fail-with-body -b cookies.txt \
  -H 'Origin: https://app.example.com' -H 'Content-Type: application/json' \
  --data '{"invitationId":"invite_123"}' \
  https://app.example.com/api/auth/organization/reject-invitation
```

The response contains the invitation with `status: "rejected"` and `member: null`. The account keeps its current organization and team. A pending invitation can be declined after its expiry. If it has already been accepted, canceled or rejected, the request returns HTTP 400 with `INVITATION_NOT_FOUND`. A concurrent acceptance and rejection have one winner.

The account’s current email must match the invitation address, ignoring case. Enable `RequireVerifiedEmail` to require verification as well. Go clients call `authClient.RejectOrganizationInvitation(ctx, invitationID)`. [HTTP comparison](../conformance/organization-invitations.mjs) · [Three-database concurrency test](../adapters/sqlstore/organization_decision_test.go)

## Observe invitation decisions

Set `BeforeAcceptInvitation` or `AfterAcceptInvitation` to run host code when a recipient joins. The corresponding rejection and cancellation options are `BeforeRejectInvitation`, `AfterRejectInvitation`, `BeforeCancelInvitation`, and `AfterCancelInvitation`. Each callback receives the request context and an `organization.InvitationDecisionEvent`. Its `Actor` is the recipient for acceptance or rejection and the administrator for cancellation. The event includes the destination organization and the invitation, including its targeted teams.

```go
groups, err := organization.New(organization.Options{
    Store: store,
    AfterAcceptInvitation: func(ctx context.Context, event organization.InvitationDecisionEvent) error {
        return recordMembership(ctx, event.Member.ID, event.Actor.ID, event.Organization.ID)
    },
    BeforeCancelInvitation: func(ctx context.Context, event organization.InvitationDecisionEvent) error {
        return checkCancellationPolicy(ctx, event.Actor.ID, event.Organization.ID, event.Invitation.ID)
    },
    AfterRejectInvitation: func(ctx context.Context, event organization.InvitationDecisionEvent) error {
        return recordDecline(ctx, event.Invitation.ID, event.Actor.ID)
    },
})
```

The example’s policy and recording functions belong to the host application. The before callback runs once per authorized request, before the write and outside database locks. Returning an error leaves the invitation untouched by that request. The SQL adapter checks the session, account, invitation, organization and cancellation permission again before committing. If inputs changed while the callback ran, the request can return HTTP 409 with `INVITATION_DECISION_CHANGED` or the applicable authorization error.

Acceptance checks the live recipient, email verification policy and available organization seats before calling the before hook. Its `Member` is nil. The after hook receives the newly committed `Member`, including its ID and role. At that point the recipient belongs to the invited teams and their accepting session has selected the organization. A single invited team is also selected. Other sessions keep their own selections.

If an after hook returns an error, the HTTP request fails and the database retains the decision. A client recovering from an acceptance error can read its session and membership. Retrying an already accepted invitation returns `INVITATION_NOT_FOUND`. Repeating an authorized cancellation can deliver another callback for the same invitation. Custom adapters implement `organization.ObservedInvitationAcceptanceStore` for acceptance hooks and `organization.ObservedInvitationDecisionStore` for rejection and cancellation hooks. [Hook comparison](../conformance/invitation-hooks.mjs) · [Acceptance and capacity tests](../adapters/sqlstore/organization_acceptance_hooks_test.go) · [Rejection and cancellation tests](../adapters/sqlstore/organization_decision_hooks_test.go)

## Read one invitation

Use `GET /organization/get-invitation?id=INVITATION_ID` to display the details of an invitation before the recipient decides whether to accept. Send the recipient’s signed-in session. The opaque ID comes from your invitation delivery callback or the recipient’s inbox.

```sh
curl --fail-with-body -b cookies.txt --get \
  https://app.example.com/api/auth/organization/get-invitation \
  --data-urlencode "id=$INVITATION_ID"
```

The response includes the invitation fields, the current `organizationName`, `organizationSlug` and the current `inviterEmail`. The inviter must still belong to that organization. The recipient can read the invitation before joining. Reading it preserves the invitation status and the session’s organization and team.

| Condition | HTTP result |
| --- | --- |
| Missing session | 401 |
| Unknown ID, expired invitation or a status other than pending | 400 `INVITATION_NOT_FOUND` |
| Signed-in account has a different email | 403 `YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION` |
| `RequireVerifiedEmail` is enabled and the recipient has an unverified email | 403 `EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION` |
| The original inviter has left the destination organization | 400 `INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION` |

In Go, call `authClient.OrganizationInvitation(ctx, invitationID)`. A client that only knows the recipient’s email can use the verified inbox described below once the recipient signs in. [Client comparison](../conformance/organization-invitations.mjs) · [Database and verification tests](../adapters/sqlstore/organization_received_test.go)

## Read the recipient’s invitations

Call `GET /organization/list-user-invitations` with the signed-in recipient’s session cookie. The account must have a verified email, including when your organization allows accepting an invitation without prior verification. The user can read their invitations before joining an organization or selecting a team. The request preserves the session’s organization and team.

```sh
curl --fail-with-body -b cookies.txt \
  https://app.example.com/api/auth/organization/list-user-invitations
```

The response is a JSON array of pending invitations addressed to that verified account, with `organizationName` alongside each invitation. An expired invitation can still have a pending status. Check `expiresAt` before offering an accept action. The SQL store considers the first 100 records for the mailbox in creation order and returns the pending entries from that page. A verified account with no matching invitations receives `[]`. An unverified account receives HTTP 403 with `EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION`. Missing session credentials or a nonempty HTTP `email` query parameter returns HTTP 400.

Go HTTP clients call `authClient.ListUserInvitations(ctx)`. Trusted host code with an organization service can look up a mailbox directly, for example in a support workflow after the application authorizes the operator.

```go
invitations, err := organizations.ListInvitationsForEmail(ctx, "recipient@example.com")
```

The trusted lookup accepts mixed-case email and requires no session. [Recipient client comparison](../conformance/organization-invitations.mjs) · [Live mailbox and revocation tests](../adapters/sqlstore/organization_received_test.go)

## Grant membership from your application

Create an organization service if your application grants access to existing accounts, for example after a provisioning job approves a new employee. Mount its plugin and keep the service for trusted Go calls.

```go
organizations, err := organization.NewService(organization.Options{Store: store})
if err != nil {
    return err
}
// Include organizations.Plugin() in plainauth.Options.Plugins at startup.
// After your application has authorized this specific grant:
member, err := organizations.AddMember(ctx, organization.AddMemberRequest{
    OrganizationID: organizationID,
    UserID:         employeeID,
    Roles:          []string{"member"},
})
```

The trusted server chooses the role labels. Commas split names, surrounding whitespace and empty components are removed, and order and repeated names are preserved. For example, `[]string{"editor, reviewer", "editor"}` is stored as `editor,reviewer,editor`. A label acquires actions from the organization’s configured policy. An explicit empty slice grants membership with no role actions. This member can still join or select a team. A nil slice omits the required role input and returns a validation error. HTTP invitations and member role changes validate role names against the host policy. [Server grant comparison](../conformance/organization-server-grants.mjs)

Supply the exact organization and user IDs. A duplicate grant returns `USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION`. To add the user to a team in the same transaction, enable `Teams` on the service and set `TeamID` to a team in that organization. A full team rolls back the entire grant. Granting membership preserves the user's current browser selection. [Three-database membership tests](../adapters/sqlstore/organization_members_test.go)

## Limit organization membership

An organization starts with one owner, who counts toward its seat limit. The default limit is 100. A direct grant or invitation acceptance that would exceed the limit returns `ORGANIZATION_MEMBERSHIP_LIMIT_REACHED` (HTTP 403). A denied invitation stays pending and the session keeps its current organization and team. Sending an invitation takes no seat. Lowering a limit preserves existing memberships.

For a fixed limit, set `MembershipLimit: organization.MembershipLimit{Maximum: 25}` in `organization.Options`. A fixed limit also determines the default member directory page size. Readers can always request a larger page explicitly.

To vary capacity by account or organization, supply a resolver. This example looks up the organization's purchased seats and allows the application to check whether this particular account qualifies.

```go
policy := organization.MembershipLimit{
    Resolve: func(ctx context.Context, candidate plainauth.User, org organization.Organization) (int, error) {
        return plans.AvailableMembershipLimit(ctx, org.ID, candidate.ID)
    },
}
scoped, err := store.WithMembershipLimit(policy)
if err != nil {
    return err
}
orgPlugin, err := organization.New(organization.Options{Store: scoped})
if err != nil {
    return err
}
auth, err := plainauth.New(plainauth.Options{
    Store: scoped, BaseURL: origin, Secret: secret,
    Plugins: []plainauth.Plugin{orgPlugin, enterpriseSSO},
})
```

`plans.AvailableMembershipLimit` is your application function. Return the **total seats allowed**, including occupied seats. A resolver returning zero denies this admission. Return an error when the policy cannot be evaluated. The SQL adapter calls the resolver outside the transaction with the candidate's core account fields and the destination organization's profile. It then rechecks the inputs, permissions and seat count before committing. If the candidate, invitation or organization changes during the lookup, the write can return HTTP 409 with `MEMBERSHIP_POLICY_INPUT_CHANGED`. Retrying the request evaluates the current data. Directory reads use a default page size of 100 with a resolver.

When enterprise SSO provisions memberships, supply the same scoped SQL store to the auth handler and organization plugin on every server. In the example, `enterpriseSSO` is the configured SSO plugin. The scoped store shares the original database connection pool. Concurrent admissions compete for seats in the database. A denied enterprise admission commits neither a new identity nor its session. [Three-database admission tests](../adapters/sqlstore/organization_limit_test.go) · [Client comparison](../conformance/organization-capacity.mjs)

## Teams

Use the `organization-teams` schema profile and enable `Teams` on the organization plugin.

```go
memberLimit := 15
plugin, err := organization.New(organization.Options{
    Store: store,
    Teams: &organization.TeamOptions{
        MaximumTeams:          10,
        MaximumMembersPerTeam: &memberLimit,
    },
})
```

Creating an organization also creates a team with the organization's name, adds its creator, and selects the team on that session. `DisableDefaultTeam` skips the initial team. `keepCurrentActiveOrganization: true` preserves the creator’s current organization and team. Creating additional teams starts them empty.

Owners and admins manage teams and membership. An organization member can list their organization's teams. Reading the membership of a specific team requires membership in both that team and its organization. A user can list their own teams across organizations. An owner or admin can list another user's teams in the organization they manage.

| Method | Path under the auth mount | Inputs and result |
| --- | --- | --- |
| POST | `/organization/create-team` | Send `name` and optional `organizationId`. Returns the new team. |
| POST | `/organization/update-team` | Send `teamId` and `data` containing the new `name` and optional `organizationId`. Returns the updated team. |
| GET | `/organization/list-teams` | Use an optional `organizationId` query parameter. Returns the organization's teams. |
| POST | `/organization/remove-team` | Send `teamId` and optional `organizationId`. Select another team or clear the active team before deleting it. |
| POST | `/organization/set-active-team` | Send a `teamId` belonging to the active organization, or `null` to clear the selection. Returns the selected team or `null`. |
| GET | `/organization/list-user-teams` | Use optional `userId` and `organizationId` query parameters. With neither, returns the caller's teams across organizations. |
| GET | `/organization/list-team-members` | Use an optional `teamId` query parameter, which defaults to the current session’s active team. |
| POST | `/organization/add-team-member` | Send `teamId`, `userId` and optional `organizationId`. The target must already belong to that organization. Repeated adds return the same membership. |
| POST | `/organization/remove-team-member` | Send the same fields as add. Removal clears that user's active selections for the team. |

To invite a new organization member into teams, include `teamId` in `/organization/invite-member`. Supply one ID or an array of IDs from that organization. Acceptance commits the organization membership and every team membership together. A single invited team becomes active on the accepting session. Removing a team updates outstanding invitations. An invitation whose final team is removed can still grant organization membership.

`MaximumTeams` limits the number of teams per organization. A positive value enables the limit. `MaximumMembersPerTeam` sets a fixed seat limit for added and invited members. `nil` leaves capacity unrestricted and zero admits no new members. To decide each team's seats at runtime, see [Set a member limit per team](#set-a-member-limit-per-team). Removing an organization's last team requires `AllowRemovingAllTeams: true`. See the [organization checklist](parity/plugins/organization.md) for team membership policies and lifecycle callbacks.

The native client includes `CreateTeam`, `UpdateTeam`, `RemoveTeam`, `ListOrganizationTeams`, `ListUserTeams`, `SetActiveTeam`, `ListTeamMembers`, `AddTeamMember` and `RemoveTeamMember`. Each client uses its own session when resolving an omitted organization or team. [Multi-engine team tests](../adapters/sqlstore/organization_teams_test.go)


### Set a team limit per organization

Set `TeamOptions.ResolveMaximumTeams` to look up the total number of teams an organization may have. For example, a billing policy can use the organization's plan. Return a positive count to set a cap or zero to allow unlimited teams. Choose the resolver or a fixed `MaximumTeams` value.

```go
groups, err := organization.NewService(organization.Options{
    Store: store,
    Teams: &organization.TeamOptions{
        ResolveMaximumTeams: func(ctx context.Context, in organization.TeamLimitInput) (int, error) {
            return plans.TeamLimit(ctx, in.OrganizationID)
        },
    },
})
```

`plans.TeamLimit` is an application function. Signed HTTP calls provide the destination organization ID, the current user's core profile and session in `in.Session`, and the incoming `in.Request`. `POST /organization/create-team` accepts `{"name":"Design","organizationId":"org_a"}`. An omitted or empty organization ID uses the current session's selection. A member needs `team.create` in the destination. In Go, use `authClient.CreateTeam(ctx, "Design", organizationID)`.

Trusted backend code can call `groups.CreateTeam(ctx, organization.CreateTeamRequest{OrganizationID: organizationID, Name: "Design"})`. The application authorizes this call. It requires an explicit destination and gives the resolver a nil session and request. Both entry points count the same teams, including the default team created with an organization. Creating that initial team skips the resolver.

Plain Auth calls the resolver outside the database transaction. Before saving, it checks the actor, destination and available capacity again. A full organization receives HTTP 400 with `YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS`. If the callback's session or profile inputs change while it runs, retry after HTTP 409 with `TEAM_POLICY_INPUT_CHANGED`. A revoked session or membership gets its authentication or permission error. Creating a team preserves the active selection. [HTTP and server API comparisons](../conformance/organization-team-limits.mjs) · [Concurrent creation on three SQL engines](../adapters/sqlstore/organization_team_creation_test.go)

### Set a member limit per team

Set `TeamOptions.ResolveMaximumMembersPerTeam` to decide how many members a team may hold each time someone would join it. For example, a billing policy can read the organization's plan. Return the team's capacity; zero admits no new members. Choose the resolver or a fixed `MaximumMembersPerTeam` value.

```go
groups, err := organization.NewService(organization.Options{
    Store: store,
    Teams: &organization.TeamOptions{
        ResolveMaximumMembersPerTeam: func(ctx context.Context, in organization.TeamMemberLimitInput) (int, error) {
            return plans.TeamSeats(ctx, in.OrganizationID, in.TeamID)
        },
    },
})
```

`plans.TeamSeats` is an application function. `in.TeamID` and `in.OrganizationID` name the destination, and `in.Session` holds the signed-in user making the change with their core profile:

| Entry point | `in.Session` | When the resolver runs |
| --- | --- | --- |
| `POST /organization/add-team-member` | The owner or admin adding the member | Once. Adding an existing team member returns the membership without asking. |
| `POST /organization/invite-member` with `teamId` | The inviter | Once per requested team. Renewing a pending invitation with `resend: true` keeps its teams without checking them again. |
| `POST /organization/accept-invitation` | The recipient | Once per invited team, before any `BeforeAcceptInvitation` hook. The organization and every team are joined together or not at all. |

Trusted `groups.AddMember` calls have no session. With a resolver configured, a request that includes a `TeamID` returns `organization.ErrUnauthenticated` and adds nothing. The same request without a team still grants organization membership.

Plain Auth calls the resolver outside the database transaction. Before saving, it rereads the caller's session and counts the team's members under the organization lock, so concurrent joins on any node cannot exceed the answer. A full team receives HTTP 403 with `TEAM_MEMBER_LIMIT_REACHED`. If the session or profile changes while the resolver runs, retry after HTTP 409 with `TEAM_POLICY_INPUT_CHANGED`. A resolver error or a negative count fails the request without writing. [HTTP, invitation and concurrency tests on three SQL engines](../adapters/sqlstore/organization_team_seats_test.go)

### Share a database between nodes

Invitation IDs are case-sensitive on all three SQL engines. Use the original ID when accepting an invitation. Nodes using the plain organization plugin can accept invitations that grant organization membership alone. Route invitations containing team IDs to a node configured with the team's membership policy. A plain node returns HTTP 409 with code `ORGANIZATION_TEAM_POLICY_REQUIRED` to the signed-in recipient. The invitation remains pending. The team-enabled node checks capacity in the acceptance transaction and grants organization and team membership together.

Every node clears the session's active team when the user switches to a different organization or clears the active organization. Selecting the same organization preserves its current team. These rules also apply when a plain node was already running when the database gained team tables. [Mixed-node HTTP and storage tests](../adapters/sqlstore/organization_topology_test.go)
