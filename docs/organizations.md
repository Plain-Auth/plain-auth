# Organizations

Enable the organization schema in the same store used by the auth handler. The plugin creates organizations with an owner membership, lists the organizations a user belongs to, and stores the active organization on each individual session.

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
    SendInvitation: func(ctx context.Context, invite organization.Invitation) error {
        return sendInvitation(ctx, invite.Email, invite.ID)
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

The application provides `sendInvitation`, its configured public `origin` and its `secret`. A failed delivery leaves the pending invitation available for another attempt using `resend: true`. Invitation IDs are opaque and expire after 48 hours. The signed-in recipient must match the invitation email. Set `RequireVerifiedEmail` to also require a verified account.

| Method | Path under the auth mount | Behavior |
| --- | --- | --- |
| POST | `/organization/create` | Create an organization with `name` and `slug` and select it on the creator's session |
| GET | `/organization/list` | List the current user's organizations |
| GET | `/organization/list-members` | List public member profiles and a filtered total for an organization you belong to. |
| GET | `/organization/get-organization` | Read the organization profile by ID, slug or active selection |
| GET | `/organization/get-full-organization` | Read the profile together with members, visible invitations and configured teams |
| GET | `/organization/get-active-member` | Read your membership, role and public profile in this session's active organization. Requires a signed-in session. |
| GET | `/organization/get-active-member-role` | Read a user's role in an organization you both belong to. Omit all query parameters for your own role in the active organization. |
| POST | `/organization/set-active` | Select by ID or slug. Send `{"organizationId":null}` to clear the current selection |
| GET | `/organization/get-invitation` | Read one pending, unexpired invitation addressed to the signed-in account |
| GET | `/organization/list-user-invitations` | Read pending invitations for the signed-in account’s verified email across organizations |
| GET | `/organization/list-invitations` | List invitations visible to an owner or admin in the named or active organization |
| POST | `/organization/invite-member` | Invite by email and role, using an explicit organization ID or the active selection |
| POST | `/organization/accept-invitation` | Accept by invitation ID, create the membership, and select the organization |
| POST | `/organization/remove-member` | Remove by membership ID or email. Omit `organizationId` to use the active organization. |
| POST | `/organization/check-slug` | Check whether a slug is available to register. Requires a signed-in user. |
| POST | `/organization/update` | Update an organization's name, slug, logo or metadata as an owner or admin. |
| POST | `/organization/update-member-role` | Replace roles by membership ID in the supplied or active organization. |
| POST | `/organization/leave` | End the signed-in user's own membership in the supplied `organizationId`. |

An owner can invite members, admins or other owners. An admin can invite members or admins. The member role grants no invitation permission. The SQL store commits invitation acceptance and the resulting membership together. The [organization feature checklist](parity/plugins/organization.md) tracks additional role policies and operations.

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

Read `GET /get-session` under the auth mount for the active organization and team. A second login for the same user has its own selection. Creating an organization selects it by default. Pass `keepCurrentActiveOrganization: true` to retain the current selection when creating another organization. [Plain HTTP session-isolation tests](../adapters/sqlstore/organization_selection_http_test.go)

Applications acting as an OAuth issuer can also configure a host-owned page for organization or team selection during authorization. A signed OAuth request can then return a protocol redirect or a JSON destination. [Post-login authorization](oauth-authorization-code.md#select-an-organization-or-team-after-login)

If you generate a client from OpenAPI, the ordinary response is a nullable `Organization` or `Team`. A host that enables signed post-login selection also exposes the optional `oauth_query` input, a JSON result with `redirect` and `url`, and an HTTP 302 response for navigation. [OpenAPI reference](openapi.md) · [Configured schema tests](../plugins/openapi/organization_selection_test.go)

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

A Go server can call `organizations.UpdateMemberRole(ctx, session.Session, change)` with a signed-in session returned by `auth.GetSession`. Both entry points recheck the session and current membership before committing. The built-in policy covers `owner`, `admin` and `member`. Custom role definitions and role-change hooks remain open on the [organization checklist](parity/plugins/organization.md). [Released client comparison](../conformance/organization-role.mjs) · [Database concurrency tests](../adapters/sqlstore/organization_role_test.go)

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

Supply the exact organization and user IDs. Built-in roles are `owner`, `admin`, and `member`. A duplicate grant returns `USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION`. To add the user to a team in the same transaction, enable `Teams` on the service and set `TeamID` to a team in that organization. A full team rolls back the entire grant. Granting membership preserves the user's current browser selection. [Three-database membership tests](../adapters/sqlstore/organization_members_test.go)

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

`MaximumTeams` limits the number of teams per organization. A positive value enables the limit. `MaximumMembersPerTeam` sets a fixed seat limit for added and invited members, and `nil` leaves capacity unrestricted. Removing an organization's last team requires `AllowRemovingAllTeams: true`. Custom role permissions, dynamic team quotas and team lifecycle callbacks are tracked separately in the [organization checklist](parity/plugins/organization.md).

The native client includes `CreateTeam`, `UpdateTeam`, `RemoveTeam`, `ListOrganizationTeams`, `ListUserTeams`, `SetActiveTeam`, `ListTeamMembers`, `AddTeamMember` and `RemoveTeamMember`. Each client uses its own session when resolving an omitted organization or team. [Multi-engine team tests](../adapters/sqlstore/organization_teams_test.go)

### Share a database between nodes

Invitation IDs are case-sensitive on all three SQL engines. Use the original ID when accepting an invitation. Nodes using the plain organization plugin can accept invitations that grant organization membership alone. Route invitations containing team IDs to a node configured with the team's membership policy. A plain node returns HTTP 409 with code `ORGANIZATION_TEAM_POLICY_REQUIRED` to the signed-in recipient. The invitation remains pending. The team-enabled node checks capacity in the acceptance transaction and grants organization and team membership together.

Every node clears the session's active team when the user switches to a different organization or clears the active organization. Selecting the same organization preserves its current team. These rules also apply when a plain node was already running when the database gained team tables. [Mixed-node HTTP and storage tests](../adapters/sqlstore/organization_topology_test.go)
