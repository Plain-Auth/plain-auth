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
auth, err := stonewrit.New(stonewrit.Options{
    Store: store, BaseURL: origin, Secret: secret, EmailAndPassword: true,
    Plugins: []stonewrit.Plugin{org},
})
```

The application provides `sendInvitation`, its configured public `origin` and its `secret`. A failed delivery leaves the pending invitation available for another attempt using `resend: true`. Invitation IDs are opaque and expire after 48 hours. The signed-in recipient must match the invitation email. Set `RequireVerifiedEmail` to also require a verified account.

| Method | Path under the auth mount | Behavior |
| --- | --- | --- |
| POST | `/organization/create` | Create an organization with `name` and `slug` and select it on the creator's session |
| GET | `/organization/list` | List the current user's organizations |
| GET | `/organization/get-organization` | Read by `organizationId`, `organizationSlug` or active selection |
| POST | `/organization/set-active` | Select by ID or slug. Send `{"organizationId":null}` to clear the current selection |
| POST | `/organization/invite-member` | Invite by email and role, using an explicit organization ID or the active selection |
| POST | `/organization/accept-invitation` | Accept by invitation ID, create the membership, and select the organization |
| POST | `/organization/remove-member` | Remove by membership ID or email. Omit `organizationId` to use the active organization. |
| POST | `/organization/update-member-role` | Replace roles by membership ID in the supplied or active organization. |
| POST | `/organization/leave` | End the signed-in user's own membership in the supplied `organizationId`. |

An owner can invite members, admins or other owners. An admin can invite members or admins. The member role grants no invitation permission. The SQL store commits invitation acceptance and the resulting membership together. The [organization feature checklist](parity/plugins/organization.md) tracks additional role policies and operations.

Browser membership changes check the acting account and session inside the database transaction. Acceptance reads the current account email and verification status. Account deletion removes invitations that user sent, their organization and team memberships, and updates affected team counts. Other members keep their memberships and invitations.

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

## Grant membership from your application

Create an organization service if your application grants access to existing accounts, for example after a provisioning job approves a new employee. Mount its plugin and keep the service for trusted Go calls.

```go
organizations, err := organization.NewService(organization.Options{Store: store})
if err != nil {
    return err
}
// Include organizations.Plugin() in stonewrit.Options.Plugins at startup.
// After your application has authorized this specific grant:
member, err := organizations.AddMember(ctx, organization.AddMemberRequest{
    OrganizationID: organizationID,
    UserID:         employeeID,
    Roles:          []string{"member"},
})
```

Supply the exact organization and user IDs. Built-in roles are `owner`, `admin`, and `member`. A duplicate grant returns `USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION`. To add the user to a team in the same transaction, enable `Teams` on the service and set `TeamID` to a team in that organization. A full team rolls back the entire grant. Direct grants and invitation acceptance share the default 100-member limit. Granting membership preserves the user's current browser selection. [Three-database membership tests](../adapters/sqlstore/organization_members_test.go)

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

`MaximumTeams` limits the number of teams per organization. A positive value enables the limit. `MaximumMembersPerTeam` sets a fixed seat limit for added and invited members, and `nil` leaves capacity unrestricted. Removing an organization's last team requires `AllowRemovingAllTeams: true`. Custom role permissions, dynamic quota functions and team lifecycle callbacks are tracked separately in the [organization checklist](parity/plugins/organization.md).

The native client includes `CreateTeam`, `UpdateTeam`, `RemoveTeam`, `ListOrganizationTeams`, `ListUserTeams`, `SetActiveTeam`, `ListTeamMembers`, `AddTeamMember` and `RemoveTeamMember`. Each client uses its own session when resolving an omitted organization or team. [Multi-engine team tests](../adapters/sqlstore/organization_teams_test.go)

### Share a database between nodes

Invitation IDs are case-sensitive on all three SQL engines. Use the original ID when accepting an invitation. Nodes using the plain organization plugin can accept invitations that grant organization membership alone. Route invitations containing team IDs to a node configured with the team's membership policy. A plain node returns HTTP 409 with code `ORGANIZATION_TEAM_POLICY_REQUIRED` to the signed-in recipient. The invitation remains pending. The team-enabled node checks capacity in the acceptance transaction and grants organization and team membership together.

Every node clears the session's active team when the user switches to a different organization or clears the active organization. Selecting the same organization preserves its current team. These rules also apply when a plain node was already running when the database gained team tables. [Mixed-node HTTP and storage tests](../adapters/sqlstore/organization_topology_test.go)
