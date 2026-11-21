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
auth, err := frostauth.New(frostauth.Options{
    Store: store, BaseURL: origin, Secret: secret, EmailAndPassword: true,
    Plugins: []frostauth.Plugin{org},
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

An owner can invite members, admins or other owners. An admin can invite members or admins. The member role grants no invitation permission. The SQL store commits invitation acceptance and the resulting membership together. The [organization feature checklist](parity/plugins/organization.md) tracks additional role policies and operations.

Every organization mutation checks the active account and session inside the database transaction. Acceptance reads the current account email and verification status. Account deletion removes invitations that user sent, their organization and team memberships, and updates affected team counts. Other members keep their memberships and invitations.

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
