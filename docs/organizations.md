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
auth, err := authn.New(authn.Options{
    Store: store, BaseURL: origin, Secret: secret, EmailAndPassword: true,
    Plugins: []authn.Plugin{org},
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

An owner can invite members, admins or other owners. An admin can invite members or admins. The member role grants no invitation permission. The SQL store commits invitation acceptance and the resulting membership together. See the [organization feature checklist](parity/plugins/organization.md) for teams, custom roles and other capabilities.

Every organization mutation checks the active account and session inside the database transaction. Acceptance reads the current account email and verification status. Account deletion removes invitations that user sent, their organization and team memberships, and updates affected team counts. Other members keep their memberships and invitations.
