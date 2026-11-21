# Administrator accounts

The admin plugin manages users and sessions through the same HTTP mount as ordinary sign-in. Every administrative operation authenticates the calling session and checks the operator’s current database role. SQLite, PostgreSQL and MySQL support the `admin` schema profile.

When another process applies the `admin` profile, running SQL stores detect its ban and impersonation fields on subsequent session reads and account authorization checks. They also enforce those controls when their HTTP server exposes only ordinary sign-in. If a database exposes a ban or impersonation column before all five administrative columns are present, those operations return an error until the migration finishes.

```go
p, err := admin.New(admin.Options{})
if err != nil {
    return err
}
opts.Plugins = append(opts.Plugins, p)
```

Import `plugins/admin` from this module. New accounts default to the `user` role. The built-in `admin` role can read and update users, manage credentials, ban users, revoke sessions and impersonate ordinary users.

## Create the first administrator

Supply the target database in `AUTH_DSN`. Apply the admin schema and provide the first password from your secret manager or a private file.

```sh
export AUTH_DSN='./accounts.db'
go run ./cmd/authctl migrate --dialect sqlite --plugins admin
go run ./cmd/authctl create-admin --dialect sqlite \
  --name 'Site Operator' --email 'operator@example.org' \
  --password-stdin < /run/secrets/initial-admin-password
```

Use `--dialect postgres` or `--dialect mysql` with the corresponding connection string for a network database. The command requires an existing admin schema, a new email address, and a password 16–128 UTF-16 code units long. It reads one line from a pipe or file, hashes the password using the regular credential hasher, and prints the new administrator’s email. Concurrent attempts can create one administrator. Once someone holds the `admin` role, subsequent grants go through an authenticated administrator. Applications that provision accounts directly can call `stonewrit.BootstrapAdmin` with a trusted store.

## Permissions

`AdminUserIDs` grants full administrative authority to explicit account IDs. `AdminRoles` identifies roles that receive the extra protection against impersonating administrators. `Roles` maps role names to resources and actions. For a custom role map, define every assigned role, including `DefaultRole` and the names in `AdminRoles`. A single assigned role must grant the entire permission request.

```go
p, err := admin.New(admin.Options{
    DefaultRole: "user",
    AdminRoles:  []string{"operator"},
    Roles: map[string]admin.Permissions{
        "user": {},
        "operator": {
            "user":    {"get", "list", "ban"},
            "session": {"list", "revoke"},
        },
    },
})
```

Creating a user with an explicit role requires both `user:create` and `user:set-role`. Updating an email or its verification status requires `user:set-email`. Ban-related fields require `user:ban`. Password changes use a dedicated endpoint. Profile updates accept the standard name, image, email, verification, role and ban fields. Roles assigned through the API must exist in the configured role map. To use role checks in your own handlers, see [Role permissions](access.md).

## HTTP operations

| Operation under the auth mount | Request and response |
| --- | --- |
| `POST /admin/create-user` | Send `name`, `email` and optionally `password`, `role` or `data`. Returns `{user}`. Omitting the password creates a profile without a credential account. |
| `GET /admin/get-user?id=…` | Returns the user. |
| `GET /admin/list-users` | Returns `{users,total}` and echoes explicit nonzero `limit` and `offset`. The default page contains up to 100 users. |
| `POST /admin/update-user` | Send `{userId,data}`. Returns the updated user. |
| `POST /admin/set-role` | Send `userId` and one role or an array of roles. Returns `{user}`. |
| `POST /admin/set-user-password` | Send `{userId,newPassword}`. Updates or creates the credential account and returns `{status:true}`. |
| `POST /admin/ban-user` | Send `userId`, optional `banReason`, and optional `banExpiresIn` in seconds. Returns `{user}`. |
| `POST /admin/unban-user` | Send `{userId}` to clear the ban, reason and expiration. Returns `{user}`. |
| `POST /admin/list-user-sessions` | Send `{userId}`. Returns `{sessions}`. The `token` field on each entry is an operator-bound revocation handle. |
| `POST /admin/revoke-user-session` | Send the listed handle in `{sessionToken}` from the same operator account. Requires the `session:revoke` permission and returns `{success:true}`. |
| `POST /admin/revoke-user-sessions` | Send `{userId}`. Returns `{success:true}`. |
| `POST /admin/impersonate-user` | Send `{userId}`. Returns `{session,user}` and sets a temporary browser session. |
| `POST /admin/stop-impersonating` | Send `{}` from that browser. Returns the original session and user. |
| `POST /admin/remove-user` | Send `{userId}`. Deletes the account and returns `{success:true}`. |
| `POST /admin/has-permission` | Send a `permissions` object such as `{"permissions":{"user":["get"]}}`. Returns `{success,error:null}` for the authenticated caller. |

User listing supports `searchValue`, `searchField`, `searchOperator`, `filterField`, `filterOperator`, `filterValue`, `sortBy` and `sortDirection`. Operators include `eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `contains`, `starts_with`, `ends_with`, `in` and `not_in`. Repeat the `filterValue` query parameter for an array. Search defaults to email substring matching. The Go client accepts a `stonewrit.AdminQuery` for the same operations.

## Bans and impersonation

Banning an account revokes its sessions. An administrative password reset, ban or account-wide session revocation also clears pending second-factor challenges and remembered-browser grants. Session creation checks the current ban inside the database transaction, including sign-ins through other enabled authentication methods. A permanent ban clears any previous expiry. A successful login after a temporary ban expires clears the ban fields. Set `DefaultBanReason`, `DefaultBanDuration` and `BannedUserMessage` to customize the policy. An administrator cannot ban or delete their own account.

Impersonation issues a separate browser-only session with its operator recorded in `impersonatedBy`. It expires after one hour by default. Set `ImpersonationSessionDuration` to change the lifetime. The ordinary session list hides delegated sessions. The administrative session list includes their metadata. Its opaque handles contain only record identifiers and an expiry. A handle authorizes a single-session revocation when the issuing operator holds the revocation grant. Delegated sessions created by the service depend on their original login and cannot authorize administrative operations. The initiating browser can return to that exact login, preserving its original persistence setting. Impersonating an administrator requires an explicit grant of `user:impersonate-admins`, an allowlisted administrator ID, or `AllowImpersonatingAdmins`.

During impersonation, enrolling or changing factors, linking identities, changing login credentials, approving a device, accessing billing, managing organization membership, and retrieving sessions, provider tokens or service JWTs require a direct login by the account owner. Ordinary session reads remain available during impersonation and omit the service JWT header. Custom endpoints that issue credentials or change account permissions can call `session.RequireOwner()`. [Combined plugin tests](../adapters/sqlstore/admin_factor_test.go)

The native Go client provides corresponding `Admin…` methods. For in-process calls, pass the caller’s headers to `Auth.Admin` with a `stonewrit.AdminRequest`. HTTP endpoints handle the browser cookies used to start and stop impersonation. [Database and HTTP tests](../adapters/sqlstore/admin_test.go)

Administrators can assign a phone number or change its verification status when both plugins are enabled. Managing these fields requires the `user:set-phone` permission in addition to the operation’s base grant. [Administrative phone changes](phone-number.md#administrative-phone-changes)
