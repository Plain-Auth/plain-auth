# Administrator accounts

The admin plugin manages users and sessions through the same HTTP mount as ordinary sign-in. Every administrative HTTP operation authenticates the calling session and checks the operator’s current database role. SQLite, PostgreSQL and MySQL support the `admin` schema profile.

When another process applies the `admin` profile, running SQL stores detect its ban and impersonation fields on subsequent session reads and account authorization checks. They also enforce those controls when their HTTP server exposes only ordinary sign-in. If a database exposes a ban or impersonation column before all five administrative columns are present, those operations return an error until the migration finishes.

```go
p, err := admin.New(admin.Options{})
if err != nil {
    return err
}
opts.Plugins = append(opts.Plugins, p)
```

Import `plugins/admin` from this module. New accounts default to the `user` role. The built-in `admin` role can read and update users, manage credentials, ban users, revoke sessions and impersonate ordinary users.

For applications with an existing password format, call `auth.BootstrapAdmin(ctx, name, email, password)` on your configured instance after applying the admin schema. It runs your password policy and hashing callbacks and enforces the bootstrap length range of 16–128 UTF-16 code units. [Host-managed passwords](authentication.md#use-an-existing-password-database)

## Create the first administrator

Supply the target database in `AUTH_DSN`. Apply the admin schema and provide the first password from your secret manager or a private file.

```sh
export AUTH_DSN='./accounts.db'
go run ./cmd/authctl migrate --dialect sqlite --plugins admin
go run ./cmd/authctl create-admin --dialect sqlite \
  --name 'Site Operator' --email 'operator@example.org' \
  --password-stdin < /run/secrets/initial-admin-password
```

Use `--dialect postgres` or `--dialect mysql` with the corresponding connection string for a network database. The command requires an existing admin schema, a new email address, and a password 16–128 UTF-16 code units long. It reads one line from a pipe or file and hashes the password using the regular credential hasher. There is no password argument, so the password never reaches the shell history or the process list. It prints:

```text
Admin user created successfully.
User ID: …
Email: operator@example.org
Role: admin
```

| Option | Effect |
| --- | --- |
| `--name NAME` | Display name; defaults to `Admin` |
| `--role ROLES` | Comma-separated roles; defaults to `admin` |
| `--no-email-verified` | Leaves the email unverified; it is verified by default |
| `--data JSON` | A JSON object with `image` (a string or null) and values for additional user fields declared with `--user-fields FILE`, the file `migrate` takes. Other keys are refused, and `name`, `email`, `role` and `emailVerified` are ignored because their own options decide them |
| `--force`, `-y`, `--yes` | Create the administrator even though the database already has users |
| `-c DIR`, `--cwd DIR` | Run in another directory |

The command refuses when an account already holds one of the requested roles, so concurrent attempts create at most one holder of each role, and `--role user` is refused once ordinary accounts exist. Grant further roles through the HTTP API, which requires an operator with `user:set-role`. The command runs outside your application, so no hooks, `ValidateUserInfo` or custom password hasher apply; call `auth.BootstrapAdmin` on your configured instance for those. It grants only the `admin` role with an unverified email and takes no roles, image or field values. Neither path checks the roles against your role map. Applications that provision accounts directly can call `plainauth.BootstrapAdminAccount` with a trusted store and the same options. [Command tests](../cmd/authctl/admin_test.go)

## Permissions

`AdminUserIDs` grants full administrative authority to explicit account IDs. `AdminRoles` identifies roles that receive the extra protection against impersonating administrators. `Roles` maps role names to resources and actions. For a custom role map, define every assigned role, including `DefaultRole` and the names in `AdminRoles`. A single assigned role must grant the entire permission request. Sign-up and administrator-created accounts without a role store `DefaultRole`. `AdminRoles` replaces the default `["admin"]`, so name every role to protect. Without `AdminRoles`, a custom role map must define `admin`. `DefaultRole` and every name in `AdminRoles` must match a role in the map exactly, including case. `admin.New` refuses a name that differs only in case, because such a protected role would protect no account.

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

`admin.DefaultRoles()` returns a fresh copy of the built-in `admin` and `user` roles. The admin role grants every built-in action except `user:impersonate-admins`, and the user role grants none. A non-nil `Roles` map replaces the built-in roles, so start from this copy to keep or extend them. `admin.DefaultRoleControl()` holds the built-in vocabulary: the user actions `create`, `list`, `set-role`, `ban`, `impersonate`, `impersonate-admins`, `delete`, `set-password`, `set-email`, `set-phone`, `get` and `update`, and the session actions `list`, `revoke` and `delete`. Its `NewRole` refuses a grant outside the vocabulary. The plugin accepts any resource, so your own handlers can check custom ones.

```go
roles := admin.DefaultRoles()
roles["admin"]["user"] = append(roles["admin"]["user"], "impersonate-admins")
roles["support"] = admin.Permissions{"user": {"get", "list"}, "session": {"list"}}
if _, err := admin.DefaultRoleControl().NewRole(access.Statements(roles["support"])); err != nil {
    return err
}
p, err := admin.New(admin.Options{Roles: roles})
```

[Default role tests](../plugins/admin/admin_test.go)

Creating a user with an explicit role requires both `user:create` and `user:set-role`. Updating an email or its verification status requires `user:set-email`. Ban-related fields require `user:ban`. Password changes use a dedicated endpoint. Profile updates accept the standard name, image, email, verification, role and ban fields, and declared additional user fields, hidden ones included. A `ServerOnly` field answers `FIELD_NOT_ALLOWED`, as at creation; set it with `Auth.UpdateTrustedUserFields`. An undeclared key or a value of the wrong type answers `VALIDATION_ERROR`, and the response carries the stored public fields. Another runtime writes any declared key without checking it; these are the create-path rules, kept for safety. Roles assigned through the API must exist in the configured role map. A role in `data` requires `user:set-role` before its value is checked. The refusals and grants for `password`, `id`, the role, the ban fields and the email fields are checked in that order before any value, so a request with several fields gets the same answer every time. To use role checks in your own handlers, see [Role permissions](access.md). From trusted server code without a session, `Auth.AdminUserHasPermission(ctx, userID, permissions)` reads the stored account's current role and honours `AdminUserIDs`; an unknown account answers 400 `USER_NOT_FOUND`. `POST /admin/has-permission` checks only the caller's own session and ignores `userId` and `role`, as another runtime does over HTTP, so never expose the server check as a handler.

## Create users with application profile fields

Include declared profile fields in the `data` object of `POST /admin/create-user`. Use their public names even when the SQL column has a different name. The operator needs `user:create`. An explicit role requires `user:set-role`, whether supplied at the top level or inside `data`. The top-level name, email and role take precedence. Ban changes and email verification retain their separate permission checks.

The Go HTTP client accepts the same input through `client.AdminCreateUser`. An operator can supply writable fields, including hidden ones. Fields marked `ServerOnly` follow the signup input rules, even for an administrator. The create, get and list responses include stored public fields and omit hidden fields and their physical column names. [Additional user fields](user-fields.md)

Trusted application code can provision an account without a session through the native auth instance. Apply your application's authorization policy before calling this method. It accepts server-owned values and validates the role against the configured roles.

```go
user, err := auth.AdminCreateUser(ctx, plainauth.AdminCreateUserRequest{
    Name:  "Jo",
    Email: "jo@example.org",
    Data: map[string]any{
        "locale":       "fr",
        "accountClass": "staff",
        "supportNote":  "Account reviewed",
    },
})
```

The profile, optional password credential and field readback share a transaction. An invalid field or failed readback rolls back the creation. For operations on behalf of a signed-in caller, pass their headers to `auth.Admin`. To change server-owned fields on an existing account, use `auth.UpdateTrustedUserFields`. [Three-database tests](../adapters/sqlstore/admin_user_fields_test.go)

## HTTP operations

| Operation under the auth mount | Request and response |
| --- | --- |
| `POST /admin/create-user` | Send `name`, `email` and optionally `password`, `role` or `data`. Returns `{user}`. Omitting the password creates a profile without a credential account. The address is stored in lower case. A top-level `role` must be a string or a list of strings, checked with the other body fields (400 `VALIDATION_ERROR`). A role in `data` requires `user:set-role` before its value is checked, and an undefined role answers 400 `YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE`. An invalid address answers 400 `INVALID_EMAIL` after the role and ban permission checks. |
| `GET /admin/get-user?id=…` | Returns the user. |
| `GET /admin/list-users` | Returns `{users,total}` and echoes explicit nonzero `limit` and `offset`. The default page contains up to 100 users. |
| `POST /admin/update-user` | Send `{userId,data}`. Returns the updated user. Empty `data` answers 400 `NO_DATA_TO_UPDATE`. Setting `banned` to true revokes the account's sessions. Other top-level fields, including `role`, are ignored. Declared user fields in `data` are written. |
| `POST /admin/set-role` | Send `userId` and one role or an array of roles. Returns `{user}`. |
| `POST /admin/set-user-password` | Send `{userId,newPassword}`. Updates or creates the credential account and returns `{status:true}`. The new password must meet the configured length bounds, which are checked before the account is looked up. |
| `POST /admin/ban-user` | Send `userId`, optional `banReason`, and optional `banExpiresIn` in seconds. Returns `{user}`. |
| `POST /admin/unban-user` | Send `{userId}` to clear the ban, reason and expiration. Returns `{user}`. |
| `POST /admin/list-user-sessions` | Send `{userId}`. Returns the unexpired `{sessions}`; expired rows, which another runtime also lists, cannot sign in and are left out. The `token` field on each entry is an operator-bound revocation handle. |
| `POST /admin/revoke-user-session` | Send the listed handle in `{sessionToken}` from the same operator account. Requires the `session:revoke` permission and returns `{success:true}`. |
| `POST /admin/revoke-user-sessions` | Send `{userId}`. Returns `{success:true}`. |
| `POST /admin/impersonate-user` | Send `{userId}`. Returns `{session,user}` and sets a temporary browser session. |
| `POST /admin/stop-impersonating` | Send `{}` from that browser. Returns the original session and user. From a direct session it answers 400 with the message `You are not impersonating anyone` and no code. Without a session it answers 401. |
| `POST /admin/remove-user` | Send `{userId}`. Deletes the account and its sessions, without a prior revocation, and returns `{success:true}`. |
| `POST /admin/has-permission` | Send a `permissions` object such as `{"permissions":{"user":["get"]}}`. Returns `{success,error:null}` for the authenticated caller. A body without a `permissions` object answers 400 `VALIDATION_ERROR` before the session is checked; one that sends the singular `permission` instead answers 400 with the message `invalid permission check. no permission(s) were passed.` and no code. Without a session it answers 401. |

User listing supports `searchValue`, `searchField`, `searchOperator`, `filterField`, `filterOperator`, `filterValue`, `sortBy` and `sortDirection`. Operators include `eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `contains`, `starts_with`, `ends_with`, `in` and `not_in`. Repeat the `filterValue` query parameter for an array. Search defaults to email substring matching. The Go client accepts a `plainauth.AdminQuery` for the same operations. The pattern operators `contains`, `starts_with` and `ends_with` match `%` and `_` in the value literally, where another runtime passes them on as wildcards, so a search for an address such as `first_last@` never also returns `firstXlast@` accounts that an operator might then ban or remove. [Listing and session tests](../adapters/sqlstore/admin_listing_test.go)

An operator without the operation's grant receives 403 with its `YOU_ARE_NOT_ALLOWED_TO_…` code, and an operation that names an account that does not exist receives 404 `USER_NOT_FOUND`. A missing account answers before its role or profile data are checked; `set-user-password` checks the password length first. [Refusal and default tests](../adapters/sqlstore/admin_policy_test.go)

## Bans and impersonation

Banning an account revokes its sessions. Revoking a user's sessions, banning them or removing them also ends the sessions they opened by impersonating someone else, which no longer have a live source; another runtime deletes only the user's own sessions. An administrative password reset, ban or account-wide session revocation also clears pending second-factor challenges and remembered-browser grants. Session creation checks the current ban inside the database transaction, including sign-ins through other enabled authentication methods. An email sign-in by a banned account is refused with `BANNED_USER` before the email-verification check, so a banned account is never sent a verification mail. A permanent ban clears any previous expiry. A successful login after a temporary ban expires clears the ban fields. Set `DefaultBanReason`, `DefaultBanDuration` and `BannedUserMessage` to customize the policy. `BannedUserMessageFunc` builds the message from the banned account instead, with its role, ban fields and public additional fields, for example to quote `BanReason`. It runs after the store call that refused the session has returned, never inside a store transaction. Its result is what endpoint after hooks, `OnAPIError` and the HTTP error response see, and the `error_description` of a magic-link error redirect. An empty result or a panic keeps `BannedUserMessage`, as native Go calls do. The store must implement `plainauth.AdminUserReader`, as the SQL store does. [Banned message tests](../adapters/sqlstore/admin_banned_message_test.go) A ban without `banReason` stores `DefaultBanReason`, which defaults to `No reason`. A ban without `banExpiresIn` expires after `DefaultBanDuration`; zero keeps it until an administrator lifts it. An administrator cannot ban or delete their own account.

Impersonation issues a separate browser-only session with its operator recorded in `impersonatedBy`. It expires after one hour by default. Set `ImpersonationSessionDuration` to change the lifetime. The ordinary session list hides delegated sessions. The administrative session list includes their metadata. Its opaque handles contain only record identifiers and an expiry. A handle authorizes a single-session revocation when the issuing operator holds the revocation grant. Delegated sessions created by the service depend on their original login and cannot authorize administrative operations. The initiating browser can return to that exact login, preserving its original persistence setting. Impersonating an administrator requires an explicit grant of `user:impersonate-admins`, an allowlisted administrator ID, or `AllowImpersonatingAdmins`.

During impersonation, enrolling or changing factors, linking identities, changing login credentials, approving a device, accessing billing, managing organization membership, and retrieving sessions, provider tokens or service JWTs require a direct login by the account owner. Ordinary session reads remain available during impersonation and omit the service JWT header. Custom endpoints that issue credentials or change account permissions can call `session.RequireOwner()`. [Combined plugin tests](../adapters/sqlstore/admin_factor_test.go)

The native Go client provides corresponding `Admin…` methods. For in-process calls, pass the caller’s headers to `Auth.Admin` with a `plainauth.AdminRequest`. HTTP endpoints handle the browser cookies used to start and stop impersonation. [Database and HTTP tests](../adapters/sqlstore/admin_test.go)

Administrators can assign a phone number or change its verification status when both plugins are enabled. Managing these fields requires the `user:set-phone` permission in addition to the operation’s base grant. [Administrative phone changes](phone-number.md#administrative-phone-changes)
