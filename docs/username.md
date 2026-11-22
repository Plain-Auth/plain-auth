# Username sign-in

Users can add a public username to an email and password account and sign in with either identifier. The username is unique. The optional display username preserves the spelling shown to other people.

Enable email and password authentication and register the plugin. SQLite, PostgreSQL, MySQL and the in-memory store support usernames.

```go
import (
    "github.com/Plain-Auth/plain-auth"
    "github.com/Plain-Auth/plain-auth/plugins/username"
)

p, err := username.New(username.Options{})
if err != nil {
    return err
}
opts.EmailAndPassword = true
opts.Plugins = append(opts.Plugins, p)
service, err := plainauth.New(opts)
```

For SQL storage, apply the `username` schema profile. The fields are nullable so existing accounts can choose a name later. SQLite adds a unique index when upgrading a populated user table. A fresh installation declares the same uniqueness directly on the column.

```sh
AUTH_DSN=./accounts.db go run ./cmd/authctl migrate --dialect sqlite --plugins username
```

## Register, sign in and edit

| Operation under the auth mount | Input and behavior |
| --- | --- |
| `POST /sign-up/email` | Add optional `username` and `displayUsername` to a normal credential registration. A supplied username supplies the default display spelling. When only a display name is supplied, a valid login name is also registered from it. |
| `POST /sign-in/username` | Supply `username`, `password` and optionally `rememberMe` and `callbackURL`. Email verification, administrator bans and enrolled second factors apply to this login. A successful login sets the regular session cookie. |
| `POST /update-user` | The authenticated account owner can submit either name alongside ordinary profile changes. Omitted fields keep their stored values. Send `null` to clear either name. Clearing a mutable login name makes it available for registration. |
| `POST /is-username-available` | Supply `username` to receive `{"available":true}` or `{"available":false}`. A database constraint settles simultaneous attempts to claim the same name. |

In Go, use `ProfileUpdate.ClearUsername` and `ClearDisplayUsername` to clear fields. A clear flag takes precedence over a supplied value for the same field. Owners retain their assigned login name under `Immutable`. Administrators with the user update grant can change or clear either field.

The Go client exposes `SignUpEmail`, `SignInUsername`, `UpdateUser` and `IsUsernameAvailable`. In process, use `Auth.SignInUsername` or `Auth.IsUsernameAvailable`. Administrators can supply `username` and `displayUsername` in the `data` field of authenticated user creation and profile updates. [Public API and storage tests](../adapters/sqlstore/username_test.go)

## Configure names

By default login names contain 3–30 UTF-16 code units and accept ASCII letters, digits, underscores and dots. The service stores lowercase login names. Display spellings have no default character restriction.

| Option | Behavior |
| --- | --- |
| `MinLength`, `MaxLength` | Change the length bounds for login names. |
| `Validate`, `ValidateDisplay` | Set application validators with signature `func(context.Context, string) bool`. The login validator replaces the default character rule. |
| `Normalize`, `NormalizeDisplay` | Use idempotent transformations with signature `func(string) string`. Display text defaults to its submitted form. |
| `ValidateAfterNormalization`, `ValidateDisplayAfterNormalization` | Choose whether the corresponding validator sees the transformed value. The default checks the submitted value. |
| `DisableNormalization` | Preserve the submitted login spelling. For this option, comparison and uniqueness also depend on the database’s collation. |
| `Immutable` | An owner can choose a name once and later update its display spelling. Concurrent first assignments have one winner. |
| `DisableDisplay` | Use the `username-only` schema profile. Responses omit `displayUsername`. |
| `DisableAvailability` | Remove the public availability endpoint. The in-process lookup remains available to the application. |

When enabled, an account without a registered name returns `"username":null`. The display-enabled configuration also returns `"displayUsername":null`. The two username schema profiles are mutually exclusive. [Schema profiles](schema.md)
