# Breached-password checks

Register the password-checking plugin to reject newly chosen credentials that appear in the Have I Been Pwned password corpus. It also screens passwords that an administrator chooses for someone else. Signing in with an existing credential uses local verification.

```go
import (
    "github.com/Plain-Org/plain-auth"
    "github.com/Plain-Org/plain-auth/plugins/pwnedpassword"
)

policy := pwnedpassword.New(pwnedpassword.Options{
    CustomPasswordCompromisedMessage: "Choose a password you have not used before.",
})
auth, err := plainauth.New(plainauth.Options{
    Store: store, BaseURL: origin, Secret: secret, EmailAndPassword: true,
    Plugins: []plainauth.Plugin{policy},
})
```

The check hashes the proposed password locally, then requests a padded range using the first five hexadecimal characters of the SHA-1 digest. The server compares the remaining characters locally and ignores padding entries with a count of zero. The auth store derives its own salted credential hash for storage. [Pwned Passwords range API](https://haveibeenpwned.com/API/v3#PwnedPasswords)

A match returns HTTP 400 with `PASSWORD_COMPROMISED`. When the service fails or returns an invalid count for the matching suffix, the write fails with HTTP 500. If a proposed password fails screening during recovery, the existing password and sessions remain valid. The owner can retry with a different password and the same unexpired reset link or code.

## Select the operations

`Enabled` defaults to true. Set it to a pointer to false to disable network checks. A nil `Paths` screens these operations when their corresponding feature is enabled.

| Operation | Paths under the auth mount |
| --- | --- |
| Email registration and signed-in password changes | `/sign-up/email`, `/change-password` |
| Recovery using an email link or code | `/reset-password`, `/email-otp/reset-password` |
| Recovery using an SMS code | `/phone-number/reset-password` |
| Administrator creates a user with a password or sets a user's password | `/admin/create-user`, `/admin/set-user-password` |

A non-nil `Paths` list replaces the defaults. An empty list disables screening on all paths. To include the server-only initial password operation as well, select all eight paths explicitly.

```go
policy := pwnedpassword.New(pwnedpassword.Options{
    Paths: []string{
        "/sign-up/email", "/change-password", "/reset-password",
        "/email-otp/reset-password", "/phone-number/reset-password",
        "/admin/create-user", "/admin/set-user-password", "/set-password",
    },
})
```

Programmatic and HTTP operations invoke the same policy. The checklist links to tests covering all seven default paths. [Password screening tests](parity/plugins/have-i-been-pwned.md#credential-setting-paths)

## Check a custom operation

A custom server handler can call `auth.ValidateNewPassword(ctx, path, password)` to run registered policies for its configured path. To query the range service directly, use the standalone helper.

```go
compromised, err := pwnedpassword.IsPasswordCompromised(ctx, proposedPassword, nil)
```

Pass a custom `http.RoundTripper` to the helper, or set the plugin's `Transport`, to use a local fixture in tests. The default client uses HTTPS, requests response padding and allows five seconds for a lookup.
