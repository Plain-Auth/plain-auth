# Breached-password checks

Register the password-checking plugin to reject newly chosen credentials that appear in the Have I Been Pwned password corpus. The plugin checks email registration, password changes and password resets. Signing in with an existing credential uses local verification.

```go
import (
    "github.com/FineStack/finestack-auth"
    "github.com/FineStack/finestack-auth/plugins/pwnedpassword"
)

policy := pwnedpassword.New(pwnedpassword.Options{
    CustomPasswordCompromisedMessage: "Choose a password you have not used before.",
})
auth, err := fineauth.New(fineauth.Options{
    Store: store, BaseURL: origin, Secret: secret, EmailAndPassword: true,
    Plugins: []fineauth.Plugin{policy},
})
```

The check hashes the proposed password locally, then requests a padded range using the first five hexadecimal characters of the SHA-1 digest. The server compares the remaining characters locally and ignores padding entries with a count of zero. The auth store derives its own salted credential hash for storage. [Pwned Passwords range API](https://haveibeenpwned.com/API/v3#PwnedPasswords)

A match returns HTTP 400 with `PASSWORD_COMPROMISED`. When the service fails or returns an invalid count for the matching suffix, credential changes fail with HTTP 500. A failed reset leaves its proof available for a retry.

## Select the operations

`Enabled` defaults to true. Set it to a pointer to false to disable network checks. A nil `Paths` uses the default policy. A non-nil list replaces those paths and an empty list disables every path. To include the server-only initial password operation alongside the three implemented credential flows, select all four explicitly.

```go
policy := pwnedpassword.New(pwnedpassword.Options{
    Paths: []string{"/sign-up/email", "/change-password", "/reset-password", "/set-password"},
})
```

Programmatic and HTTP operations invoke the same policy. The selection also reserves default paths for future email OTP, phone OTP and admin credential operations. Their status appears in the [feature checklist](parity/plugins/have-i-been-pwned.md).

## Check a custom operation

A custom server handler can call `auth.ValidateNewPassword(ctx, path, password)` to run registered policies for its configured path. To query the range service directly, use the standalone helper.

```go
compromised, err := pwnedpassword.IsPasswordCompromised(ctx, proposedPassword, nil)
```

Pass a custom `http.RoundTripper` to the helper, or set the plugin's `Transport`, to use a local fixture in tests. The default client uses HTTPS, requests response padding and allows five seconds for a lookup.
