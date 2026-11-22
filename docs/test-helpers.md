# Test helpers

Import `github.com/Stonewrit/stonewrit-auth/authtest` from a Go test to build user and organization fixtures or read codes issued by your test server. The package runs in the test process and registers no HTTP routes.

## Build fixture data

`NewUser` creates a verified user with a unique ID, a generated address under `example.com`, and creation and update times. `NewOrganization` creates a unique ID and a slug based on the given name. Pass an empty name for “Test Organization”. Both functions return ordinary Go structs in memory. Set fields directly before passing the values to your test setup.

```go
user := authtest.NewUser()
user.Name = "Alice"
user.Email = "alice@example.test"
user.EmailVerified = false

team := authtest.NewOrganization("Support Team")
team.Slug = "support"
```

## Test email and phone codes

Create one recorder per test and wrap the sender when configuring the plugin. The wrapper captures the issued code under its delivery address and calls the sender you supply. Pass `nil` for a test that uses only the recorder. A sender error still reaches the caller. Captured proofs stay in the test process even if the database stores a hash.

```go
var inbox authtest.OTPRecorder
mail, err := emailotp.New(emailotp.Options{
    StoreOTP: "hashed",
    Send: inbox.Email(nil),
})
if err != nil {
    t.Fatal(err)
}
// Mount mail in the test server's auth.Options.Plugins, then sign up a test user.
if err := c.SendEmailOTP(t.Context(), "alice@example.test", emailotp.VerifyEmail); err != nil {
    t.Fatal(err)
}
code, ok := inbox.Get("alice@example.test")
if !ok {
    t.Fatal("verification email was not issued")
}
if _, err := c.VerifyEmailOTP(t.Context(), "alice@example.test", code); err != nil {
    t.Fatal(err)
}
```

Use `inbox.Phone(sendSMS)` for `phonenumber.Options.SendOTP` and `SendPasswordResetOTP` to capture SMS verification and password recovery codes. Look up the phone number used for delivery. When multiple messages go to the same address, `Get` returns the latest code. Call `Clear` to discard the recorder’s copies. Expiration, one-time redemption and retry limits continue to be enforced by the server. Keep the recorder in test configuration, since its contents can authorize a real session on the issuing instance. [Runnable integration test](../authtest/fixtures_test.go)
