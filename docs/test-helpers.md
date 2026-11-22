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

## Test a protected handler

Construct a test server with the same public options as your application and a dedicated database. Mount `server.Auth` on your normal router. The example below uses the in-memory adapter. SQLite, PostgreSQL and MySQL support the same setup and teardown operations.

```go
server, err := authtest.New(auth.Options{
    BaseURL: "https://app.example.test",
    Secret: strings.Repeat("x", 40),
    Store: memory.New(),
})
if err != nil {
    t.Fatal(err)
}
user, err := server.SaveUser(t.Context(), authtest.NewUser())
if err != nil {
    t.Fatal(err)
}
login, err := server.Login(t.Context(), user.ID)
if err != nil {
    t.Fatal(err)
}
req := httptest.NewRequest(http.MethodGet, "https://app.example.test/profile", nil)
req.Header = login.Headers.Clone()
res := httptest.NewRecorder()
router.ServeHTTP(res, req) // router mounts server.Auth and your protected /profile handler
```

`SaveUser` writes the user's profile without adding a password, linked provider, or session. `Login` creates a session for that user and returns the user, session, token, request headers, and signed HTTP cookie. The cookie uses the auth instance's name, signing secret, security settings, and expiration policy. Pass `login.Headers` to a native auth call or set `login.Cookies` in your browser fixture. Reusing this result keeps requests in the same session.

`GetAuthHeaders(ctx, userID)` and `GetCookies(ctx, userID, domain)` each create a new session. An empty domain selects the configured cookie domain or the auth hostname. To remove a fixture and its sessions, call `server.DeleteUser(ctx, user.ID)` while the test database is still open. Custom adapters can provide profile persistence and cleanup through `authtest.UserStore`. [Four-adapter tests](../authtest/server_test.go)

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
