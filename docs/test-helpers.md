# Test helpers

Import `github.com/Plain-Org/plain-auth/authtest` from a Go test to build user and organization fixtures or read codes issued by your test server. The package runs in the test process and registers no HTTP routes.

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

`GetAuthHeaders(ctx, userID)` and `GetCookies(ctx, userID, domain)` each create a new session. An empty domain selects the configured cookie domain or the auth hostname. To remove a fixture and its sessions, call `server.DeleteUser(ctx, user.ID)` while the test database is still open. Custom adapters can provide profile persistence and cleanup through `authtest.UserStore`, and run the [store contract tests](custom-store.md#test-your-store). [Four-adapter tests](../authtest/server_test.go)

## Import a fixture login into a browser

Call `login.BrowserCookies("")` to export the current fixture login as browser automation cookie objects. An empty domain uses the cookie's issued scope. Pass a test domain such as `.example.test` when testing across subdomains. The export reuses the signed cookie and the session's original deadline. Each object contains `name`, `value`, `domain`, `path`, `httpOnly`, `secure`, and `sameSite`. Persistent cookies also contain `expires` in Unix seconds. A partitioned cookie also contains `partitionKey`, the HTTPS site of its domain. Pass the top-level site's domain to export one that the instance issues host-only.

```go
cookies, err := login.BrowserCookies("")
if err != nil {
    t.Fatal(err)
}
cookieJSON, err := json.Marshal(cookies)
if err != nil {
    t.Fatal(err)
}
```

Pass the decoded `cookieJSON` array to the browser context's cookie importer before opening your protected route. Keep it in the test process or a private temporary file. The signed values grant access to this fixture user's session. The [Chromium test](../conformance/browser-fixture-cookies.mjs) imports the array, reads the authenticated user, and verifies that deleting the fixture revokes the browser login.

## Save and remove organization fixtures

Use `authtest.NewWithOrganizations` with a dedicated SQLite, PostgreSQL or MySQL database initialized with the `organization` schema profile. Use `organization-teams` when the test needs teams. Pass the organization options to the constructor once. It installs the plugin and retains the same configured adapter for trusted grants and fixture persistence. An empty `organization.Options.Store` selects the auth store. A custom organization adapter can implement `authtest.OrganizationStore` and `organization.MemberWriter`.

```go
server, err := authtest.NewWithOrganizations(opts, organization.Options{})
if err != nil {
    t.Fatal(err)
}
group, err := server.SaveOrganization(t.Context(), authtest.NewOrganization("Support"))
if err != nil {
    t.Fatal(err)
}
t.Cleanup(func() {
    if err := server.DeleteOrganization(context.Background(), group.ID); err != nil {
        t.Error(err)
    }
})
user, err := server.SaveUser(t.Context(), authtest.NewUser())
if err != nil {
    t.Fatal(err)
}
member, err := server.AddMember(t.Context(), organization.AddMemberRequest{
    UserID: user.ID, OrganizationID: group.ID, Roles: []string{"admin"},
})
if err != nil {
    t.Fatal(err)
}
if member.Role != "admin" {
    t.Fatalf("unexpected member role %q", member.Role)
}
```

`SaveOrganization` inserts the supplied ID, name, slug, logo, metadata and creation time. The new organization starts with zero members and teams. `AddMember` uses the trusted grant service and preserves application-defined role labels. Omitting the roles or supplying a single empty string selects `member`. A role grants the actions defined for it in the organization's permission policy. Supply `TeamID` to enroll the member in an existing team when teams are configured.

`DeleteOrganization` is idempotent and runs in one database transaction. It removes local memberships, invitations, teams, team memberships and current selections, plus tenant-owned API keys, billing subscriptions and billing receipts. An account with the same reference ID retains its own credentials and subscriptions. The fixture returns an actionable error if a managed SSO provider still names the organization, or if an imported key or billing record has ambiguous ownership. Delete the provider using its management API or resolve the ambiguous local records before retrying. Custom plugin data, external key storage and remote provider resources require their own test teardown. Register cleanup before closing the fixture database. [SQL lifecycle and isolation tests](../adapters/sqlstore/organization_fixtures_test.go)

## Supply additional session fields

Pass `authtest.LoginOptions` to seed a session that requires application-defined values. Configure the fields on the auth instance and include their physical columns in the test database. The helpers can set a server-only field such as a workstation ID before the insert.

```go
opts := authtest.LoginOptions{
    UserID: user.ID,
    Fields: map[string]any{"station": "warehouse-2", "label": ""},
}
login, err := server.LoginWithOptions(t.Context(), opts)
if err != nil {
    t.Fatal(err)
}
station, ok := login.Session.AdditionalField("station") // "warehouse-2", true
```

`GetAuthHeadersWithOptions(ctx, opts)` and `GetCookiesWithOptions(ctx, opts, domain)` accept the same values. Omitted fields use their configured defaults. An explicitly supplied empty string, zero or false overrides a default. Hidden values stay in storage. The issuer supplies the session ID, user ID, token, timestamps, IP address and user agent. A missing required field, unknown field or invalid value returns an error before the helper creates a session. [Four-adapter tests](../adapters/sqlstore/fixture_session_fields_test.go)

## Test email and phone codes

Create one recorder per test and wrap the sender when configuring the plugin. The wrapper captures the issued code under its delivery address and calls the sender you supply. Pass `nil` for a test that uses only the recorder. A sender error reaches a direct Go caller; over HTTP it is logged and the endpoint answers as if the code was sent, except `/phone-number/send-otp` without `BackgroundTasks`, which reports it. Captured proofs stay in the test process even if the database stores a hash.

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
