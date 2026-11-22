# Additional user fields

Declare application profile attributes in `Options.UserAdditionalFields`. Email/password signup and first-time email OTP sign-in accept each writable attribute at the top level of the request. The signed-in owner can change writable attributes through `POST /update-user`. Signup, credential signin and current-session responses expose the configured public values under `user`.

```go
fields := map[string]plainauth.UserField{
	"locale":       {Type: plainauth.FieldString, Required: true, Column: "preferred_locale"},
	"score":        {Type: plainauth.FieldNumber, Default: 0},
	"newsletter":   {Type: plainauth.FieldBoolean},
	"accountClass": {Type: plainauth.FieldString, ServerOnly: true, Default: "standard"},
	"supportNote":  {Type: plainauth.FieldString, ServerOnly: true, Hidden: true},
}
decl := schema.AdditionalFields{User: fields}
store, err := sqlstore.OpenWithAdditionalFields(ctx, dialect, dsn, nil, decl)
if err != nil {
	return err
}
defer store.Close()
opts.Store = store
opts.UserAdditionalFields = fields
auth, err := plainauth.New(opts)
if err != nil {
	return err
}
```

The example uses the root package, `schema` and `adapters/sqlstore`. Supply the public URL, secret and email/password options for your installation. The in-memory adapter accepts the same declarations. To include session fields, populate `decl.Session` and `opts.SessionAdditionalFields` too. Each table owns its own namespace.

## Supply fields at registration

Choose a source for each required field on every registration path enabled in your application.

| Registration path | How the account receives its initial values |
| --- | --- |
| Email and password | Send writable fields at the top level of the signup request, or use `SignUpRequest.AdditionalFields` in Go. |
| Email code | Send writable fields with the code on the first successful sign-in for a new mailbox. Returning sign-ins use the saved profile. [Email OTP](email-otp.md#registration-profile-fields) |
| Phone verification | Send writable fields with the verification code. The host's resolvers supply the temporary email and display name. [Phone accounts](phone-number.md#registration-profile-fields) |
| Magic link | Configure static defaults for required fields. Verification writes them when it creates the account. [Magic links](magic-link.md#registration-fields) |
| Social authorization code | Map authenticated claims in the provider resolver or provide defaults. A returning sign-in keeps the stored values. [Social sign-in](social.md#user-fields-on-social-registration) |
| Administrator provisioning | Put attributes in the request's `data` object. Trusted application code can use `Auth.AdminCreateUser` to set server-owned values. [Administrator accounts](admin.md#create-users-with-application-profile-fields) |

## Reading and updating a profile

```go
created, err := client.SignUpEmail(ctx, authclient.SignUpRequest{
	Name: "Jo", Email: email, Password: password,
	AdditionalFields: map[string]any{"locale": "fr", "newsletter": false},
})
if err != nil {
	return err
}
locale, present := created.User.AdditionalField("locale")
```

Here `client` is a configured Go HTTP client and `authclient` is the `client` package. Native callers use `SignUpInput.AdditionalFields`. Both native and HTTP clients accept `ProfileUpdate{AdditionalFields: map[string]any{"newsletter": nil}}` to clear a nullable field. Omitted fields retain their current value. Core profile changes and the supplied additional values commit together. Use `User.AdditionalField` to distinguish an absent key from a present null. Numbers return as `int64`.

`ServerOnly` gives the application exclusive write access. At signup, a configured server-owned default overrides a supplied value. The input parser ignores false, zero, an empty string and null for a server-owned field. Other attempts to change it return `FIELD_NOT_ALLOWED`. After your application authorizes an operation, call the native service to update the exact account.

```go
err = auth.UpdateTrustedUserFields(ctx, userID, map[string]any{
	"accountClass": "staff",
	"supportNote":  "Account reviewed",
})
```

`Hidden` excludes a column from public user reads, even when the owner may write it. Pair it with `ServerOnly` when only a trusted application may supply the value. Hidden fields are ordinary database values. Apply your storage access controls and encryption requirements to them. Configured nodes read user profiles from storage for current-session requests and bypass the browser session snapshot. Use the same field declarations across nodes serving your application.

## Database upgrades

`schema.GenerateWithAdditionalFields(dialect, profiles, decl)` renders fresh DDL. `sqlstore.CheckSchemaWithAdditionalFields(ctx, dialect, dsn, profiles, decl)` checks the existing catalog without changing it. `OpenWithAdditionalFields` validates all requested user and session additions under the migration lock. A populated table can gain a nullable field or a required field with a supplied static default. Plan a backfill before requiring a column whose value must be computed for each row. Existing columns must have a compatible type and nullability and accept writes.

Supported values are strings, booleans and signed 32-bit integers. A required field needs a value or static default when the account is created. Explicit null is valid only on nullable fields. Choose logical and physical names that are distinct from core, plugin and reserved request fields.

Use `--user-fields FILE` with `authctl generate`, `authctl migrate` and `authctl check schema`. Applications can read the same declaration with `schema.ReadUserFields`. [Schema commands](schema.md#configure-user-and-session-fields)

The [feature checklist](parity/plugins/additional-fields.md) tracks further field types, computed defaults, custom validators and transforms.
