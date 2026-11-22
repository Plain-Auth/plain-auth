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

Supported values are strings, booleans and signed 32-bit integers. `Required` rejects missing values without defaults at signup and rejects explicit null on writes. Logical and physical names must be distinct from core, plugin and reserved request fields. Signup on a fresh database applies defaults in the application. Other provisioning flows such as social signup, SCIM, administration and fixtures have their own input contracts. A required column needs a value from each enabled writer. The CLI reads these declarations from `--user-fields FILE`. An application can load the same JSON with `schema.ReadUserFields`. [Schema commands](schema.md#configure-user-and-session-fields)

This profile covers static scalar defaults, the email/password account lifecycle and email OTP registration. Collections, dates, computed defaults, custom validators and transforms, and per-field compile-time client inference remain open.
