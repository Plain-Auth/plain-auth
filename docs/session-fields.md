# Additional session fields

An application can store scalar metadata on each login, such as a preferred language or a host-assigned device class. One account's sessions can hold different values. Configure the same field definitions on the nodes that create and manage those sessions.

```go
fields := map[string]plainauth.SessionField{
    "locale": {
        Type: plainauth.FieldString, Column: "preferred_locale",
        Required: true, Default: "en",
    },
    "deviceClass": {
        Type: plainauth.FieldString, ServerOnly: true, Default: "browser",
    },
    "internalRisk": {
        Type: plainauth.FieldNumber, ServerOnly: true, Hidden: true,
    },
}

store, err := sqlstore.OpenWithSessionFields(ctx, "postgres", dsn, nil, fields)
if err != nil {
    return err
}
defer store.Close()

server, err := plainauth.New(plainauth.Options{
    Store: store, BaseURL: origin, Secret: signingSecret,
    EmailAndPassword: true, SessionAdditionalFields: fields,
})
```

Set `Default: time.Now` on a `plainauth.FieldDate` to record a new instant each time the application prepares a session. The library evaluates a zero-argument callback once for that preparation and validates its result against the declared type. Reads and updates reuse the stored value. A plugin can call `EndpointContext.IssueSessionWithFields` to provide trusted values at issuance. A trusted override takes precedence over the computed default.

Use `FieldString`, `FieldBoolean`, `FieldNumber`, or `FieldDate`. Set a date with a Go `time.Time` or an RFC 3339 string that includes its time zone. The session returns the instant in UTC at millisecond precision. Numbers are signed 32-bit integers and the Go accessor returns an `int64`. Optional fields accept null. Setting `Required` rejects null during issuance and updates. Use a static value or a creation callback for required fields when ordinary sign-in creates sessions. A host that supplies all required fields itself can use trusted insertion. Strings support Unicode and exclude the NUL character.

Logical field names and physical column names start with an ASCII letter and can contain up to 63 ASCII letters, digits and underscores. Names belonging to identity, session credentials or built-in plugin session fields are reserved. A physical name defaults to the logical field name. Case-insensitive collisions are rejected during setup.

## Read and update a session

Call `GetSession` or `ListSessions` and use `session.AdditionalField("locale")`. The second return value distinguishes a present null from an absent field. On the wire, visible fields are properties of the session object. `Hidden` removes the field from that object. `ServerOnly` prevents a caller from changing the value, including updates that supply null, false or zero. The two settings can be combined. A hidden field without `ServerOnly` accepts input and omits it from the response.

```go
updated, err := browserClient.UpdateSession(ctx, map[string]any{"locale": "es"})
if err != nil {
    return err
}
locale, present := updated.AdditionalField("locale")
```

`POST /update-session` accepts a JSON object and returns `{"session": ...}`. The authenticated owner can patch the current session. Unknown properties are ignored. A request with no writable changes returns 400. An invalid configured field rejects the entire patch. Origin restrictions apply to the HTTP request, including the usual callback URL properties. Application credentials, delegated logins and expired or revoked sessions cannot update session metadata.

`Auth.WithTrustedSessionFields(row, overrides)` prepares a new `StoredSession` with static defaults and the host's overrides. Pass the prepared row to the store's normal atomic session creation operation. This Go method accepts declared server-only fields and rejects undeclared names. For example, a trusted fixture can set the device class while retaining the normal expiry, user and token of the prepared row.

## Storage and deployment

`schema.GenerateWithSessionFields(dialect, profiles, fields)` produces fresh SQL. `sqlstore.OpenWithSessionFields` applies the profile and field configuration to SQLite, PostgreSQL or MySQL. Pass the same map to `plainauth.New`. The memory adapter accepts the runtime map directly. A custom adapter can implement `SessionFieldStore` and use `StoredSession.PhysicalSessionFields()` inside its normal session-insert transaction.

On a fresh SQL database, the application supplies configured defaults on each insert. On an existing database the migration adds missing columns and uses their static defaults to backfill older sessions. Columns with compatible types and nullability are reused. The migration rejects incompatible, generated or identity columns. It also rejects adding a required column without a default to a populated session table. Coordinate required field deployments across writers, including older application nodes that omit a new column. Renames and changes to a column type or existing default need an application-managed migration.

A node with configured session fields reads the live session for its browser session view, including when compact, JWT or JWE cookie caching is enabled. This makes updates visible immediately and respects each node's field visibility configuration. A node without the field configuration exposes only its own declared response. The supported scalar contract covers database-backed session creation, reads, owner session lists and updates. The checklist tracks custom validators, JSON fields and additional fields in cookie-only snapshots.
