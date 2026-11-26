# Switch accounts on one device

Enable the multi-session plugin when several people or accounts share a browser. Signing in sets the active account. The browser can remember five distinct accounts by default.

```go
limit := 3
switcher, err := multisession.New(multisession.Options{MaximumSessions: &limit})
if err != nil {
	return err
}
opts.Plugins = append(opts.Plugins, switcher)
```

Import `plugins/multisession` from this module. An explicit zero disables remembering new accounts. A sign-in at capacity still activates the new account. Signing in to a remembered account again replaces its previous login on that device. A separate browser can keep its own login for the same account.

## Use the account picker

All routes are relative to the configured auth mount. Keep the same cookie jar when listing and choosing an account.

| Request | Result |
| --- | --- |
| `GET /multi-session/list-device-sessions` | Returns an array of live `{session, user}` pairs, one per remembered account. An empty browser receives `[]`. |
| `POST /multi-session/set-active` | Send `{"sessionToken":"..."}` from a listed entry. The response contains the selected session and user. The next authenticated request uses that account. |
| `POST /multi-session/revoke` | Send the same JSON while signed in. The server revokes the selected login and returns `{"status":true}`. Removing the active login selects the first remaining live entry or signs out the browser. |
| `POST /sign-out` | Revokes the active login and every login proven by this browser's remembered-account cookies. Other browsers retain their independent logins. |

The Go client exposes `ListDeviceSessions`, `SetActiveSession` and `RevokeDeviceSession`. A signed remembered-account cookie allows listing and switching even when the primary cookie is missing. Revocation also requires a live active session. Supplying a token without its matching cookie returns HTTP 401 with code `INVALID_SESSION_TOKEN` and message `Invalid session token`.

## Cookie lifetime and concurrent requests

Each remembered login has an HTTP-only, same-site cookie under the application's cookie prefix. HTTPS uses secure cookies. A browser-only login keeps its original persistence setting when switched back to active. The server checks current storage on every selection and filters expired or revoked sessions from the list. Removing a remembered login revokes its stored session on every server using the same database.

Two tabs can submit sign-ins before either receives the other's cookies. The next list request reconciles the entries in cookie order, shows at most the configured maximum, and clears surplus, duplicate or expired entries. When simultaneous selections complete, the active cookie applied last by the browser controls its next request.

SQLite, PostgreSQL, MySQL and the in-memory adapter support this plugin with the core session records. A custom adapter must implement `plainauth.DeviceSessionStore`. Its guarded revocation operation validates the active login and deletes the target in one transaction.

## Customize list entries

With `customsession.NewWithOptions(project, customsession.Options{ProjectDeviceSessions: true})`, the service runs the session projection on each list entry. The default list returns the standard user and session fields. Choosing an account always returns the standard shape. Applications that render a custom picker should include the selection token in their projected view. In Go, call `client.ListDeviceSessionViews[T](ctx, c)` with the application's projected entry type. An empty picker returns an empty slice.
