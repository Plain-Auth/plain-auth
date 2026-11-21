# Two-factor authentication

Add an authenticator app and single-use backup codes to email/password sign-in. Enable the two-factor SQL schema and register the plugin on every instance that accepts credentials. SQLite, PostgreSQL and MySQL support this flow.

```go
ddl, err := schema.Generate("sqlite", []string{"two-factor"})
if err != nil {
	return err
}
store, err := sqlstore.OpenWithSchema(ctx, "sqlite", "auth.db", ddl)
if err != nil {
	return err
}
opts.Store = store
opts.EmailAndPassword = true
opts.Plugins = append(opts.Plugins, twofactor.New(twofactor.Options{Issuer: "My App"}))
```

The packages above live under the module's `schema`, `adapters/sqlstore` and `plugins/twofactor` directories. Keep the same configured secret or versioned key ring across instances. When enabling the plugin on an existing database, apply the schema change before restarting the authentication servers. The library checks the presence of the two-factor field during startup.

## Enroll an authenticator

An authenticated browser sends JSON to these endpoints. All paths are relative to the auth mount.

1. POST `/two-factor/enable` with the current `password`. The response contains a `totpURI` for the authenticator and ten `backupCodes`. Offer the codes for private storage during setup.
2. POST `/two-factor/verify-totp` with the six-digit `code` as a string, preserving leading zeroes. On success the account becomes enrolled. The server replaces its sessions and sets a fresh cookie for the current browser.
3. The next successful password check at `/sign-in/email` returns `{"twoFactorRedirect":true,"twoFactorMethods":["totp"]}`. The browser receives a signed challenge cookie. Submit the authenticator code to `/two-factor/verify-totp`, or submit one backup code to `/two-factor/verify-backup-code`. Success consumes the challenge and creates the authenticated session in one transaction.

For direct Go calls, inspect `SignInEmail`'s `AuthResult.Challenge`. If present, return `Auth.TwoFactorChallengeCookie(*result.Challenge)` to the browser and complete the verification step there. A pending challenge carries no authenticated token. A Go HTTP client can inspect its sign-in result's `TwoFactorRedirect` and call the verification endpoint with the same cookie jar.

## Manage an enrolled account

| Endpoint | JSON fields | Effect |
| --- | --- | --- |
| `POST /two-factor/get-totp-uri` | `password` | Returns the current provisioning URI for the authenticated account. |
| `POST /two-factor/generate-backup-codes` | `password` | Returns ten fresh codes and invalidates the entire previous set. |
| `POST /two-factor/disable` | `password` | Removes the factor, invalidates outstanding challenges and replaces existing sessions with a new session for the caller. |
| `POST /two-factor/verify-backup-code` | `code`, optional `disableSession` | During sign-in, setting `disableSession` to `true` consumes the challenge and backup code without issuing a session. |

A challenge expires after ten minutes or five failed proofs. Ten consecutive failed verification attempts lock verification on the account for fifteen minutes. A successful proof resets the account failure count. Password changes and password recovery invalidate outstanding challenges. Each accepted sign-in TOTP time step can grant one login. Backup codes can each be spent once across all instances.

Provisioning secrets and backup codes use authenticated encryption at rest. Every encrypted record identifies its key version. A single configured secret uses version zero. To rotate it, include it as version zero in the key list and place the new key first. Keep each version available until the credentials it protects have been replaced. The session user's `twoFactorEnabled` field reports enrollment status.
