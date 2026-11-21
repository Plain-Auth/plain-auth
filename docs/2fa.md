# Two-factor authentication

Add an authenticator app, delivered verification code or single-use backup code to email/password sign-in. Enable the two-factor SQL schema and register the plugin on every instance that accepts credentials. SQLite, PostgreSQL and MySQL support this flow.

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

1. POST `/two-factor/enable` with the current `password`. The response contains a `totpURI` for the authenticator and ten `backupCodes` by default. Offer the codes for private storage during setup.
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

Provisioning secrets use authenticated encryption at rest. Backup codes use the same protection by default. Every encrypted record identifies its key version. A single configured secret uses version zero. To rotate it, include it as version zero in the key list and place the new key first. Keep each version available until the credentials it protects have been replaced. The session user's `twoFactorEnabled` field reports enrollment status.

## Remember a browser

A browser completing a sign-in challenge can include `"trustDevice":true` with a valid authenticator code, delivered code or backup code. The server issues an HTTP-only signed cookie and records an expiring grant for that account. On the next password sign-in it consumes the old grant, creates the session and issues a replacement grant in one transaction. Concurrent sign-ins presenting the same cookie can use it once. A missing, expired, altered or differently owned grant leads to a new second-factor challenge.

`TrustDeviceMaxAge` defaults to 30 days and `ChallengeLifetime` defaults to 10 minutes. Set both on `twofactor.Options`. Password changes, password resets and disabling the factor invalidate the account's remembered grants. For native credentials, pass the incoming signed cookie value in `RequestMeta.TrustedDeviceCookie` and return any `AuthResult.TrustedDeviceCookie` to the browser. `Auth.TrustedDeviceCookieName()` returns the namespace for this instance.

## Deliver a second-factor code

Configure `OTP.Send` with an application-owned mail, SMS or other delivery callback. Direct each code to a verified destination for `message.User`. The server stages a pending code, calls the sender outside the database transaction, and activates the code after delivery succeeds. A failed or delayed callback cannot replace a newer code.

```go
plugin := twofactor.New(twofactor.Options{
	OTP: twofactor.OTPOptions{
		Store: "encrypted",
		Send: func(ctx context.Context, message twofactor.OTPMessage) error {
			return mailer.SendFactorCode(ctx, message.User.ID, message.Code)
		},
	},
})
```

1. An authenticated account enrolls with `POST /two-factor/enable` and `{"method":"otp","password":"…"}`. Enrolling replaces the current session.
2. A subsequent password sign-in returns a challenge and the available methods. The client calls `POST /two-factor/send-otp` with an empty JSON object to deliver a new code for that challenge. Sending another code replaces the previous one.
3. Submit the code to `POST /two-factor/verify-otp` as `{"code":"012345","trustDevice":false}`. The server consumes the proof and challenge as it creates the session. An active signed-in session may also request a code for itself.

An account enrolled with delivered codes can set up an authenticator while continuing to use its existing channel. Confirming the new authenticator adds it to the available methods. The Go HTTP client provides `EnableDeliveredFactor`, `SendFactorOTP`, `VerifyFactorOTP`, `VerifyTOTPWithTrust` and `VerifyBackupCodeWithTrust`.

## Configure the factors

| Setting on `twofactor.Options` | Behavior |
| --- | --- |
| `TOTP.Digits`, `TOTP.Period` | Six or eight digits, with a whole-second period. Defaults to six digits and 30 seconds. The provisioning URI carries both values. |
| `TOTP.Disabled` | Disables the authenticator method. |
| `Backup.Amount`, `Backup.Length` | Defaults to ten codes of ten random characters each, separated after the first five. |
| `Backup.Generate` | Supplies a distinct, nonempty set of application-generated recovery codes. |
| `Backup.Store` | Accepts `encrypted` (default) or `plain`. A paired `Backup.Encrypt` and `Backup.Decrypt` supplies a custom storage format. |
| `OTP.Digits`, `OTP.Period`, `OTP.AllowedAttempts` | Delivered codes default to six decimal digits, three minutes and five comparisons. The challenge also limits failed proofs across resends. |
| `OTP.Store` | Accepts `plain` (default), `hashed` or `encrypted`. An application can supply `OTP.Hash` or paired `OTP.Encrypt` and `OTP.Decrypt` instead. |
| `Lockout.MaxFailedAttempts`, `Lockout.Duration`, `Lockout.Disabled` | Configure the account-wide failure count and lockout interval or disable that counter. The challenge attempt cap still applies. |
| `AllowPasswordless` | Allows a signed-in account without a credential password to manage its factors. Accounts with a password must supply it. `TOTP.AllowPasswordless` and `Backup.AllowPasswordless` enable the corresponding URI and code-management operations separately. |
| `SkipVerificationOnEnable` | Enables authenticator enrollment immediately after the password check and replaces the existing sessions. |

Trusted Go code can call `Auth.GenerateTOTP(rawSecret)` and `Auth.ViewBackupCodes(ctx, userID)`. Authorize requests for recovery material before passing the account ID to the latter operation. Both functions stay inside the Go process.
