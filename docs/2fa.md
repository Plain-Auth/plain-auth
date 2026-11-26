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

1. POST `/two-factor/enable` with the current `password`. The response is `{"method":"totp","totpURI":…,"backupCodes":[…]}`, with ten backup codes by default. For an account without a second factor, the factor stays off, so password sign-in is not challenged, until step 2 succeeds. Offer the codes for private storage during setup.
2. POST `/two-factor/verify-totp` with the six-digit `code` as a string, preserving leading zeroes. On success the account becomes enrolled. The server replaces its sessions and sets a fresh cookie for the current browser.
3. The next successful password check at `/sign-in/email` returns `{"twoFactorRedirect":true,"twoFactorMethods":["totp"]}`. The browser receives a signed challenge cookie. Submit the authenticator code to `/two-factor/verify-totp`, or submit one backup code to `/two-factor/verify-backup-code`. Success consumes the challenge and creates the authenticated session in one transaction.

For direct Go calls, inspect `SignInEmail`'s `AuthResult.Challenge`. If present, return `Auth.TwoFactorChallengeCookie(*result.Challenge)` to the browser and complete the verification step there. A pending challenge carries no authenticated token. A Go HTTP client can inspect its sign-in result's `TwoFactorRedirect` and call the verification endpoint with the same cookie jar.

A host can also enable authenticator enrollment from a personal application key. This flow verifies the current password, binds the pending enrollment to that exact key and confirms it with an authenticator code. [Application key guide](api-keys.md#authenticate-an-auth-request-with-a-key)

## Manage an enrolled account

| Endpoint | JSON fields | Effect |
| --- | --- | --- |
| `POST /two-factor/get-totp-uri` | `password` | Returns the current provisioning URI for the authenticated account. |
| `POST /two-factor/generate-backup-codes` | `password` | Returns ten fresh codes and invalidates the entire previous set. |
| `POST /two-factor/disable` | `password` | Removes the factor, invalidates outstanding challenges and replaces existing sessions with a new session for the caller. |
| `POST /two-factor/verify-backup-code` | `code`, optional `disableSession` | During sign-in, setting `disableSession` to `true` consumes the challenge and backup code without issuing a session. |

A challenge expires after ten minutes or five failed proofs. Ten consecutive failed verification attempts lock verification on the account for fifteen minutes. A successful proof resets the account failure count. Password changes and password recovery invalidate outstanding challenges. The server accepts an authenticator code from the current period and from the periods just before and after it. A sign-in then accepts only a code from a later period than the last one accepted, so each period grants at most one login. The management routes check the password first, so a wrong one answers `INVALID_PASSWORD` even where authenticators are disabled or no factor is enrolled; another runtime answers the refusals of `/two-factor/get-totp-uri`, and of `/two-factor/generate-backup-codes` for an account without two-factor, before the password. `/two-factor/verify-totp` answers `TOTP_NOT_ENABLED` to an account without an authenticator, including one enrolled for delivered codes alone, and during sign-in to an authenticator that is not confirmed yet. Backup codes can each be spent once across all instances.

Provisioning secrets use authenticated encryption at rest. Backup codes use the same protection by default. Every encrypted record identifies its key version. A single configured secret uses version zero. To rotate it, include it as version zero in the key list and place the new key first. Keep each version available until the credentials it protects have been replaced. The session user's `twoFactorEnabled` field reports enrollment status.

## Remember a browser

A browser completing a sign-in challenge can include `"trustDevice":true` with a valid authenticator code, delivered code or backup code. The server issues an HTTP-only signed cookie and records an expiring grant for that account. The proof also clears the browser's don't-remember marker, so a session started with `rememberMe` false renews like a remembered one. On the next password sign-in it consumes the old grant, creates the session and issues a replacement grant in one transaction. Concurrent sign-ins presenting the same cookie can use it once. A missing, expired, altered or differently owned grant leads to a new second-factor challenge.

`TrustDeviceMaxAge` defaults to 30 days and `ChallengeLifetime` defaults to 10 minutes. `New` refuses a negative lifetime or one under a second. Set both on `twofactor.Options`. Password changes, password resets and disabling the factor invalidate the account's remembered grants. For native credentials, pass the incoming signed cookie value in `RequestMeta.TrustedDeviceCookie` and return any `AuthResult.TrustedDeviceCookie` to the browser. `Auth.TrustedDeviceCookieName()` returns the namespace for this instance.

## Deliver a second-factor code

Configure `OTP.Send` with an application-owned mail, SMS or other delivery callback. Direct each code to a verified destination for `message.User`. The server stores the code and then calls the sender outside the database transaction, after the response when `BackgroundTasks` is set; another runtime starts the sender before the response and hands off only its promise. A sender error is logged without the code, and the answer is still `{"status":true}` with the stored code valid. A newer send replaces the code, so a late failure of an older one leaves the newer code alone.

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

1. An authenticated account enrolls with `POST /two-factor/enable` and `{"method":"otp","password":"…"}`. Enrolling ends the account's sessions and starts a new one for the caller; another runtime ends only the current one. The answer is `{"method":"otp"}`. Without `OTP.Send` the route answers `OTP_NOT_CONFIGURED` after the password check and changes nothing.
2. A subsequent password sign-in returns a challenge and the available methods. The client calls `POST /two-factor/send-otp` with an empty JSON object to deliver a new code for that challenge. Sending another code replaces the previous one. The body may carry a boolean `trustDevice`, which is checked and otherwise ignored; the browser is remembered only when the `/two-factor/verify-otp` request sends `trustDevice`.
3. Submit the code to `POST /two-factor/verify-otp` as `{"code":"012345","trustDevice":false}`. The server consumes the proof and challenge as it creates the session. An active signed-in session may also request a code for itself.

An account enrolled with delivered codes can set up an authenticator while continuing to use its existing channel. Confirming the new authenticator adds it to the available methods. The Go HTTP client provides `EnableDeliveredFactor`, `SendFactorOTP`, `VerifyFactorOTP`, `VerifyTOTPWithTrust` and `VerifyBackupCodeWithTrust`.

## Observe or cancel second-factor records with hooks

[Verification database hooks](hooks.md#verification-hooks) see a sign-in challenge as `2fa`, a delivered code as `2fa-otp` and a remembered browser as `trust-device`, each naming the account and never a key, code or count. Every proof during sign-in runs the challenge's delete before hooks before it is compared, and `/two-factor/verify-otp` runs the code's first. A declined proof is refused before it counts. A counted wrong guess runs the update after hooks, and a spent or removed record runs the delete after hooks. A declined challenge is answered with a cookie that redeems nothing, a declined remembered browser asks for the second factor and keeps its grant, a declined new grant signs in without remembering the browser, and a declined code answers as sent with nothing stored or sent. Enabling, disabling or importing a factor, password changes and resets and the other account-wide revocations remove these records without hooks. Verification hooks need a store implementing `plainauth.FactorRecordReporter`, as the SQL store does, and `New` refuses verification update before hooks with this plugin. [Two-factor hooks on SQL engines](../adapters/sqlstore/twofactor_hooks_test.go)

## Configure the factors

| Setting on `twofactor.Options` | Behavior |
| --- | --- |
| `TOTP.Digits`, `TOTP.Period` | Six or eight digits, with a whole-second period. Defaults to six digits and 30 seconds. The provisioning URI carries both values. |
| `TOTP.Disabled` | Disables the authenticator method. `/two-factor/enable` without `"method":"otp"`, `/two-factor/get-totp-uri` and `/two-factor/verify-totp` answer `TOTP_NOT_CONFIGURED`. `/two-factor/verify-totp` checks its body and then answers before it reads a session, challenge, factor or lockout, so it compares or counts no code. Sign-in leaves `totp` out of `twoFactorMethods`. Backup codes and delivered codes keep working. |
| `Backup.Amount`, `Backup.Length` | Defaults to ten codes of ten random characters each, separated after the first five. Generated codes are distinct. `New` refuses a negative value, one above 256, and a one-character length with more than 62 codes. |
| `Backup.Generate` | Supplies a distinct, nonempty set of application-generated recovery codes. |
| `Backup.Store` | Accepts `encrypted` (default) or `plain`. A paired `Backup.Encrypt` and `Backup.Decrypt` supplies a custom storage format. |
| `OTP.Digits`, `OTP.Period`, `OTP.AllowedAttempts` | Delivered codes default to six decimal digits, three minutes and five comparisons. The challenge also limits failed proofs across resends. `New` refuses a negative digit count or one above 128. |
| `OTP.Store` | Accepts `plain` (default), `hashed` or `encrypted`. An application can supply `OTP.Hash` or paired `OTP.Encrypt` and `OTP.Decrypt` instead. |
| `Lockout.MaxFailedAttempts`, `Lockout.Duration`, `Lockout.Disabled` | Configure the account-wide failure count and lockout interval or disable that counter. The challenge attempt cap still applies. |
| `AllowPasswordless` | Allows a signed-in account without a credential password to manage its factors without one. `TOTP.AllowPasswordless` and `Backup.AllowPasswordless` override it, in either direction, for `/two-factor/get-totp-uri` and `/two-factor/generate-backup-codes`. Where a switch is on, `password` is optional, and an account with a password that leaves it out gets `INVALID_PASSWORD`. Where it is off, a missing `password` is a `VALIDATION_ERROR`. A `password` that is sent must be a string. |
| `SkipVerificationOnEnable` | Enables authenticator enrollment immediately after the password check and replaces the existing sessions. |

Trusted Go code can call `Auth.GenerateTOTP(rawSecret)` and `Auth.ViewBackupCodes(ctx, userID)`. Authorize requests for recovery material before passing the account ID to the latter operation. Both functions stay inside the Go process.

## Errors

Each error carries its status, code and message from the two-factor error table.

| Code | Status | When |
| --- | ---: | --- |
| `OTP_NOT_ENABLED` | 400 | `/two-factor/send-otp` or `/two-factor/verify-otp` from a session whose account has not enrolled; only `/two-factor/enable` with the password enrolls an account, where another runtime also enrolls one through a verified code |
| `OTP_NOT_CONFIGURED` | 400 | Delivered-code enrollment without `OTP.Send`, or `/two-factor/send-otp` without it, which answers `otp isn't configured` before reading the session or challenge |
| `OTP_HAS_EXPIRED` | 400 | No live delivered code: none was sent, or it expired |
| `TOTP_NOT_ENABLED` | 400 | `/two-factor/get-totp-uri` or `/two-factor/verify-totp` for an account without an authenticator, or a sign-in proof for one awaiting confirmation |
| `TOTP_ALREADY_ENABLED` | 400 | Authenticator enrollment for an account with a confirmed authenticator |
| `TOTP_NOT_CONFIGURED` | 400 | `TOTP.Disabled` is set: enrollment and `Auth.ImportTOTP` answer `TOTP is not available`, and `/two-factor/get-totp-uri`, `/two-factor/verify-totp` and `Auth.GenerateTOTP` answer `totp isn't configured`. A password sign-in for an enrolled account with no usable factor and no stored backup codes also answers `TOTP is not available`, even from a remembered browser, where another runtime issues a challenge or signs that browser in |
| `TWO_FACTOR_NOT_ENABLED` | 400 | `/two-factor/generate-backup-codes` for an account that has not enabled two-factor or has no authenticator; backup codes an account enrolled with delivered codes alone already holds keep working, where another runtime has none |
| `BACKUP_CODES_NOT_ENABLED` | 400 | A backup-code proof or `Auth.ViewBackupCodes` for an account without codes, an unknown account included; backup codes of an authenticator awaiting confirmation also answer it, where another runtime accepts them |
| `INVALID_BACKUP_CODE` | 401, or 400 from `Auth.ViewBackupCodes` | A wrong backup code, or stored codes that are not a JSON list once decrypted |
| `INVALID_CODE` | 401 | A wrong authenticator or delivered code |
| `TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE` | 400 | A delivered code past `OTP.AllowedAttempts`. The fifth failed proof of any kind ends a challenge at once, so the next proof answers `INVALID_TWO_FACTOR_COOKIE`; another runtime counts only authenticator and backup-code failures there and answers the next one with this code first |
| `ACCOUNT_TEMPORARILY_LOCKED` | 429 | The account lock is active. It also covers accounts enrolled with delivered codes alone, proofs from a signed-in session and `/two-factor/send-otp`, where another runtime locks only sign-in proofs of accounts with a factor record |
| `INVALID_TWO_FACTOR_COOKIE` | 401 | A proof or code request without a live challenge |

[Error code tests](../adapters/sqlstore/twofactor_errors_test.go)

## Import an existing authenticator

Trusted server code can enroll an existing account with a Base32 TOTP seed. First authorize the operator for that account and obtain the seed through a confidential channel. Supply the account's exact ID and the seed from the authenticator’s provisioning record.

```go
if err := auth.ImportTOTP(ctx, userID, base32Seed); err != nil {
    return err
}
```

The importer accepts uppercase or lowercase RFC 4648 Base32, with optional padding. Remove spaces from a grouped display before calling it. The authenticator must use SHA-1 and match the server’s `TOTP.Digits` and `TOTP.Period` settings. A successful import encrypts the decoded key with the active local storage key, enables the factor, and revokes existing sessions, pending challenges and remembered-browser grants together. The next password sign-in requires the authenticator. An existing or pending enrollment returns HTTP-equivalent status 409 through the Go error and keeps its credentials.

When the source supplies a provisioning URI, extract its Base32 `secret` query parameter. When the source encrypts its records, retrieve the seed using its authorized key-management process. The new factor starts with an empty recovery-code set. After sign-in, the account holder can generate fresh recovery codes with `POST /two-factor/generate-backup-codes`. Keep seed material out of logs and client requests. [Import and sign-in tests](../adapters/sqlstore/twofactor_import_test.go)
