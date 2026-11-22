# Passwordless email sign-in

Register a mail sender to let users sign in by opening a single-use link delivered to their inbox. The SQL adapters use the existing verification, user and session tables.

```go
plugin, err := magiclink.New(magiclink.Options{
	HashTokens: true,
	ExpiresIn: 5 * time.Minute,
	Send: func(ctx context.Context, message magiclink.Message) error {
		return mailer.Send(ctx, message.Email, "Sign in", message.URL)
	},
})
if err != nil {
	return err
}
opts.Plugins = append(opts.Plugins, plugin)
```

Import `plugins/magiclink` from this module. The sender receives the destination email, full URL, raw token and optional application metadata. Use `message.Request.Header.Get("Accept-Language")` to select a mail template from the browser locale. The request is a metadata-only copy. Encoding the message as JSON excludes HTTP headers and cookies. Deliver the link only to `message.Email`. Treat metadata as user input. The HTTP response to a successful send is `{"status":true}`.

## Request and verify a link

Send `POST /sign-in/magic-link` beneath the auth mount with the following JSON fields.

| Field | Meaning |
| --- | --- |
| `email` | Mailbox that will receive the link. |
| `name` | Optional display name for a newly registered user. |
| `callbackURL` | Destination after successful sign-in. The link defaults to the application's root. |
| `newUserCallbackURL` | Optional destination after creating an account. |
| `errorCallbackURL` | Optional destination for an expired, spent or rejected link. |
| `metadata` | Optional JSON object delivered to the sender. |

Opening the delivered `GET /magic-link/verify` URL verifies the mailbox, sets the session cookie and redirects to the application. The server checks all redirect destinations against its configured origins on both requests. Calling the verification endpoint with only `token` returns a JSON object containing `token`, `user` and `session`. Expired and spent links redirect with `error=INVALID_TOKEN`. Each link can issue one session across all server instances.

Set `DisableSignUp` on the plugin to restrict sign-in to existing users. An unknown mailbox then receives the same initial delivery response and verification redirects with `error=new_user_signup_disabled`. An existing unverified account is promoted only after proving the email address. The account's pre-verification credentials and sessions are revoked during that promotion. A link issued for an existing account checks that account's identity when redeemed in Go.

A Go client can request delivery with `Client.SignInMagicLink(ctx, client.MagicLinkRequest{Email: email})`. Once the user supplies the delivered token, call `Client.VerifyMagicLink(ctx, token)` on the same client. The result includes the user and session, and the client retains the session cookie.

## Registration fields

A new account receives the static defaults from `Options.UserAdditionalFields` on the server that verifies the link. The request accepts the fields listed above. Sending extra profile properties or adding them to delivery metadata cannot change those defaults. An existing mailbox owner keeps their saved profile and display name. Each new session receives its own configured session defaults.

A required profile field needs a default for magic-link registration. If the server cannot supply that value, verification consumes the proof and returns a server error without creating an account or session. An existing account with a saved value can still sign in. A custom store that combines open magic-link registration with configured user fields implements `MagicLinkUserFieldStore` to commit the new profile and first session together.

JSON verification and `get-session` expose public fields using their configured names. In the Go client, read them with `result.User.AdditionalField(name)` and `result.Session.AdditionalField(name)`. [Profile and field configuration](user-fields.md) · [Registration tests](../adapters/sqlstore/magiclink_fields_test.go)

## Choose a store

Use `memory.New()` from `adapters/memory` for development with a single process. Share that store across auth instances that need to redeem each other's links. Restarting the process clears pending links, accounts and sessions. For multiple processes, give each instance a SQLite, PostgreSQL or MySQL adapter connected to the same database. A link issued for an existing owner stops working when the address moves to another account. [Concurrent memory redemptions](../adapters/memory/magiclink_test.go) · [SQL adapter tests](../adapters/sqlstore/magiclink_test.go)

## Tokens and limits

Links expire after five minutes by default. Set `ExpiresIn` to change their lifetime. With `HashTokens: true`, the database stores a SHA-256 digest of the token using unpadded URL-safe Base64. The default stores the raw token under a purpose-specific key. Applications with their own token services can supply `GenerateToken` and `HashToken` callbacks. Configure one hashing mode and use the same configuration on all instances.

When rate limiting is enabled on the auth server, each endpoint accepts five requests per peer per minute. Set `RateLimit` to a `plainauth.RateLimitRule` to change the maximum and window. The rule uses the server's configured rate-limit storage.
