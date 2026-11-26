# Custom stores

`Options.Store` takes any value that implements `plainauth.Store`; the [SQL stores](databases.md) and `memory.New()` are two of them. Implement the core interface, add the optional interfaces your features need, and check the result with `storetest.Run`. The [map-backed example](../storetest/minimal_test.go) is the smallest store that passes.

## The core interface

```go
type Store interface {
	CreateUser(ctx context.Context, user User, passwordHash string, initial *StoredSession) error
	Credential(ctx context.Context, email string) (User, string, error)
	CreateSession(ctx context.Context, session StoredSession) error
	Session(ctx context.Context, token string) (StoredSession, User, error)
	DeleteSession(ctx context.Context, token string) error
	ListSessions(ctx context.Context, userID string) ([]StoredSession, error)
	DeleteOtherSessions(ctx context.Context, userID, keepToken string) error
	DeleteUserSession(ctx context.Context, userID, token string) error
}
```

Plain Auth generates every ID, token and timestamp; store them as given.

| Method | Contract |
| --- | --- |
| `CreateUser` | Writes the user, a password credential holding `passwordHash`, and `initial` when it is not nil, all or nothing. If another user has the address, return `ErrEmailTaken` and write nothing. Any other failure also writes nothing |
| `Credential` | Returns the user with this address and its hash, or `ErrNotFound` when there is no such user or it has no password |
| `CreateSession` | Inserts the session. Fail and store nothing when the user does not exist, including one deleted at the same moment, and never keep a session without its user; `ErrNotFound` is the preferred error |
| `Session` | Returns the session with this token and its user's current profile, or `ErrNotFound` |
| `ListSessions` | Returns all of the user's sessions in any order, and an empty list when there are none. There is no limit |
| `DeleteSession` | Deletes the session with this token |
| `DeleteUserSession` | Deletes the session only when it belongs to `userID` |
| `DeleteOtherSessions` | Deletes all of the user's sessions except `keepToken`; an empty `keepToken` deletes all of them |

Deleting something that is already gone returns nil.

- **Addresses.** Plain Auth lowercases the address before `CreateUser` and `Credential`. `FindAccountUser` receives it as typed, for example from a reset request, so match it case-insensitively. The simplest approach is to store addresses lowercased behind a unique index and lowercase lookup arguments.
- **Tokens and IDs** are unique, case-sensitive random strings. Store and compare them exactly as given; do not trim, re-encode or change their case. A unique index on session tokens is good practice, but Plain Auth never sends a token twice.
- **Times.** Keep at least millisecond precision. Times in `CreateUser` and `CreateSession` arrive as whole UTC milliseconds and must read back as the same instant; the time zone does not matter. Other `now` arguments, such as profile updates, email verification and reset tokens, may carry finer precision; truncating them to your column's precision is fine.
- **Expiry.** Store `ExpiresAt` as given. Plain Auth compares it with its own clock on every read, so `Session` and `ListSessions` may return expired sessions; a store may also drop them, for example with a TTL. With `SessionRefreshStore`, Plain Auth deletes an expired session that a request presents. Otherwise prune expired rows yourself.
- **Errors.** `ErrNotFound` and `ErrEmailTaken` are matched with `errors.Is`, so wrapping them with `%w` is fine. Optional interfaces have their own sentinels, such as `ErrUsernameTaken` and `ErrPasswordAlreadySet`. A store may return an `*APIError` to answer with its own status; keep secrets out of its message. Any other error becomes 500 `INTERNAL_SERVER_ERROR` over HTTP; `OnAPIError` and Go callers see the original error, the HTTP client never does.
- **Context.** Pass `ctx` to every database and network call, and do not keep it after the method returns.

## Concurrency and transactions

One store value serves all requests at once, and several servers may share the database. Enforce uniqueness of addresses and tokens with database constraints, and make each method's writes one transaction that the method begins and commits itself. A process-local mutex is enough only when one process owns the data, as with `memory.New()`. Never hold a transaction or lock between calls.

[Hooks](hooks.md#run-code-around-database-writes) run before and after the store call, never inside it, so a hook may call the Auth or the store and a store never waits on application code. Stores that decide a sign-in inside their own transaction implement `LoginPlanner`; see [sign-ins the store decides](hooks.md#sign-ins-the-store-decides).

## Optional interfaces

Plain Auth detects optional interfaces with type assertions on `Options.Store`. When an option needs one the store lacks, `New` returns an error that names it.

| Feature | Interface |
| --- | --- |
| Profile updates, password changes, reset and verification mail | `AccountStore` |
| Deleting users, changing email | `AccountLifecycleStore` |
| Additional user, session or account fields | `UserFieldStore`, `SessionFieldStore`, `AccountFieldStore` |
| `OnExistingUserSignUp` with `RequireEmailVerification` or `DisableAutoSignIn`, user and session create hooks, `ValidateUserInfo` for email sign-up | a `FindAccountUser` method |
| User or session create before hooks, or `ValidateUserInfo`, with sign-ins the store decides, such as social sign-in, magic links, email codes, One Tap or SSO | `LoginPlanner` |
| Social sign-in | `OAuthIdentityStore`, and `OAuthFlowStore` unless the state lives in a cookie |
| `SecondaryStorage` | `SessionMirrorStore` |
| `DisableVerificationCleanup` | `VerificationCleanupStore` |
| Plugins such as phone, username, magic link, email codes or JWT | the interface each plugin's guide names |

Plugins that take their own store, such as organizations, the OAuth provider, SSO, SCIM, passkeys, wallet sign-in, billing and API keys, check it the same way. The store that `AccountFieldStore.WithAccountFields` returns, and with the admin plugin the value `WithAdminConfig` returns, replace `Options.Store`, so each must implement every interface yours does: return a configured copy of your own type. `AdminOptions.BannedUserMessageFunc` and `Auth.AdminUserHasPermission` also need `plainauth.AdminUserReader`, which reads one account with its role and ban fields, and a ban refusal should be a `*plainauth.BannedUserError` naming the account.

Some interfaces change behaviour instead of being required. Without `AccountStore`, profile, password and verification operations answer 501. `SessionRefreshStore` adds sliding expiration and the deletion of expired sessions. With `AccountStore.CreateCredentialSession`, a sign-in creates its session only if the password is unchanged. Without `SessionCacheStore`, `SessionCookieCache` silently does nothing. Without `LinkedAccountStore` and `ProviderCredentialStore`, the account listing, unlinking and provider token routes answer 501, and sign-out never returns a provider logout URL.

## Test your store

```go
func TestStoreContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) plainauth.Store {
		s := openMyStore(t)
		t.Cleanup(func() { s.Close() })
		return s
	})
}
```

`open` may return a fresh store or one shared store: the cases use random keys and read only their own records. If the store has a `DeleteFixtureUser(ctx, userID)` method, the one `authtest.UserStore` requires, each case's users are deleted when it ends; otherwise use a disposable database. Run it with `-race`.

| Group | Runs when the store implements | Covers |
| --- | --- | --- |
| `Store` | always | atomic sign-up, duplicate addresses, session ownership, listing, the three deletes, concurrent sign-up and session creation, and sign-up, sign-in, revocation, password reset and sign-out through `plainauth.New` |
| `AccountStore` | `AccountStore` | case-insensitive lookup, password-guarded sessions and changes, single-use reset tokens, email verification and profile updates |
| `SessionRefreshStore` | `SessionRefreshStore` | the guarded expiry refresh and the deletion of expired sessions |

`Store/AuthFlow` builds an Auth with default options, so do not share the store with an Auth that sets `DisableVerificationCleanup`. Other optional interfaces are not covered; test those features through `plainauth.New` with the [test helpers](test-helpers.md). [Contract kit](../storetest/storetest.go) · [Memory store run](../adapters/memory/storetest_test.go) · [SQL store runs](../adapters/sqlstore/storetest_test.go)
