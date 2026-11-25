# Sign in with Ethereum

By default a user signs an EIP-4361 message with an externally owned Ethereum account. Plain Auth verifies the signature locally and issues its ordinary session cookie. Applications can also authorize smart-contract wallets through a server-side verifier. The server requires the configured application origin in the signed message and its URI. A bare authority such as `wallet.example.com` selects HTTPS. Include the port when it is part of the origin.

```go
ddl, err := schema.Generate("sqlite", []string{"siwe"})
if err != nil {
    return err
}
store, err := sqlstore.OpenWithSchema(ctx, "sqlite", "auth.db", ddl)
if err != nil {
    return err
}
defer store.Close()

wallet, err := siwe.New(siwe.Options{
    Domain: "wallet.example.com",
    Chains: []int64{1, 137},
})
if err != nil {
    return err
}
server, err := plainauth.New(plainauth.Options{
    BaseURL: "https://wallet.example.com", Secret: secret, Store: store,
    Plugins: []plainauth.Plugin{wallet},
})
```

1. Send `POST /siwe/nonce` or `POST /siwe/get-nonce` with an empty JSON object. The response contains a random alphanumeric `nonce` valid for 15 minutes.
2. Have the wallet sign an EIP-4361 version 1 message containing its address, your configured authority, a URI on that origin, chain ID, issuance time and the nonce. Plain Auth accepts valid optional expiration and not-before times. Omit `Chains` to accept positive chain IDs through 2,147,483,647.
3. Send `POST /siwe/verify` with the exact `message` and its `signature`. The built-in verifier accepts 65-byte hex EOA signatures. The JSON response contains `success`, the session `token`, and the user’s `id`, checksummed `walletAddress` and `chainId`. The Go HTTP client exposes `SIWENonce(ctx)` and `VerifySIWE(ctx, message, signature)`.

These paths are relative to the authentication mount. When verification receives a recognized challenge from the signed text, it consumes the challenge before evaluating the domain, chain, time bounds and signature. Request a fresh nonce after a failed verification.

[Verification database hooks](hooks.md#verification-hooks) run create hooks, `siwe`, when a nonce is issued, and delete hooks when a verification spends it, before the signature is checked and before `ValidateUserInfo` and the session hooks. A declined nonce is returned but never stored, so it signs in nobody; a custom `GetNonce` value still enters the nonce history. A declined spend answers `UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE` and keeps the nonce usable. Records never carry the nonce and name no owner. Contact email reservations run no hooks, and `New` still refuses user create hooks and account hooks with this plugin. [Wallet nonce hooks on SQL engines](../adapters/sqlstore/siwe_hooks_test.go)

Each EOA chain association has its own account record. The first successful signature for an address creates a local user. Further signatures for that address on permitted chains return the same user. A closed registration policy allows existing wallets to sign in. The server checks account bans before issuing the session. Unlinking a chain removes that association. A signer who still has another association for the same address can authenticate again on any allowed chain.

New wallet accounts receive an unverified placeholder email at `siwe.placeholder.invalid`. Set `EmailDomainName` to a dedicated non-deliverable domain to customize this namespace. Wallet ownership comes from the signature. In the default mode the server validates an optional email in the verification body and uses the generated placeholder. If an existing account already uses the generated placeholder, registration returns HTTP 409 and preserves its owner.

## Require a contact email

Set `siwe.Options{Domain: "wallet.example.com", RequireEmail: true}` to require an `email` string on every `POST /siwe/verify`. The native client exposes `VerifySIWEWithEmail(ctx, message, signature, email)`. An omitted or malformed email returns HTTP 400 before spending the signed nonce. The server accepts ASCII contact addresses up to 254 bytes and lowercases them.

For a new wallet, the SQL adapter tries to reserve the address for one minute. If available at commit, the new user receives it with `emailVerified: false`. A busy, expired or unavailable reservation and an already registered address produce the same successful wallet sign-in using its placeholder. Addresses matching the configured wallet placeholder format remain reserved for their own wallet. On MySQL a contact whose reservation identifier exceeds the canonical 255-byte column also uses the placeholder. Inspect `GetSession` for the stored email. Returning wallets keep their original profile, including when they sign on a new chain.

The signature proves control of the wallet. Treat the email as unverified until your mailbox-verification flow succeeds. Explicit email verification confirms the address for the account named in the verification message and preserves its existing sign-in methods. When a mailbox holder signs into an unverified account through a magic link or an email sign-in code, Plain Auth retires the old wallet associations and sessions in the same transaction as the verified sign-in. The mailbox holder keeps the account’s configured user fields. The new session receives its own configured defaults. A failed session insert rolls back the promotion and leaves the proof available for retry. The signer can subsequently register an independent wallet account. Apply the wallet-aware SQL adapter on every node that performs this passwordless promotion.

Custom wallet stores enabling this mode implement `siwe.ContactStore`. Acquire the short-lived contact claim before the host profile lookup, recheck its owner and lifetime in the account-creation transaction, and release only the exact claim that was issued. Select the user by the signed wallet address and applicable chain. Look up a contact only to decide whether it is available.

## Application callbacks

Set these functions on `siwe.Options` before constructing the plugin. Each receives the request context. Run remote services with a timeout and pass the context through to their clients. Signature and profile callbacks run outside SQL transactions.

| Option | Contract |
| --- | --- |
| `GetNonce(ctx)` | Return a cryptographically unpredictable, globally unique string containing 8 to 250 ASCII letters or digits. Both nonce endpoints return that exact value. An invalid or previously issued value fails the request with HTTP 500. |
| `VerifyMessage(ctx, args)` | Return `true, nil` only after authenticating the original message and signature for `args.Address` on `args.ChainID`. A configured verifier makes the final decision for every signature. `args.SignedBy(args.Address)` performs standard local EOA recovery. |
| `ENSLookup(ctx, args)` | Return display data for the authenticated `WalletAddress` and `ChainID` when creating a user. An empty name uses the wallet address. An avatar may be an HTTPS or IPFS URI. Later sign-ins preserve the stored profile. |

The verifier receives the checksummed address, chain ID, original message and signature, and CACAO context with the configured domain and consumed nonce. The server validates the signed domain, URI, chain policy, nonce, issuance time and any signed time bounds before calling it. A negative verdict, callback error or panic fails verification and burns the challenge. Cancellation or expiry while the verifier or resolver runs prevents account and session creation. Concurrent first sign-ins can each call the resolver. The winning registration supplies the persisted display data.

For a contract wallet, select a trusted RPC client for the signed chain and ask the contract at the signed address to validate the signature over the EIP-191 hash of the original message. ERC-1271 specifies the success value `0x1626ba7e`. The application supplies the RPC service and its verification policy. The plugin ships local EOA verification. [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) · [EIP-4361](https://eips.ethereum.org/EIPS/eip-4361)

An accepted proof that cannot recover the address as an EOA uses a chain-bound account subject, `contract:<chainId>:<checksummedAddress>`, and a placeholder email with a `+<chainId>` suffix. Two contracts at the same address on different networks get independent identities. Contract subjects live in the `account` table. The `walletAddress` table retains EOA associations, allowing EOA-only nodes to continue authenticating those identities safely.

When a custom generator is installed, the SQL adapter creates `plainauth_siwe_nonce_digest` under its migration lock and imports outstanding wallet challenges. All updated SQL issuers using that database reserve a SHA-256 digest for each new nonce. Preserve this history through backups and upgrades. Deploy updated issuers before enabling a custom generator and select a fresh nonce namespace for values previously issued by legacy or external implementations. Their already-consumed values cannot be reconstructed from the verification table. Each new challenge contributes one permanent 32-byte digest plus database overhead.

Custom stores can implement `siwe.CustomNonceStore` for nonce generation, `siwe.CallbackStore` for timed consumption, and `siwe.ContractStore` to resolve a contract owner on its signed chain. Store initialization verifies the interfaces needed by the enabled callbacks. With verification hooks, a custom store also implements `siwe.NonceFinder` for delete hooks and `siwe.NonceHistoryStore` for create before hooks with `GetNonce`, and stores each nonce under `siwe.NonceRecordID(nonce)`.

Hosts supply their own ERC-1271 and ENS services. The integration tests use local signers and resolver fixtures. [Feature checklist](parity/plugins/siwe.md)

## Map an existing wallet schema

Use one declaration for schema generation, the SQL store and the wallet plugin. Set any subset of `Table`, `UserID`, `Address`, `ChainID`, `IsPrimary` and `CreatedAt`. Omitted names keep their defaults. The primary key is always `id`.

```go
layout := siwe.Schema{
    Table: "wallet_address", UserID: "user_id", Address: "wallet_address",
    ChainID: "chain_id", IsPrimary: "is_primary", CreatedAt: "created_at",
}
profiles := []string{"siwe"}
database := schema.Options{Wallet: layout}
ddl, err := schema.GenerateWithOptions("postgres", profiles, database)
if err != nil {
    return err
}
fmt.Print(ddl)
store, err := sqlstore.OpenWithOptions(ctx, "postgres", dsn, profiles, database)
if err != nil {
    return err
}
defer store.Close()
wallet, err := siwe.New(siwe.Options{Domain: "wallet.example.com", Schema: layout})
if err != nil {
    return err
}
// Use store and wallet when constructing the authentication server.
```

`sqlstore.CheckSchemaWithOptions(ctx, dialect, dsn, profiles, database)` checks the live columns without writing. Supply additional user and session fields in `database.AdditionalFields`. Names are portable ASCII SQL identifiers up to 63 bytes, starting with a letter or underscore and followed by letters, digits or underscores. The generator preserves the owner foreign key and derives its index name from the physical table and owner column. The wire fields, verification records and canonical account subjects remain the same.

Opening the same mapping again preserves populated records. When renaming existing storage, migrate the table, columns and owner index with your normal database migration before deploying the new declaration. Stop writers during that cutover and back up the database. The store checks an existing target’s expected columns and refuses to create an alternate wallet table when it detects established wallet accounts. A mapped database can also be opened by a server without wallet routes. Pass the same schema options there so mailbox promotion, credential unlinking and account deletion can clean up wallet rows. Go nodes compare the wallet associations with the canonical account subjects before authorizing cross-chain access or deleting established links.

Pass the same JSON declaration to `authctl generate`, `check` and `migrate` with `--wallet-schema FILE`. [Wallet schema commands](schema.md#configure-the-wallet-table)

A custom wallet adapter implements `siwe.MappingStore` to check the configured schema against its own physical layout. [Database configuration](databases.md)
