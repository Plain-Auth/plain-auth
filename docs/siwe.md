# Sign in with Ethereum

A user signs an EIP-4361 message with an externally owned Ethereum account. Plain Auth verifies the signature locally and issues its ordinary session cookie. The server requires the configured application origin in the signed message and its URI. A bare authority such as `wallet.example.com` selects HTTPS. Include the port when it is part of the origin.

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
3. Send `POST /siwe/verify` with the exact `message` and its 65-byte hex `signature`. The JSON response contains `success`, the session `token`, and the user’s `id`, checksummed `walletAddress` and `chainId`. The Go HTTP client exposes `SIWENonce(ctx)` and `VerifySIWE(ctx, message, signature)`.

These paths are relative to the authentication mount. When verification receives a recognized challenge from the signed text, it consumes the challenge before evaluating the domain, chain, time bounds and signature. Request a fresh nonce after a failed verification.

Each chain association has its own account record. The first successful signature for an address creates a local user. Further signatures for that address on permitted chains return the same user. A closed registration policy allows existing wallets to sign in. The server checks account bans before issuing the session. Unlinking a chain removes that association. A signer who still has another association for the same address can authenticate again on any allowed chain.

New wallet accounts receive an unverified placeholder email at `siwe.placeholder.invalid`. Set `EmailDomainName` to a dedicated non-deliverable domain to customize this namespace. Wallet ownership comes from the signature. The server ignores an optional email in the verification body. If an existing account already uses the generated placeholder, registration returns HTTP 409 and preserves its owner.

Smart-contract wallets, remote signature verification, ENS profiles, mandatory contact email, custom nonce generation and custom database field mappings remain open. [Feature checklist](parity/plugins/siwe.md) · [EIP-4361](https://eips.ethereum.org/EIPS/eip-4361)
