# Sign in with Ethereum

[Feature index](../README.md)

## Interfaces

- [ ] Sign in with Ethereum endpoints, types and options
  - [x] `siweClient` ([test](../../../conformance/siwe-wallet.mjs#L28))
    - [x] Use both nonce aliases and sign in through the released client and a locally generated signing key ([test](../../../conformance/siwe-wallet.mjs#L28))
  - [x] `/siwe/nonce` ([test](../../../conformance/siwe-wallet.mjs#L35))
    - [x] Issue a random 15-minute challenge using either public client method ([test](../../../conformance/siwe-wallet.mjs#L35))
    - [x] Reject an expired stored nonce and clean it up at the next issuance ([test](../../../adapters/sqlstore/siwe_test.go#L145))
  - [x] `/siwe/get-nonce` ([test](../../../conformance/siwe-wallet.mjs#L35))
    - [x] Issue a random 15-minute challenge using either public client method ([test](../../../conformance/siwe-wallet.mjs#L35))
    - [x] Reject an expired stored nonce and clean it up at the next issuance ([test](../../../adapters/sqlstore/siwe_test.go#L145))
  - [ ] `POST /siwe/verify`
    - [x] Verify an Ethereum wallet signature, return the account and issue a session cookie ([test](../../../conformance/siwe-wallet.mjs#L53))
    - [x] Two simultaneous presentations of the same signed challenge issue one session ([test](../../../adapters/sqlstore/siwe_test.go#L174))
    - [x] Refuse a database account with an ambiguous wallet binding ([test](../../../adapters/sqlstore/siwe_test.go#L210))
  - [ ] `SIWEPluginOptions`
    - [x] `domain` ([test](../../../plugins/siwe/message_test.go#L9))
      - [x] Match the signed authority, scheme and URI including the relying-party port ([test](../../../plugins/siwe/message_test.go#L9))
    - [x] `emailDomainName` ([test](../../../adapters/sqlstore/siwe_test.go#L281))
      - [x] Apply a configured placeholder domain without verifying the user’s email ([test](../../../adapters/sqlstore/siwe_test.go#L281))
    - [ ] `anonymous`
      - [x] Establish a wallet-only identity and ignore contact email supplied in the signing request ([test](../../../conformance/siwe-wallet.mjs#L51))
    - [ ] `getNonce`
    - [ ] `verifyMessage`
    - [ ] `ensLookup`
    - [ ] `schema`
  - [ ] `siwe`
    - [x] Respect closed registration and refuse wallet sessions for a banned owner ([test](../../../adapters/sqlstore/siwe_test.go#L221))
    - [x] Delete the wallet credential when its owner unlinks or deletes the account ([test](../../../adapters/sqlstore/siwe_test.go#L246))
  - [x] `WalletAddress` ([test](../../../conformance/schema.test.mjs#L290))
    - [x] Match the table, all six fields, owner relationship and index in the three SQL dialects ([test](../../../conformance/schema.test.mjs#L290))
  - [ ] `SIWEVerifyMessageArgs`
  - [ ] `ENSLookupArgs`
  - [ ] `ENSLookupResult`

## Sign In With Ethereum (SIWE)

- [ ] Sign In With Ethereum (SIWE)
  - [ ] Usage
    - [x] Generate a Nonce ([test](../../../conformance/siwe-wallet.mjs#L35))
      - [x] Issue a random 15-minute challenge using either public client method ([test](../../../conformance/siwe-wallet.mjs#L35))
      - [x] Reject an expired stored nonce and clean it up at the next issuance ([test](../../../adapters/sqlstore/siwe_test.go#L145))
    - [ ] Sign In with Ethereum
      - [x] Verify an Ethereum wallet signature, return the account and issue a session cookie ([test](../../../conformance/siwe-wallet.mjs#L53))
      - [x] Two simultaneous presentations of the same signed challenge issue one session ([test](../../../adapters/sqlstore/siwe_test.go#L174))
      - [x] Refuse a database account with an ambiguous wallet binding ([test](../../../adapters/sqlstore/siwe_test.go#L210))
    - [x] Chain-Specific Messages ([test](../../../conformance/siwe-wallet.mjs#L58))
      - [x] A second signed chain for the same wallet keeps its local owner and creates a second association ([test](../../../conformance/siwe-wallet.mjs#L58))
  - [ ] Configuration Options
    - [ ] Server Options
      - [x] domain ([test](../../../plugins/siwe/message_test.go#L9))
        - [x] Match the signed authority, scheme and URI including the relying-party port ([test](../../../plugins/siwe/message_test.go#L9))
      - [x] emailDomainName ([test](../../../adapters/sqlstore/siwe_test.go#L281))
        - [x] Apply a configured placeholder domain without verifying the user’s email ([test](../../../adapters/sqlstore/siwe_test.go#L281))
      - [ ] anonymous
        - [x] Establish a wallet-only identity and ignore contact email supplied in the signing request ([test](../../../conformance/siwe-wallet.mjs#L51))
      - [ ] getNonce
      - [ ] verifyMessage
      - [ ] ensLookup
    - [x] Client Options ([test](../../../conformance/siwe-wallet.mjs#L28))
      - [x] Use both nonce aliases and sign in through the released client and a locally generated signing key ([test](../../../conformance/siwe-wallet.mjs#L28))
  - [x] Schema ([test](../../../conformance/schema.test.mjs#L290))
    - [x] Match the table, all six fields, owner relationship and index in the three SQL dialects ([test](../../../conformance/schema.test.mjs#L290))
    - [x] id ([test](../../../conformance/schema.test.mjs#L290))
      - [x] Match the generated wallet schema on SQLite, PostgreSQL and MySQL ([test](../../../conformance/schema.test.mjs#L290))
    - [x] userId ([test](../../../conformance/schema.test.mjs#L290))
      - [x] Match the generated wallet schema on SQLite, PostgreSQL and MySQL ([test](../../../conformance/schema.test.mjs#L290))
    - [x] address ([test](../../../conformance/schema.test.mjs#L290))
      - [x] Match the generated wallet schema on SQLite, PostgreSQL and MySQL ([test](../../../conformance/schema.test.mjs#L290))
    - [x] chainId ([test](../../../conformance/schema.test.mjs#L290))
      - [x] Match the generated wallet schema on SQLite, PostgreSQL and MySQL ([test](../../../conformance/schema.test.mjs#L290))
    - [x] isPrimary ([test](../../../conformance/schema.test.mjs#L290))
      - [x] Match the generated wallet schema on SQLite, PostgreSQL and MySQL ([test](../../../conformance/schema.test.mjs#L290))
    - [x] createdAt ([test](../../../conformance/schema.test.mjs#L290))
      - [x] Match the generated wallet schema on SQLite, PostgreSQL and MySQL ([test](../../../conformance/schema.test.mjs#L290))
  - [ ] Example Implementation
