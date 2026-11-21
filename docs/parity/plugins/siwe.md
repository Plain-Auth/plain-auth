# Sign in with Ethereum

[Feature index](../README.md)

## Interfaces

- [ ] Sign in with Ethereum endpoints, types and options
  - [ ] `siweClient`
  - [ ] `/siwe/nonce`
  - [ ] `/siwe/get-nonce`
  - [ ] `POST /siwe/verify`
  - [ ] `SIWEPluginOptions`
    - [ ] `domain`
    - [ ] `emailDomainName`
    - [ ] `anonymous`
    - [ ] `getNonce`
    - [ ] `verifyMessage`
    - [ ] `ensLookup`
    - [ ] `schema`
  - [ ] `siwe`
  - [ ] `WalletAddress`
  - [ ] `SIWEVerifyMessageArgs`
  - [ ] `ENSLookupArgs`
  - [ ] `ENSLookupResult`

## Sign In With Ethereum (SIWE)

- [ ] Sign In With Ethereum (SIWE)
  - [ ] Usage
    - [ ] Generate a Nonce
    - [ ] Sign In with Ethereum
    - [ ] Chain-Specific Messages
  - [ ] Configuration Options
    - [ ] Server Options
      - [ ] domain
      - [ ] emailDomainName
      - [ ] anonymous
      - [ ] getNonce
      - [ ] verifyMessage
      - [ ] ensLookup
    - [ ] Client Options
  - [ ] Schema
    - [ ] id
    - [ ] userId
    - [ ] address
    - [ ] chainId
    - [ ] isPrimary
    - [ ] createdAt
  - [ ] Example Implementation
