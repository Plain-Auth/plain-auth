# Electron

[Feature index](../README.md)

## Interfaces

- [ ] Electron endpoints, types and options
  - `requestAuth` — *not applicable: JavaScript only*
  - `authenticate` — *not applicable: JavaScript only*
  - `kElectron` — *not applicable: JavaScript only*
  - `ElectronRequestAuthOptions` — *not applicable: JavaScript only*
  - `ElectronAuthenticateOptions` — *not applicable: JavaScript only*
    - `fetchOptions`
    - `token`
  - `handleDeepLink` — *not applicable: JavaScript only*
  - `electronClient` — *not applicable: JavaScript only*
  - [ ] `electron`
  - `setupRenderer` — *not applicable: JavaScript only*
  - `ExposedBridges` — *not applicable: JavaScript only*
  - `SetupRendererConfig` — *not applicable: JavaScript only*
    - `channelPrefix`
  - `electronProxyClient` — *not applicable: JavaScript only*
  - [ ] `POST /electron/token`
  - [ ] `GET /electron/init-oauth-proxy`
  - [ ] `POST /electron/transfer-user`
  - `storage` — *not applicable: JavaScript only*
  - `Storage` — *not applicable: JavaScript only*
  - `ElectronSharedClientOptions` — *not applicable: JavaScript only*
    - `protocol`
    - `callbackPath`
    - `clientID`
  - `ElectronClientOptions` — *not applicable: JavaScript only*
    - `signInURL`
    - `protocol`
    - `storage`
    - `storagePrefix`
    - `sanitizeUser`
    - `userImageProxy`
    - `cookiePrefix`
    - `channelPrefix`
    - `disableCache`
    - `callbackPath`
    - `clientID`
  - `ElectronProxyClientOptions` — *not applicable: JavaScript only*
    - `cookiePrefix`
    - `protocol`
    - `callbackPath`
    - `clientID`
  - [ ] `ElectronSharedOptions`
    - [ ] `clientID`
  - [ ] `ElectronOptions`
    - [ ] `codeExpiresIn`
    - [ ] `redirectCookieExpiresIn`
    - [ ] `cookiePrefix`
    - [ ] `clientID`
  - `fetchUserImage` — *not applicable: JavaScript only*
  - `normalizeUserOutput` — *not applicable: JavaScript only*
  - `FetchUserImageResult` — *not applicable: JavaScript only*
