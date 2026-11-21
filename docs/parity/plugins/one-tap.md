# One tap

[Feature index](../README.md)

## Interfaces

- [ ] One tap endpoints, types and options
  - [ ] `GsiButtonConfiguration`
  - [ ] `GoogleOneTapOptions`
    - [x] `clientId` ([test](../../../conformance/core.test.mjs#L638))
      - [x] Validate the configured browser audience against the host-issued challenge ([test](../../../conformance/core.test.mjs#L638))
    - [x] `autoSelect` ([test](../../../conformance/one-tap-browser.test.mjs#L13))
      - [x] Set automatic account selection ([test](../../../conformance/one-tap-browser.test.mjs#L13))
    - [x] `cancelOnTapOutside` ([test](../../../conformance/one-tap-browser.test.mjs#L13))
      - [x] Forward outside-click dismissal configuration ([test](../../../conformance/one-tap-browser.test.mjs#L13))
    - [x] `uxMode` ([test](../../../plugins/onetap/redirect_test.go#L64))
      - [x] Use popup credential delivery ([test](../../../conformance/one-tap-browser.test.mjs#L13))
      - [x] Deliver a redirect-mode form through the same first-party protected callback in headless Chrome ([test](../../../plugins/onetap/redirect_test.go#L64))
    - [x] `context` ([test](../../../conformance/one-tap-browser.test.mjs#L13))
      - [x] Set the prompt context ([test](../../../conformance/one-tap-browser.test.mjs#L13))
    - [ ] `additionalOptions`
      - [x] Forward vetted Google SDK options while protecting receiver and nonce controls ([test](../../../conformance/one-tap-browser.test.mjs#L132))
    - [ ] `promptOptions`
      - [x] Retry eligible dismissals with a bounded backoff and stop on FedCM skips ([test](../../../conformance/one-tap-browser.test.mjs#L113))
      - [x] Clear supported browser selection state after successful sign-out ([test](../../../conformance/one-tap-browser.test.mjs#L151))
  - [ ] `GoogleOneTapActionOptions`
    - [ ] `fetchOptions`
      - [x] Keep authentication fetches on the configured origin ([test](../../../conformance/one-tap-browser.test.mjs#L13))
    - [ ] `callbackURL`
      - [x] Navigate to the validated same-origin URL after a successful callback ([test](../../../conformance/one-tap-browser.test.mjs#L13))
    - [x] `onPromptNotification` ([test](../../../conformance/one-tap-browser.test.mjs#L13))
      - [x] Forward the Google prompt notification callback ([test](../../../conformance/one-tap-browser.test.mjs#L13))
    - [x] `nonce` ([test](../../../conformance/core.test.mjs#L638))
      - [x] Bind the Google prompt to the server-generated nonce ([test](../../../conformance/one-tap-browser.test.mjs#L13))
      - [x] Accept an application-generated nonce with an expiring HttpOnly browser binding ([test](../../../conformance/core.test.mjs#L638))
    - [x] `button` ([test](../../../conformance/one-tap-browser.test.mjs#L13))
      - [x] Render the selected button element with its visual options ([test](../../../conformance/one-tap-browser.test.mjs#L13))
  - [ ] `oneTapClient`
    - [x] Submit a stubbed Google credential and send the HttpOnly browser cookie in headless Chrome ([test](../../../conformance/one-tap-browser.test.mjs#L65))
    - [x] Cancel without processing credentials from a delayed callback ([test](../../../conformance/one-tap-browser.test.mjs#L50))
    - [x] Sign in with a host-generated, browser-bound nonce using the pinned client ([test](../../../conformance/core.test.mjs#L638))
  - [ ] `POST /one-tap/callback`
    - [x] Verify Google-issued claims with a local RSA signing key and enforce Workspace ownership ([test](../../../adapters/sqlstore/onetap_test.go#L149))
    - [x] Consume a browser challenge once, including concurrent tokens signed for the same nonce ([test](../../../adapters/sqlstore/onetap_test.go#L164))
    - [x] Preserve Google subject ownership after an email change ([test](../../../adapters/sqlstore/onetap_test.go#L174))
    - [x] Expire browser proof before verifying a credential ([test](../../../onetap_test.go#L45))
    - [x] Require the application-issued nonce and reject a replay from the pinned client ([test](../../../conformance/core.test.mjs#L638))
    - [x] Require the Google CSRF cookie and escape the relay document for redirect submissions ([test](../../../plugins/onetap/redirect_test.go#L19))
  - [ ] `OneTapOptions`
    - [x] `disableSignup` ([test](../../../adapters/sqlstore/onetap_test.go#L167))
      - [x] Restrict new registrations while allowing a returning Google subject ([test](../../../adapters/sqlstore/onetap_test.go#L167))
    - [x] `clientId` ([test](../../../onetap_test.go#L37))
      - [x] Accept the explicitly configured audience and require an audience before issuing a challenge ([test](../../../onetap_test.go#L37))
  - [ ] `oneTap`

## One Tap

- [ ] One Tap
