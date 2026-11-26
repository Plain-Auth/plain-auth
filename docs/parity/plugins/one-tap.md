# One tap

[Feature index](../README.md)

## Interfaces

- [ ] One tap endpoints, types and options
  - [ ] `GsiButtonConfiguration`
    - [x] Forward the button size option unchanged to Google's button renderer ([test](../../../conformance/one-tap-browser.test.mjs#L37))
    - [x] Forward the button theme option unchanged to Google's button renderer ([test](../../../conformance/one-tap-browser.test.mjs#L147))
  - [ ] `GoogleOneTapOptions`
    - [x] `clientId` ([test](../../../conformance/core.test.mjs#L643))
      - [x] Validate the configured browser audience against the host-issued challenge ([test](../../../conformance/core.test.mjs#L643))
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
      - [x] Refuse an untrusted callbackURL on the One Tap callback with 403 ([test](../../../adapters/sqlstore/onetap_test.go#L145))
    - [x] `onPromptNotification` ([test](../../../conformance/one-tap-browser.test.mjs#L13))
      - [x] Forward the Google prompt notification callback ([test](../../../conformance/one-tap-browser.test.mjs#L13))
    - [x] `nonce` ([test](../../../conformance/core.test.mjs#L643))
      - [x] Bind the Google prompt to the server-generated nonce ([test](../../../conformance/one-tap-browser.test.mjs#L13))
      - [x] Accept an application-generated nonce with an expiring HttpOnly browser binding ([test](../../../conformance/core.test.mjs#L643))
    - [x] `button` ([test](../../../conformance/one-tap-browser.test.mjs#L13))
      - [x] Render the selected button element with its visual options ([test](../../../conformance/one-tap-browser.test.mjs#L13))
    - [x] `autoSelect` ([test](../../../conformance/one-tap-browser.test.mjs#L13))
      - [x] Forward automatic account selection from the start call to the Google prompt ([test](../../../conformance/one-tap-browser.test.mjs#L13))
    - [x] `cancelOnTapOutside` ([test](../../../conformance/one-tap-browser.test.mjs#L13))
      - [x] Forward outside-click dismissal from the start call to the Google prompt ([test](../../../conformance/one-tap-browser.test.mjs#L13))
    - [x] `uxMode` ([test](../../../conformance/one-tap-browser.test.mjs#L13))
      - [x] Default to popup credential delivery when the start call names no mode ([test](../../../conformance/one-tap-browser.test.mjs#L13))
      - [x] Pass redirect mode with a pinned same-origin receiver ([test](../../../conformance/one-tap-browser.test.mjs#L132))
      - [x] Relay a redirect-mode credential form from the same-origin receiver to a stubbed callback and reach the success page in headless Chrome ([test](../../../plugins/onetap/redirect_test.go#L64))
    - [ ] `context`
      - [x] Forward the prompt context from the start call to the Google prompt ([test](../../../conformance/one-tap-browser.test.mjs#L13))
    - [ ] `additionalOptions`
      - [x] Forward allow-listed Google SDK options from the start call and reject receiver or nonce overrides ([test](../../../conformance/one-tap-browser.test.mjs#L132))
  - [ ] `oneTapClient`
    - [x] Submit a stubbed Google credential and send the HttpOnly browser cookie in headless Chrome ([test](../../../conformance/one-tap-browser.test.mjs#L65))
    - [x] Cancel without processing credentials from a delayed callback ([test](../../../conformance/one-tap-browser.test.mjs#L50))
    - [x] Sign in with a host-generated, browser-bound nonce using the pinned client ([test](../../../conformance/core.test.mjs#L643))
    - [x] Refuse a second start on the same page while a prompt is active ([test](../../../conformance/one-tap-browser.test.mjs#L42))
    - [x] Render a sign-in button in a selector-addressed container without showing the prompt ([test](../../../conformance/one-tap-browser.test.mjs#L138))
    - [x] Retry a dismissed prompt and stop on a later skip, passing it to the notification callback ([test](../../../conformance/one-tap-browser.test.mjs#L113))
    - [x] Clear supported browser selection state only after the server revokes the session ([test](../../../conformance/one-tap-browser.test.mjs#L151))
  - [ ] `POST /one-tap/callback`
    - [x] Verify Google-issued claims with a local RSA signing key and enforce Workspace ownership ([test](../../../adapters/sqlstore/onetap_test.go#L149))
    - [x] Consume a browser challenge once, including concurrent tokens signed for the same nonce ([test](../../../adapters/sqlstore/onetap_test.go#L164))
    - [x] Preserve Google subject ownership after an email change ([test](../../../adapters/sqlstore/onetap_test.go#L174))
    - [x] Expire browser proof before verifying a credential ([test](../../../onetap_test.go#L45))
    - [x] Require the application-issued nonce and reject a replay from the pinned client ([test](../../../conformance/core.test.mjs#L643))
    - [x] Require the Google CSRF cookie and escape the relay document for redirect submissions ([test](../../../plugins/onetap/redirect_test.go#L19))
    - [x] Apply the provider policy on direct sign-in, Google One Tap and permitted automatic links across three SQL engines ([test](../../../adapters/sqlstore/oauth_profile_sync_test.go#L16))
    - [x] Check the exact local mailbox before issuing a session on direct ID-token and One Tap sign-in across all SQL engines ([test](../../../adapters/sqlstore/oauth_verified_email_test.go#L18))
    - [x] Refuse an untrusted callbackURL with 403 ([test](../../../adapters/sqlstore/onetap_test.go#L145))
    - [x] Answer 401 when a new Google subject's email belongs to an existing unlinked account ([test](../../../adapters/sqlstore/onetap_test.go#L191))
  - [x] `OneTapOptions` ([test](../../../onetap_test.go#L37))
    - [x] Use the explicitly configured audience for the browser challenge ([test](../../../onetap_test.go#L37))
    - [x] Issue the browser challenge for the Google provider's audience when the plugin sets none ([test](../../../adapters/sqlstore/onetap_test.go#L109))
    - [x] Refuse a new Google subject when the plugin disables sign-up and still sign in a returning one ([test](../../../adapters/sqlstore/onetap_test.go#L167))
    - [x] `disableSignup` ([test](../../../adapters/sqlstore/onetap_test.go#L167))
      - [x] Restrict new registrations while allowing a returning Google subject ([test](../../../adapters/sqlstore/onetap_test.go#L167))
    - [x] `clientId` ([test](../../../onetap_test.go#L37))
      - [x] Accept the explicitly configured audience and require an audience before issuing a challenge ([test](../../../onetap_test.go#L37))
  - [x] `oneTap` ([test](../../../adapters/sqlstore/onetap_test.go#L27))
    - [x] Install the plugin with a Google provider and sign in through its challenge and callback routes on SQLite, PostgreSQL and MySQL ([test](../../../adapters/sqlstore/onetap_test.go#L27))

## One Tap

- [ ] One Tap
  - [x] Sign in to Go through the pinned One Tap client with a host-issued nonce and a locally signed Google credential ([test](../../../conformance/core.test.mjs#L665))
  - [x] Complete a stubbed prompt sign-in with the bundled browser module in headless Chrome ([test](../../../conformance/one-tap-browser.test.mjs#L65))
