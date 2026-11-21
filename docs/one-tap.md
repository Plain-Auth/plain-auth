# Google One Tap

Use Google's browser prompt or sign-in button to create a local session. Register the site's origin as an authorized JavaScript origin for the Google web client. Use the same audience on every server that handles the prompt or callback. [Google setup guide](https://developers.google.com/identity/gsi/web/guides/get-google-api-clientid)

```go
google := providers.GoogleWithOptions(providers.GoogleOptions{
    ClientID:     googleClientID,
    ClientSecret: googleClientSecret,
    HostedDomain: "example.org",
})
options.SocialProviders = map[string]stonewrit.OAuthProvider{"google": google}
options.Plugins = append(options.Plugins, onetap.New(onetap.Options{}))
mux.HandleFunc("GET /assets/one-tap.mjs", onetap.BrowserModule)
```

Mount the auth handler and serve the optional browser module on the page's origin. For a One Tap-only installation, `onetap.Options{ClientID: googleClientID}` supplies the Google audience without a client secret. A configured Google provider also supports redirect sign-in and its own registration and hosted-domain settings. `HostedDomain` accepts one Workspace domain, or `"*"` for any Workspace account. The server checks the signed `hd` claim. An email's domain alone cannot satisfy the restriction. [Google ID token verification](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token)

```html
<div id="google-signin"></div>
<script type="module">
  import { startOneTap } from "/assets/one-tap.mjs";

  const signIn = await startOneTap({
    authPath: "/api/auth",
    button: {
      element: document.getElementById("google-signin"),
      options: { theme: "outline", size: "large" },
    },
    callbackURL: "/account",
  });
  await signIn.result;
</script>
```

Call `startOneTap` once per document. It fetches the server's audience and nonce, loads Google's Identity Services script, and initializes the browser API. The default requests a prompt. Supplying a button renders just the button. Add `showPrompt: true` to display both. The library loads Google's script from `https://accounts.google.com/gsi/client`. Set `scriptNonce` for a host Content Security Policy nonce. The browser and Google control prompt availability. `autoSelect`, `cancelOnTapOutside`, `context` and `onPromptNotification` configure supported prompt behavior. `cancel()` cancels the active prompt and pending callback. A successful `result` resolves with the user and session token. An optional same-origin `callbackURL` navigates after the server accepts the credential. [Google JavaScript API](https://developers.google.com/identity/gsi/web/reference/js-reference)

A custom UI starts with `POST /one-tap/nonce` from a trusted origin. Pass the returned `nonce` and `clientId` to Google's popup API. Submit its credential as JSON `{"idToken":"…"}` to `POST /one-tap/callback` from the same browser and origin. Both requests send cookies. The challenge cookie is HttpOnly, host-only and valid for five minutes. HTTPS also enables Secure and the `__Host-` prefix. The callback checks Google's signature, issuer, audience, authorized party, nonce, token age and expiration before applying account policy. The SQL transaction binds the Google subject to the account, consumes the browser nonce and ID token, and issues the session. Two distinct tokens issued for one browser challenge can create only one session.

Set `onetap.Options.DisableSignUp` to limit One Tap to existing users. The Google provider and global sign-up policies also apply. Previously linked accounts keep their Google subject as their identity if the email changes. Verified-email linking follows the configured provider policy.

## Host-issued nonces

If the host already renders its Google sign-in page, it can generate a fresh nonce on its own server and bind it to that browser before writing the response. Supply the configured page origin and Google audience.

```go
nonce := rand.Text() // crypto/rand
if err := auth.BindOneTapNonce(w, "https://app.example", googleClientID, nonce); err != nil {
    http.Error(w, "Unable to prepare sign-in", http.StatusInternalServerError)
    return
}
w.Header().Set("Cache-Control", "no-store")
// Pass nonce and googleClientID to this browser through your HTML template.
```

Provide the resulting values as `startOneTap({ clientId, nonce })`, as the Google SDK initialization nonce, or to an existing client that posts `{idToken}` on Google sign-in. A host can also supply `getChallenge({signal})` to fetch the two values from its own same-origin route. Host code generates the nonce for this request. Bind the nonce before the browser initializes Google. Each challenge expires after five minutes and can issue one session. A fresh binding replaces the browser’s previous challenge. Send an optional `nonceExpiresAt` or challenge `expiresAt` in Unix milliseconds to enforce an earlier browser timeout.

## Button redirects

Register a same-origin redirect URI in the Google console and mount the form receiver there. Choose a fixed destination on your application for successful sign-in.

```go
receiver, err := onetap.RedirectHandler("/api/auth", "/account")
if err != nil {
    return err
}
mux.Handle("POST /google/return", receiver)
```

```js
await startOneTap({
  uxMode: "redirect", redirectURI: "/google/return",
  button: { container: "#google-signin", config: { type: "standard" } },
});
```

The redirect mode applies to the Google sign-in button. The receiver checks the Google double-submit CSRF cookie and form token. Its non-cacheable page exchanges the credential on the application origin using the original HttpOnly challenge cookie. The protected callback issues the session, then the browser navigates to the destination configured on the receiver. Popup callbacks can use the `callbackURL` option. [Google redirect credential handling](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token)

## Retry and FedCM settings

`promptOptions.baseDelay` sets the initial retry delay in milliseconds. `maxAttempts` allows zero to ten retries after retryable dismissed notifications. The default allows five retries with a one-second initial delay and doubles the delay each time. Skipped and undisplayed moments end the prompt. An explicit cancellation or a returned credential ends retry scheduling. Google and the browser decide which moments are reported. A host can display its alternative sign-in flow in `onPromptNotification`.

`additionalOptions` accepts `color_scheme`, `prompt_parent_id`, `itp_support`, `login_hint`, `hd`, `use_fedcm_for_button` and `button_auto_select`. The server enforces the verified account's Workspace policy independently. The module controls the credential receiver, audience and nonce. `fetchOptions.headers` and `fetchOptions.signal` apply to same-origin auth requests.

Call `signOutOneTap()` to revoke the server session, disable Google's automatic selection and request `navigator.credentials.preventSilentAccess()` on supported FedCM browsers. Set `promptOptions.fedCM` to `false` to skip the browser's silent-access reset. Google and the browser manage FedCM for the prompt. [Google JavaScript API](https://developers.google.com/identity/gsi/web/reference/js-reference)

The local suite exercises signed credentials on three SQL engines, a host-issued challenge with the pinned browser client, and popup and redirect delivery in headless Chrome using local Google fixtures. Live Google accounts and browser-specific FedCM UI remain unverified. [Feature checklist](parity/plugins/one-tap.md)
