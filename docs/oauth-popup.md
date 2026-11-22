# OAuth popup sign-in

A popup lets someone complete social sign-in while the application stays on its current page. It also supports an application embedded in a cross-site iframe. The provider sees a top-level browser window, so its normal authorization screen and first-party state cookies work.

## Configure the server

Register the popup plugin alongside your OAuth provider. For embedded apps, install the bearer plugin with signature verification. The opener’s origin must match the auth server’s own origin or one of its trusted origins.

```go
import (
    "net/http"

    "github.com/Plain-Auth/plain-auth"
    "github.com/Plain-Auth/plain-auth/plugins/bearer"
    "github.com/Plain-Auth/plain-auth/plugins/oauthpopup"
)

// opts already contains the store, secret, public BaseURL and SocialProviders.
opts.TrustedOrigins = append(opts.TrustedOrigins, "https://app.example.com")
opts.Plugins = append(opts.Plugins, oauthpopup.New(), bearer.New(bearer.Options{RequireSignature: true}))
auth, err := plainauth.New(opts)
if err != nil {
    return err
}
mux.Handle("/api/auth/", auth)
mux.HandleFunc("/assets/oauth-popup.mjs", oauthpopup.BrowserModule)
```

Serve the module from the application origin, including when the auth handler lives on a different host. For cross-origin API access, configure the host’s CORS middleware to allow the explicit application origin, credentials, and the `Authorization` and `Content-Type` request headers. An opener that sets COOP must allow the popup relationship, for example with `Cross-Origin-Opener-Policy: same-origin-allow-popups`. A strict opener policy on the callback can sever that relationship. A sandboxed iframe needs permission to open popups and to use its own origin.

## Start and confirm a session

```js
import {createPopupClient} from "/assets/oauth-popup.mjs";

const auth = createPopupClient({
  baseURL: "https://auth.example.com/api/auth",
  onSession: ({user}) => { username.textContent = user.name; },
});
signInButton.addEventListener("click", async () => {
  const {error} = await auth.signIn.popup({
    provider: "github",
    callbackURL: "/account",
    newUserCallbackURL: "/welcome",
  });
  if (error) statusMessage.textContent = error.message;
});
signOutButton.addEventListener("click", () =>
  auth.fetch("/sign-out", {
    method: "POST", headers: {"Content-Type": "application/json"}, body: "{}",
  })
);
```

Call `signIn.popup` directly from the click handler so the browser can open the window during the user gesture. The default window is centered and measures 500 by 600 pixels. Supply a `windowFeatures` string to override it. A second attempt focuses the current popup. Pass an `AbortSignal` through `signal` to cancel waiting, or set `timeoutMs` to override the five-minute timeout. Closing the window cancels the local wait. A provider callback that already issued a session can still complete on the server.

Use `provider` or `providerId` for a configured social or custom OAuth provider. `scopes` adds to the provider’s defaults, and `requestSignUp` requests enrollment when the provider requires explicit consent to create a user. `callbackURL`, `newUserCallbackURL`, and `errorCallbackURL` must satisfy the server’s redirect policy. The completion message includes the selected successful destination. The browser helper keeps the opener on its current page and calls `onSession` after confirming the session. A rejected provider login returns its error code.

Pass small, non-secret application metadata in `additionalData`. It travels in the popup's navigation URL. The server accepts a JSON object of up to 8 KiB and makes it available to the configured provider’s exchange and profile callbacks through `plainauth.OAuthPopupAdditionalData(ctx)`. Treat these fields as browser input. The server discards reserved fields for account linking, PKCE, signup policy, destinations, and its own state.

## Custom host clients

The default message type is `plainauth:oauth-popup`. Go exposes the JSON wire structures as `oauthpopup.Data`, `oauthpopup.Message`, and `oauthpopup.Error`. A host integrating an existing client can use `oauthpopup.NewWithOptions(oauthpopup.Options{MessageType: "company.auth:oauth-popup"})` and set `messageType: "company.auth:oauth-popup"` when creating its browser client. Each half of a `namespace:event` identifier starts with an ASCII letter or digit, followed by up to 63 letters, digits, periods, underscores, or hyphens. The server binds the selected type into the opener marker during sign-in. The client pins one type for the configured mount and checks the same window, origin and nonce for every handoff.

## Browser and deployment behavior

The server authenticates a ten-minute opener cookie against the exact one-use OAuth state. It checks the opener’s origin again at callback time and sends the signed session credential by `postMessage` to that origin. The script’s hash appears in the completion page’s Content Security Policy. The response uses `Cache-Control: no-store`. The client checks the sending origin, window, message type, and random request nonce. Ordinary OAuth redirects retain their initial behavior. A second OAuth flow in another tab can supersede the browser’s state cookie.

At the top level, the browser confirms the signed-in user through the session cookie. Inside a cross-site iframe, it stores the signed bearer in that frame’s local storage, scoped to the auth origin and mount. Scripts running on that application origin can read the credential. Use `auth.fetch` for embedded API calls. It sends the bearer only to the configured auth mount, preserves an explicit authorization header, and rejects redirects. Failed handoffs clear the candidate credential. Successful sign-out, session revocation, or account deletion clears the saved bearer. `auth.getStoredPopupToken()` returns the current saved value or `null`. Embedded sign-in requires accessible local storage.

Local tests exercise top-level and embedded sign-in and sign-out in Chrome with a loopback identity provider. Browser privacy settings, live provider screens, Safari and Firefox remain deployment checks.
