# Use one OAuth callback for preview deployments

Register one redirect URI with the identity provider, such as `https://login.example.com/identity/callback/github`. A sign-in started at `https://review-42.example.com` uses that URI. The production application exchanges the authorization code and returns the encrypted result to the browser. The preview verifies the result, reads its own sign-in state, which the default database strategy makes single-use, and issues its own session. You can keep a separate database and signing keys for each environment.

## Configure the two applications

1. Register the production callback with your provider. Use the same auth mount path, provider ID, and OAuth client ID in both applications. Give production the provider credentials needed to exchange a code.
2. Configure each application’s public URL and session signing secret. Give production the exact preview origins it may return identities to. Only share the proxy secret with deployments whose code and operators you trust to assert identities. Use a separate trust group for previews that run third-party code.
3. Install the plugin on both applications and mount the resulting handler on each application's existing router. The example below builds options from the host's own configuration. `publicURL` identifies the current deployment. `sharedProxySecret` comes from the host's secret manager and must be at least 32 bytes. The production process receives `GITHUB_CLIENT_SECRET`.

```go
import (
    "os"

    "github.com/Plain-Org/plain-auth"
    "github.com/Plain-Org/plain-auth/plugins/oauthproxy"
    "github.com/Plain-Org/plain-auth/providers"
)

func newAuth(store plainauth.Store, publicURL, sharedProxySecret string) (*plainauth.Auth, error) {
    proxy, err := oauthproxy.New(oauthproxy.Options{
        ProductionURL: "https://login.example.com",
        CurrentURL:    publicURL,
        Secret:        sharedProxySecret,
    })
    if err != nil {
        return nil, err
    }
    return plainauth.New(plainauth.Options{
        Store:          store,
        BaseURL:        publicURL,
        BasePath:       "/identity",
        TrustedOrigins: []string{"https://review-42.example.com"},
        Plugins:        []plainauth.Plugin{proxy},
        SocialProviders: map[string]plainauth.OAuthProvider{
            "github": providers.GitHub(os.Getenv("GITHUB_CLIENT_ID"), os.Getenv("GITHUB_CLIENT_SECRET")),
        },
    })
}
```

Mount the instance at `/identity/` and configure `AUTH_SECRET` or `AUTH_SECRETS` separately on each deployment. [Router setup](routers.md) · [Signing secrets](environment.md)

## Start sign-in on the preview

```js
const response = await fetch("/identity/sign-in/social", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    provider: "github",
    callbackURL: "/dashboard",
    newUserCallbackURL: "/welcome",
    errorCallbackURL: "/sign-in",
  }),
});
if (!response.ok) throw new Error("Could not start sign-in");
const { url } = await response.json();
window.location.assign(url);
```

Production receives the provider's GET or form POST callback at `/identity/callback/github`. On a proxied flow it redirects the browser to `/identity/callback/github/oauth-proxy` on the preview. The preview requires the browser's original state cookie and consumes the pending sign-in once. With `OAuthStateStrategy` set to `OAuthStateCookie` the preview keeps the flow sealed in that cookie, and a captured copy can be replayed within `MaxAge`; keep the database strategy for previews. The alternative return path `/identity/oauth-proxy-callback` accepts the same authenticated result. Both paths are for the browser's return trip. The preview keeps its flow's [server context](social.md#carry-server-data-through-the-flow) and reads it on `/identity/callback/github/oauth-proxy`; production never receives it, and `OAuthStateFrom` reports false in production's hooks while its provider callbacks still read `OAuthAdditionalData`.

A first-time user reaches `/welcome`. A returning user reaches `/dashboard`. A provider refusal reaches `/sign-in?error=access_denied`. The same flow supports an existing user's `/identity/link-social` request and applies the preview's account linking policy. When the popup plugin is installed, the completion page posts the result to the initiating application's trusted opener. [Social account policies](social.md) · [Popup setup](oauth-popup.md)

Production sign-in uses its ordinary direct callback. An initiating request with a nonempty `X-Skip-OAuth-Proxy` header also selects the direct flow. A preview using this header needs its own accepted callback and the provider credentials required for that exchange.

## Configure origins, expiration and keys

| Option | Behavior |
| --- | --- |
| `ProductionURL` | Registered production origin. Defaults to `AUTH_URL`, then the auth instance’s public URL, which is the fallback with `DynamicBaseURL`. The auth mount comes from `BasePath`. |
| `CurrentURL` | Explicit public origin of this deployment. If omitted, the plugin checks the trusted request host, then a hosting-platform origin, then the configured public URL. Keep the public host intact when forwarding requests through a reverse proxy. |
| `MaxAge` | Maximum age of the encrypted return profile as a Go duration. Defaults to one minute. The initiating browser has ten minutes to complete authorization. |
| `Secret` | Dedicated shared proxy key. Without a dedicated key, the plugin uses the auth instance's configured encryption keys, which must then agree across the participating deployments. |
| `Secrets` | An ordered list of `plainauth.VersionedSecret` values. The first entry encrypts and all listed versions can decrypt. Configure either this list or `Secret`. |

Origins use HTTPS. Local HTTP works for loopback addresses, `localhost`, and its subdomains. Host discovery checks `VERCEL_URL` as a hostname, followed by `NETLIFY_URL`, `RENDER_URL`, `AWS_LAMBDA_FUNCTION_NAME`, `GOOGLE_CLOUD_FUNCTION_NAME`, and `AZURE_FUNCTION_NAME` when their values are valid public URLs. Set `CurrentURL` explicitly if the platform supplies only a function name.

To rotate a shared key, first distribute a ring that can read both versions to all participants. Once all can read the new key, promote it to the first entry everywhere. Retain the previous key long enough for pending authorizations and their return profiles to finish. Keep clocks synchronized and configure access logs to omit callback query strings. A party holding the proxy key can assert provider identities.

## Verify a deployment

Start a fresh sign-in from a trusted preview and inspect its auth requests. The provider's `redirect_uri` should identify production. Production sends a state it cannot verify, such as one sealed with another proxy key, to its own error page with `state_mismatch`, never to a preview. Once the browser returns, call `/identity/get-session` on the preview and confirm the expected email. The production database should have no new user, account or session for this flow. If a browser returns with `state_mismatch`, start sign-in again from the preview and check its public host and cookie settings. An expired return profile produces `payload_expired`.

The repository exercises independent production and preview databases on SQLite, PostgreSQL, and MySQL. Its Chrome tests exercise the cross-site navigation and the popup return to the opener. [Database tests](../adapters/sqlstore/oauth_proxy_test.go) · [Browser tests](../conformance/oauth-proxy.mjs)
