# Discover the OAuth or OpenID Connect issuer

A client that knows the issuer URL can discover the authorization, token, UserInfo and public key endpoints available on your server. Enable `oauthprovider.New`, install the `oauth-provider` database profile, and mount the handler returned by `plainauth.New` in your application. For signed access tokens, enable `plainauth.NewJWT` and install the `jwt` database profile. [Machine token setup](machine-tokens.md) · [Database setup](schema.md#oauth-authorization-server-tables)

An [extension](oauth-extensions.md) can add fields to these documents without replacing the provider's.

## Mount the discovery paths

For the issuer `https://accounts.example.com/api/auth`, clients fetch `https://accounts.example.com/.well-known/oauth-authorization-server/api/auth`. They can also append `/.well-known/oauth-authorization-server` to the issuer URL. For OpenID Connect, append `/.well-known/openid-configuration` to the issuer URL. An OpenID-enabled issuer serves the same JSON at all three paths. When the issuer is the origin itself, there is one path. The issuer is `JWTOptions.Issuer`, or the auth mount's public URL, serialized as a WHATWG URL (an ASCII lowercase host, a canonical IP literal, no default or empty port, dot segments resolved) without its query, fragment and one trailing slash, as another runtime publishes it. IPv4 shorthand such as `127.1` is kept as configured, where a WHATWG URL expands it. Tokens naming either that issuer or the configured spelling are accepted. Tokens this server signs name the published issuer, where another runtime stamps the configured spelling: a client compares `iss` with the discovered issuer exactly, so a configured trailing slash would fail every ID token. Introspection responses for opaque and refresh tokens report the published issuer too, where another runtime reports the configured spelling. [OAuth authorization-server metadata, RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html#section-3)

```go
func mount(mux *http.ServeMux, a *plainauth.Auth) {
    mux.Handle("/api/auth/", a)
    for _, path := range a.WellKnownPaths() {
        mux.Handle(path, a)
    }
}
```

With Gin, chi, Gorilla Mux, Echo, or Fiber, forward each discovery path outside the auth prefix to the same handler. The auth prefix already handles paths beneath it. Preserve the original request path. When `JWTOptions.Issuer` specifies a separate origin or path, publish the returned paths on that issuer's origin. The credential endpoints and the JWKS URL still point to the auth mount. Both the issuer and the public auth URL support HTTPS and local loopback HTTP. [Router examples](routers.md) · [Six-router discovery test](../integrations/routers/routers_test.go)

## Configure the advertised capabilities

```go
provider, err := oauthprovider.New(oauthprovider.Options{
    Scopes: []string{"reports:read", "reports:export"},
    Metadata: oauthprovider.IssuerMetadataOptions{
        Scopes:           []string{"reports:read"},
        TokenAuthMethods: []string{"private_key_jwt", "client_secret_post"},
        Headers:          http.Header{"Cache-Control": {"public, max-age=60"}},
    },
})
```

A machine-only issuer publishes `client_credentials`, configured machine scopes and an empty `response_types_supported` list. A browser issuer publishes `authorization_code`, the `code` response type, query response mode, S256 PKCE and its authorization endpoint. The server publishes the configured grants supported by its active routes and store, including delegated-only configurations. The token authentication list defaults to HTTP Basic, form credentials and, when the store can atomically consume assertions, `private_key_jwt`. Public clients use `none`. Open registration advertises it by default for delegated grants. A server with protected registration can opt in with `Metadata.TokenAuthMethods`. The issuer also publishes the verifier's configured DPoP algorithms when the store can bind tokens. The advertised scope and token authentication lists can describe a subset of these capabilities. The authorization checks still use each client's actual registration. [Machine scope management](oauth-client-registration.md#grant-machine-to-machine-scopes)

Enabling dynamic client registration adds `registration_endpoint`. The document includes introspection and revocation when those endpoints are enabled and the store implements them. `jwks_uri` reflects the JWT plugin's configured public key path, or its `RemoteJWKSURL`. A disabled endpoint is omitted. The document is available when the token endpoint can serve at least one configured grant. Set `Metadata.Disabled` to turn discovery off. Browser clients can also configure the authorization and token URLs directly. [Browser authorization](oauth-authorization-code.md) · [Feature checklist](parity/plugins/oauth-provider.md)

## Connect a relying party using the issuer URL

Enable the `openid` scope and the authorization-code grant, apply the OAuth provider and JWT database profiles and install both plugins. For example, a client configured with the issuer `https://accounts.example.com/tenant/acme` fetches `https://accounts.example.com/tenant/acme/.well-known/openid-configuration`. The credential endpoints in that document point to the auth mount, which may have a different path. Configure your router to serve the returned discovery paths on the issuer's origin. [OpenID Connect Discovery §4](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig) · [Mounting in Go routers](routers.md)

Use `github.com/coreos/go-oidc/v3/oidc` and `golang.org/x/oauth2` in a Go relying party. The client receives its registered client ID and callback URL separately from discovery.

```go
provider, err := oidc.NewProvider(ctx, issuerURL)
if err != nil {
    return err
}
cfg := oauth2.Config{
    ClientID: clientID, RedirectURL: callbackURL,
    Endpoint: provider.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "email"},
}
cfg.Endpoint.AuthStyle = oauth2.AuthStyleInParams // public client
```

Generate and save fresh state, nonce and a PKCE verifier for the login. Send the browser to `cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))`. On return, check the callback's state and issuer, then exchange the code using the saved verifier. Validate the returned ID token using `provider.Verifier(&oidc.Config{ClientID: clientID})`, check the saved nonce and call `idToken.VerifyAccessToken(token.AccessToken)`. Use `provider.UserInfo` with that access token and check that its subject matches the verified ID token. [Complete relying-party example and test](../plugins/oauthprovider/openid_metadata_test.go) · [ID-token claims](oauth-authorization-code.md#receive-and-verify-an-openid-connect-id-token)

Discovery describes the active signing algorithm, supported claim names and authentication context. A configured pairwise secret adds the pairwise subject type. Hosts choose their own interaction pages. The advertised prompts reflect the login, consent and account-selection pages configured on the server. Disabling a public JWKS or authorization endpoint removes OpenID discovery. Set `auth.JWTOptions.Algorithm` to `"RS256"` for clients that require that signing profile. Go server code can read the same document with `oauthprovider.GetOpenIDConfig(a)`. [Capability tests](../plugins/oauthprovider/openid_metadata_test.go) · [Five signing algorithms](../conformance/oauth-id-tokens.mjs)

## Read the document

```sh
curl --fail --silent --show-error \
  https://accounts.example.com/.well-known/oauth-authorization-server/api/auth
```

Check that `issuer` exactly matches the configured issuer before sending credentials to `token_endpoint`. A resource server can fetch keys from `jwks_uri` and verify a signed access token's signature, issuer, audience and expiry. It can use `introspection_endpoint` to check whether a grant is currently active. [Signed token verification](jwt.md) · [Introspection](machine-tokens.md#check-whether-a-token-is-active)

`GET` returns JSON. `HEAD` returns the same headers with an empty body. The default cache policy is `public, max-age=15, stale-while-revalidate=15, stale-if-error=86400`. Use `Metadata.Headers` for a different cache lifetime or to allow cross-origin browser reads. For native Go access, call `oauthprovider.GetAuthorizationServerConfig(a)` and handle `plainauth.ErrNotFound` when the issuer has no published document. To publish application-defined metadata on an additional route, `oauthprovider.NewMetadataResponse(value, headers)` returns an `http.Handler` with the same JSON and cache behavior. [Cross-runtime discovery and verification test](../conformance/oauth-issuer-metadata.mjs)
