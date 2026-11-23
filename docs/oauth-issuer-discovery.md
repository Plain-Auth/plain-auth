# Discover the OAuth issuer

A machine client that knows your issuer URL can discover the token endpoint, accepted client authentication methods, and public signing keys. Enable `oauthprovider.New`, install the `oauth-provider` database profile, and mount the handler returned by `plainauth.New` in your application. For signed access tokens, enable `plainauth.NewJWT` and install the `jwt` database profile. [Machine token setup](machine-tokens.md) · [Database setup](schema.md#oauth-authorization-server-tables)

## Mount the discovery paths

For the issuer `https://accounts.example.com/api/auth`, clients fetch `https://accounts.example.com/.well-known/oauth-authorization-server/api/auth`. They can also append `/.well-known/oauth-authorization-server` to the issuer URL. Both paths return the same JSON. When the issuer is the origin itself, there is one path. [OAuth authorization-server metadata, RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html#section-3)

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

The issuer publishes `client_credentials`, configured machine scopes and an empty `response_types_supported` list. The token authentication list defaults to HTTP Basic, form credentials and, when the store can atomically consume assertions, `private_key_jwt`. The issuer also publishes the verifier's configured DPoP algorithms when the store can bind tokens. The advertised scope and token authentication lists can describe a subset of these capabilities. The authorization checks still use each client's actual registration. [Machine scope management](oauth-client-registration.md#grant-machine-to-machine-scopes)

Enabling dynamic client registration adds `registration_endpoint`. The document includes introspection and revocation when those endpoints are enabled and the store implements them. `jwks_uri` reflects the JWT plugin's configured public key path. A disabled endpoint is omitted. The document is available when the machine grant and token endpoint are enabled and the store supports issuance. Set `Metadata.Disabled` to turn discovery off. Browser clients can configure the authorization and token URLs directly. Advertising the browser grant and OpenID Provider discovery remain on the roadmap. [Browser authorization](oauth-authorization-code.md) · [Feature checklist](parity/plugins/oauth-provider.md)

## Read the document

```sh
curl --fail --silent --show-error \
  https://accounts.example.com/.well-known/oauth-authorization-server/api/auth
```

Check that `issuer` exactly matches the configured issuer before sending credentials to `token_endpoint`. A resource server can fetch keys from `jwks_uri` and verify a signed access token's signature, issuer, audience and expiry. It can use `introspection_endpoint` to check whether a grant is currently active. [Signed token verification](jwt.md) · [Introspection](machine-tokens.md#check-whether-a-token-is-active)

`GET` returns JSON. `HEAD` returns the same headers with an empty body. The default cache policy is `public, max-age=15, stale-while-revalidate=15, stale-if-error=86400`. Use `Metadata.Headers` for a different cache lifetime or to allow cross-origin browser reads. For native Go access, call `oauthprovider.GetAuthorizationServerConfig(a)` and handle `plainauth.ErrNotFound` when the issuer has no published document. To publish application-defined metadata on an additional route, `oauthprovider.NewMetadataResponse(value, headers)` returns an `http.Handler` with the same JSON and cache behavior. [Cross-runtime discovery and verification test](../conformance/oauth-issuer-metadata.mjs)
