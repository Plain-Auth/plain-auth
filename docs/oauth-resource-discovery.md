# OAuth protected-resource discovery

A Go API can publish a discovery document that tells OAuth clients which issuer protects the API and which scopes they can request. The `plugins/oauthprovider` package builds the document from application configuration and serves it through `http.Handler`. Token verification belongs in the protected API route. [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html)

## Mount the document

Use the public HTTPS URL of the API as the resource identifier. For `https://api.example.com/reports`, clients fetch `https://api.example.com/.well-known/oauth-protected-resource/reports`.

```go
import (
    "net/http"

    "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

func mountReportsMetadata(mux *http.ServeMux) error {
    discovery, err := oauthprovider.NewResourceDiscovery(oauthprovider.ResourceMetadata{
        Resource:               "https://api.example.com/reports",
        ResourceName:           "Reports API",
        AuthorizationServers:   []string{"https://accounts.example.com/auth"},
        ScopesSupported:        []string{"reports:read"},
        BearerMethodsSupported: []string{"header"},
        DPoPSigningAlgorithms:  []string{}, // This example API accepts bearer tokens.
    }, oauthprovider.DiscoveryOptions{
        ProviderScopes: []string{"reports:read", "reports:write"},
    })
    if err != nil {
        return err
    }
    mux.Handle(discovery.Path(), discovery)
    return nil
}
```

With Gin, use `router.Any(discovery.Path(), gin.WrapH(discovery))`. With Gorilla Mux or chi, use `router.Handle(discovery.Path(), discovery)`. Echo uses `router.Any(discovery.Path(), echo.WrapHandler(discovery))`, and Fiber uses `app.All(discovery.Path(), adaptor.HTTPHandler(discovery))`. The handler serves public GET, HEAD and CORS preflight requests. [Framework integration tests](../integrations/routers/routers_test.go)

`discovery.URL()` returns the complete public discovery URL. The path preserves escaped segments and removes one terminating slash before inserting the well-known prefix. A resource query is retained and matched exactly. For example, `https://api.example.com/files/?team=west` publishes at `https://api.example.com/.well-known/oauth-protected-resource/files?team=west`. If your router serves several resources distinguished by query on one path, dispatch that path to the corresponding handler. Use `json.Marshal(discovery)` when your application serves the JSON itself.

## Issuers, scopes and capabilities

- **Local issuer.** Supply the configured Plain Auth instance as `DiscoveryOptions.Auth` to default the resource to its public auth mount and the issuer to its explicit JWT issuer or, by default, that mount. Set `Resource` when the protected API has its own URL. Explicit `AuthorizationServers` takes precedence. The handler builds its document once at startup.
- **Separate services.** Set `Resource` and `AuthorizationServers` explicitly. For multiple issuers, put additional supported scopes in `ExternalScopes`. Every advertised scope must appear in the local or external list. The `openid` scope belongs to the authorization server. Supply an empty list to publish an explicit JSON array.
- **Proof of possession.** Set `DefaultDPoPSigningAlgorithms` to the algorithms your verifier accepts. The default list is EdDSA, ES256, ES512, PS256 and RS256. `ResourceMetadata.DPoPSigningAlgorithms` overrides it for an individual API. An empty list advertises no proof algorithms. Set `DPoPBoundAccessTokensRequired` to a pointer to true only when the API enforces that requirement.
- **Other metadata.** The document can publish a resource JWKS URL, response-signing algorithms, documentation and policy links, supported authorization detail types, and certificate-bound token capability. For localized or application-specific fields, use `DiscoveryOptions.Extra` with a language-tagged name such as `resource_name#fr` and a JSON string value. Standard fields use their typed Go options. [Metadata and validation tests](../plugins/oauthprovider/discovery_test.go)
