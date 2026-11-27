# OAuth protected-resource discovery

A Go API can publish a discovery document that tells OAuth clients which issuer protects the API and which scopes they can request. The `plugins/oauthprovider` package builds the document from application configuration and serves it through `http.Handler`. Token verification belongs in the protected API route. [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html)

## Mount the document

Use the public HTTPS URL of the API as the resource identifier. For `https://api.example.com/reports`, clients fetch `https://api.example.com/.well-known/oauth-protected-resource/reports`. In development, a resource and its authorization servers may use HTTP on a loopback host, such as `http://localhost:3000/mcp`; HTTP elsewhere is refused, where another runtime accepts it for challenges.

```go
import (
    "net/http"

    "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
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

## Respond to a failed access-token check

Use `NewResourceChallenges` to send clients from a protected route to its discovery document. Your token verifier supplies the public failure message, status, and OAuth error code. A request that presents a DPoP token receives a DPoP challenge. A request with missing bearer credentials receives a metadata pointer and optional scope hints. A verified token with insufficient privileges can receive a challenge naming the scopes it lacks. [Bearer challenges, RFC 6750 §3](https://www.rfc-editor.org/rfc/rfc6750.html#section-3) · [DPoP challenges, RFC 9449 §7](https://www.rfc-editor.org/rfc/rfc9449.html#section-7)

`Write` sends the challenge with a JSON body. To send your own body, `Prepare` returns the same status, `WWW-Authenticate` value and public error without writing, or nil for a permission denial or server failure, as another runtime's `createResourceServerChallenge` does. [Challenge tests](../plugins/oauthprovider/challenge_test.go)

This middleware accepts an application verifier that returns a zero status on success. An ordinary access denial uses status 403. For a scope failure, set status 403, code `insufficient_scope`, and `MissingScopes`. For an expired bearer token, set status 401 and code `invalid_token`.

```go
func protectReports(next http.Handler, verify func(*http.Request) (oauthprovider.ResourceFailure, error)) (http.Handler, error) {
    challenges, err := oauthprovider.NewResourceChallenges([]string{"https://api.example.com/reports"}, oauthprovider.ChallengeOptions{
        Scopes: []string{"reports:read"},
        DPoPSigningAlgorithms: []string{"ES256"},
    })
    if err != nil {
        return nil, err
    }
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        failure, err := verify(r)
        if err != nil {
            http.Error(w, "Token verification unavailable", http.StatusServiceUnavailable)
            return
        }
        if failure.Status == 0 {
            next.ServeHTTP(w, r)
            return
        }
        written, err := challenges.Write(w, r, failure)
        if written {
            return
        }
        if err != nil {
            http.Error(w, "Invalid challenge configuration", http.StatusInternalServerError)
            return
        }
        http.Error(w, http.StatusText(failure.Status), failure.Status)
    }), nil
}
```

| Verifier result | What the client receives |
| --- | --- |
| Missing bearer credentials | HTTP 401 with a Bearer challenge, a metadata URL for each protected resource, and any configured scope hint |
| Expired or invalid bearer token | HTTP 401 with `invalid_token` and the public description |
| Invalid DPoP proof or an expired DPoP token | HTTP 401 with a DPoP challenge and the verifier’s configured proof algorithms |
| Insufficient scopes | HTTP 403 with `insufficient_scope` and the missing scopes in the presented scheme |
| Ordinary permission denial or service failure | The application handles the original failure and status |

For an opaque identifier such as `urn:example:reports`, supply its public HTTPS URL in `ChallengeOptions.MetadataMappings`. Additional resources generate separate Bearer challenges in the configured order. Browsers can read `WWW-Authenticate` through the exposed response header when the host permits the requesting origin. The JSON error body retains the public description, and the response header formats it for HTTP. [HTTP comparison tests](../conformance/resource-challenges.mjs) · [Go TLS and configuration tests](../plugins/oauthprovider/challenge_test.go)

## Verify a sender-bound access token on a protected route

For signed access tokens, [`AccessTokenVerifier.VerifyRequest`](oauth-resource-server.md#verify-a-request) checks the token and its DPoP binding together. The lower-level `DPoPVerifier.CheckBinding` below suits tokens your API authenticates some other way.

First authenticate the access token using your issuer and check the audience, expiry and scopes required by this route. Read the sender key thumbprint from the authenticated token’s `cnf.jkt` claim or from the active introspection response. The client sends the literal access token in `Authorization: DPoP <access_token>` and a separate signed JWT in the `DPoP` header. [Proof verification in RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html#section-7)

Construct one verifier at startup. For multiple instances, use the same SQL database or the same Redis or Valkey namespace on every instance. The SQL adapter uses the core verification table and supports SQLite, PostgreSQL and MySQL. A single-process service can omit `ReplayStore` to keep reservations in memory for the verifier’s lifetime.

```go
proofs, err := oauthprovider.NewDPoPVerifier(oauthprovider.DPoPOptions{
    ReplayStore: store, // *sqlstore.Store or *redisstore.Store
})
if err != nil {
    return err
}
```

Call the verifier in your middleware after token validation. Pass the actual HTTP method and public URL. Configure the public origin at startup and preserve the external path if a trusted proxy rewrites it. The verifier excludes the query string, checks the signature and key thumbprint, and compares the signed `ath` claim with a hash of the presented token.

```go
func checkReportsProof(r *http.Request, proofs *oauthprovider.DPoPVerifier, verifiedThumbprint string) error {
    scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
    return proofs.CheckBinding(r.Context(), scheme, r.Header.Get("DPoP"), oauthprovider.DPoPProofRequest{
        Method: r.Method,
        URL: "https://api.example.com" + r.URL.EscapedPath(),
        AccessToken: token,
        ExpectedThumbprint: verifiedThumbprint,
    })
}
```

An ordinary bearer token uses an empty thumbprint. A bound token requires the DPoP scheme and a fresh proof. Each accepted proof reserves its key thumbprint, HTTP method, normalized target and proof ID together. Reuse returns a 401 OAuth error. Pass the status, code and public description from `*plainauth.OAuthError` to the resource challenge writer. If replay storage is unavailable, deny the request and return a service error. [Cross-runtime HTTP tests](../conformance/dpop-proofs.mjs)

The default proof lifetime is five minutes with up to five seconds of future clock skew. Configure `ProofMaxAge` and `SigningAlgorithms` on the verifier and advertise the same algorithms in resource metadata. For a custom token endpoint that must authenticate the sender before issuing a credential, call `Verify` with the request method and public token endpoint URL. It returns the validated public JWK and thumbprint for the issuer to bind to that credential. Issuance and refresh flows are tracked separately in the [OAuth provider checklist](parity/plugins/oauth-provider.md).
