# Model Context Protocol

The `plugins/mcp` package protects a Model Context Protocol server with the OAuth provider's access tokens, as another runtime's MCP package does. [Protect your API](oauth-resource-server.md) · [Feature checklist](parity/plugins/mcp.md)

## Run the provider for an MCP resource

`mcp.New` is the OAuth provider configured for an MCP resource, as another runtime's `mcp()` is. It takes the provider's options and the resource URL:

```go
provider, err := mcp.New(mcp.Options{
    Options: oauthprovider.Options{
        Scopes:        []string{"openid", "mcp:read", "mcp:write", "offline_access"},
        Authorization: oauthprovider.BrowserAuthorizationOptions{LoginPage: "/login", ConsentPage: "/consent"},
    },
    Resource: "https://api.example.com/mcp",
})
```

The resource is added to the provider's `Resources`, unless declared there already with a policy, and to `Registration.DefaultResources`, so registered clients are linked to it; the caller's options are not changed. `Tokens.RefreshReuseInterval` defaults to 30 seconds, as another runtime's MCP plugin defaults it, so a client that lost a refresh response can retry and get the same one; a negative value turns the window off, where another runtime uses 0, since a zero duration means unset in Go. Every other provider option reaches the provider unchanged, which a reflection test checks field by field, so an option the provider gains later is forwarded too. [Forwarding test](../plugins/mcp/forward_test.go) The plugin serves the RFC 9728 protected resource metadata at `/.well-known/oauth-protected-resource` and at that path plus the resource's path, such as `/.well-known/oauth-protected-resource/mcp`: the resource, the provider's issuer, `bearer_methods_supported: ["header"]`, the DPoP signing algorithms, `dpop_bound_access_tokens_required` when the declared resource requires DPoP, and the scopes from `Metadata.Scopes` or `Scopes` without `openid`, `profile`, `email`, `phone`, `address` and `offline_access`, which belong to the authorization server. Other methods than GET and HEAD get 405. The document is built once when the host starts, where another runtime builds it on each request. The plugin is the OAuth provider, so it cannot be combined with a second one. [Plugin tests](../plugins/mcp/plugin_test.go)

Client registration stays off unless you enable it. For older MCP clients that need dynamic registration, set `Registration.Enabled`, `Registration.AllowUnauthenticated` and `Registration.DefaultApplicationType: "infer"`: a client registered without the `resources` extension is still linked to the MCP resource, and one with loopback callbacks is registered as `native`. Unauthenticated registration lets anyone register a client with a name and logo they choose, so also set `Registration.DefaultScopes`. The provider seeds the declared resource when the host first uses it.

## Client flow

The plugin serves the provider's endpoints under the auth path:

| Endpoint | Path |
| --- | --- |
| Authorization | `/oauth2/authorize` |
| Token | `/oauth2/token` |
| Dynamic registration, when enabled | `/oauth2/register` |
| UserInfo | `/oauth2/userinfo` |

An MCP client authorizes with `resource` set to the MCP resource and PKCE, then exchanges the code with the same `resource`. The access token is an `at+jwt` whose `aud` holds the resource and whose `azp` is the client, which the route's guard checks. A resource the provider does not know, or one not linked to the client, gets `invalid_target` at authorize. When the guard answers 403 for a missing scope, the client authorizes again with the wider scope, which needs the user's consent. A refresh without `resource` keeps the resources of the grant. With `dpop_jkt` at authorize and a DPoP proof at the token endpoint, the token carries `cnf.jkt` and the guard asks for the `DPoP` scheme and a fresh proof. [Flow test](../adapters/sqlstore/oauth_mcp_flow_test.go)

## Protect an MCP route

When the MCP server runs in the same process as the auth instance, `mcp.RequireAuth` protects it with the instance's own tokens, as another runtime's `requireMcpAuth` does:

```go
handler, err := mcp.RequireAuth(auth, store, mcpServer, mcp.AuthOptions{RequiredScopes: []string{"mcp:read"}})
mux.Handle("/api/auth/mcp", handler)
```

- `Resource` defaults to the instance's public URL, base path included, which the provider names as the default resource, so a request without a token is pointed at `/.well-known/oauth-protected-resource/api/auth`. A resource must follow the rules below.
- `Issuer` defaults to the issuer the instance signs with, where another runtime uses its base URL, so a custom JWT issuer needs no override.
- Keys are read in process, even with `/jwks` in `DisabledPaths`, or from the jwt plugin's `RemoteJWKSURL`; `JWKSURL` fetches them over HTTP instead.
- Tokens must carry `azp`, so a session JWT signed with the same keys fails, and `typ` must be `at+jwt`.
- `DPoP.ReplayStore` defaults to `store` when it can hold proofs, such as the SQL store, so a proof is spent once across every instance on the database; the store is passed because the instance does not expose its own.
- `OnError` defaults to logging through the instance and answering 500. An instance without a public URL, such as one with a dynamic base URL, is refused here; use `NewProtectedHandler` with explicit options.

The route's claims and step-up work as below. [RequireAuth tests](../plugins/mcp/require_auth_test.go) · [Shared replay test](../adapters/sqlstore/oauth_mcp_test.go)

## Protect a remote MCP server

When the MCP server runs apart from the authorization server, wrap its HTTP handler with `mcp.NewProtectedHandler`:

```go
handler, err := mcp.NewProtectedHandler(mcp.ProtectedHandlerOptions{
    AccessTokenVerifierOptions: oauthprovider.AccessTokenVerifierOptions{
        Issuer:         "https://auth.example.com/api/auth",
        Audience:       []string{"https://api.example.com/mcp"},
        JWKSURL:        "https://auth.example.com/api/auth/jwks",
        RequiredClaims: []string{"azp"},
    },
    RequiredScopes: []string{"mcp:read"},
}, mcpServer) // any http.Handler, such as the Go MCP SDK's streamable handler
```

The options embed the [access token verifier's](oauth-resource-server.md): `Issuer`, `JWKSURL`, `Type`, `RequiredClaims`, `ScopeSatisfied`, `Remote` for introspection and `DPoP` for proofs. `Audience` must be exactly the MCP resource URL, which must use HTTPS, or HTTP on `localhost`, a `.localhost` name or a loopback IP in development, with no credentials, fragment or query; spaces, control characters and backslashes are refused too. Proofs name that URL's origin, or `Origin` when set.

Each request is checked with `VerifyRequest` and `RequiredScopes`. A rejected request gets the RFC 9728 challenge another runtime's `createMcpProtectedRequestHandler` sends, with `Access-Control-Expose-Headers: WWW-Authenticate`, and a JSON-RPC body:

```json
{"jsonrpc":"2.0","error":{"code":-32000,"message":"access token is missing required scope: mcp:read"},"id":null}
```

`ChallengeScopes` sets the scope hint for requests without a token; it defaults to `RequiredScopes`. Any other error, such as unreadable keys, goes to `OnError`, which answers 500 by default, where another runtime rethrows it.

A verified request reaches your handler, which reads the claims with `mcp.AccessTokenClaims(r.Context())`, where another runtime passes them as a second argument. To ask for more scopes for one operation, call `mcp.WriteInsufficientScope(w, r, "mcp:admin")`: it writes the 403 `insufficient_scope` challenge naming them, in the scheme the request used. Only that helper writes such a challenge, so a 403 your handler writes itself is sent unchanged.

DPoP proofs are spent in the verifier's replay store, which defaults to memory and is safe only for one long-lived instance. Behind several instances or on serverless, set `DPoP.ReplayStore` to the SQL store or a Redis store every instance shares. [Handler tests](../plugins/mcp/handler_test.go) · [Cross-runtime test](../conformance/mcp.mjs)
