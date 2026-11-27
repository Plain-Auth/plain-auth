# Model Context Protocol

The `plugins/mcp` package protects a Model Context Protocol server with the OAuth provider's access tokens, as another runtime's MCP package does. [Protect your API](oauth-resource-server.md) · [Feature checklist](parity/plugins/mcp.md)

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
