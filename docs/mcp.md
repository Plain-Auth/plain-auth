# Model Context Protocol

The `plugins/mcp` package protects a Model Context Protocol server with the OAuth provider's access tokens, as another runtime's MCP package does. [Protect your API](oauth-resource-server.md) · [Feature checklist](parity/plugins/mcp.md)

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
