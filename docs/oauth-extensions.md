# OAuth provider extensions

An extension adds a capability to the OAuth provider without changing its core. Pass extensions in `oauthprovider.Options.Extensions`; they apply in the order given.

## Add discovery fields

An extension's `Metadata` returns fields to add to a served discovery document, such as a `credential_issuer` for a wallet protocol. It runs once per document when the host starts, outside any store transaction, and receives a `MetadataInput`:

- `Type` is `MetadataOpenIDConfiguration` on every path while OpenID is advertised, since every path then serves the OpenID document. Otherwise it is `MetadataAuthorizationServer`.
- `Server` is the authorization-server metadata the provider assembled.
- `OpenID` is the OpenID document, set while OpenID is advertised; the RFC 8414 paths serve that same document then.

```go
wallet := oauthprovider.Extension{Metadata: func(in oauthprovider.MetadataInput) map[string]any {
    return map[string]any{"credential_issuer": in.Server.Issuer}
}}
issuer, err := oauthprovider.New(oauthprovider.Options{Extensions: []oauthprovider.Extension{wallet}})
```

Each extension sees the provider's document, not the fields earlier extensions added. As in another runtime, a field the provider defines is never replaced, and when two extensions return the same field the first one wins and a warning is logged. Every field the served document's type declares counts as the provider's, even when the document omits it, so an extension cannot advertise an endpoint the provider does not serve; another runtime likewise keeps the fields its document lists, set or not. The OpenID document also owns `end_session_endpoint`, and both documents own the back-channel logout flags. A field that cannot be encoded as JSON fails `auth.New`. Another runtime also passes the request context and provider options; this one publishes discovery when the host starts, so `Metadata` sees only the document. `GetAuthorizationServerConfig` and `GetOpenIDConfig` decode only the provider's own fields; `Auth.WellKnownJSON` returns the whole document. [Extension tests](../plugins/oauthprovider/issuer_metadata_test.go) · [Cross-runtime test](../conformance/oauth-extensions.mjs)

## Add access token claims

An extension's `AccessTokenClaims` contributes claims to signed resource access tokens. It receives a `TokenClaimsInput` with the client ID, granted scopes, grant type, requested resources and the client's metadata, and runs outside store transactions; an error fails the token request. Claims merge lowest first: each extension in order, where the first keeps a shared name and a warning is logged, then the host's `Tokens.CustomAccessTokenClaims`, then the resource's own claims. Claims the issuer owns, `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id`, `scope`, `auth_time`, `acr`, `amr` and `cnf`, are dropped with a warning, and the issuer writes `azp` and drops `sid` on a client token, as in another runtime. `nbf` is dropped with a warning too, where another runtime signs a contributed `nbf`: here the signer alone sets a token's validity window. `TokenClaimsInput` also names the client ID and grant type to `Tokens.CustomAccessTokenClaims`, where another runtime passes its host callback the user, scopes, resources and client metadata only. Another runtime also adds these claims when it introspects an opaque token; this one adds them to signed tokens only so far. [Resource token tests](../adapters/sqlstore/oauth_machine_resources_test.go)

## Add ID token and UserInfo claims

An extension's `IDTokenClaims` adds claims to ID tokens from code and refresh exchanges. It receives the account and its configured fields from the issuer's snapshot, the client ID, scopes, client metadata and grant type, and runs in the issue phase, outside store transactions; an error fails the exchange and leaves the code or refresh token usable. A claim is added only where the token has none, so `Tokens.CustomIDTokenClaims` and the issuer's own claims win, and reserved protocol claims and the standard `name`, `picture`, `given_name`, `family_name`, `email` and `email_verified` claims are never set; the first extension keeps a shared name with a warning. `UserInfoClaims` joins `UserInfo.Extensions` after the host's own list, with the same rules: standard claims win, the first contributor keeps a name and `UserInfo.CustomClaims` overrides. [ID token and UserInfo tests](../adapters/sqlstore/oauth_secret_id_token_test.go)
