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

## Authenticate clients with an assertion

An extension's `ClientAuthentication` adds `token_endpoint_auth_method` values, keyed by method name. Each `ClientAuthenticationStrategy` lists its `AssertionTypes`, absolute URIs that default to the method name, and an `Authenticate` callback. A request whose `client_assertion_type` is one of them is handed to the callback with the assertion, the form's `client_id` and `ExpectedAudience`, the public URL of the endpoint serving it: `/oauth2/token`, `/oauth2/introspect` or `/oauth2/revoke`. It runs before any store call and outside store transactions, and returns the client it proved, which must still be registered for that method. An `*auth.OAuthError` it returns is the answer, so a 401 `invalid_client` gets `WWW-Authenticate`; any other error is a server error.

```go
extension := oauthprovider.Extension{ClientAuthentication: map[string]oauthprovider.ClientAuthenticationStrategy{
    "workload_identity": {
        AssertionTypes: []string{"urn:example:workload-assertion"},
        Authenticate: func(ctx context.Context, in oauthprovider.ClientAuthenticationInput) (oauthprovider.ClientAuthenticationResult, error) {
            id, err := verifyWorkload(ctx, in.Assertion, in.ExpectedAudience)
            if err != nil {
                return oauthprovider.ClientAuthenticationResult{}, &plainauth.OAuthError{Status: 401, Code: "invalid_client", Description: "invalid assertion"}
            }
            return oauthprovider.ClientAuthenticationResult{ClientID: id}, nil
        },
    },
}}
```

`New` refuses a method that is empty, one of the built-in ones, without `Authenticate`, or defined twice, and an assertion type that is not an absolute URI, is the JWT bearer type or is claimed twice. Clients register the method like any other and get no secret. Discovery lists extension methods after the built-in ones for the token, introspection and revocation endpoints, and `IssuerMetadataOptions.TokenAuthMethods` may name them. A form `client_id` that differs from the proven client is refused with 400 `invalid_client`, as for `private_key_jwt`, where another runtime takes the strategy's value. The callback gets a copy of the request headers rather than the whole request. A `Confirmation` it returns is kept for grants that forward it; the built-in grants ignore it, as in another runtime. [Extension authentication tests](../adapters/sqlstore/oauth_extension_auth_test.go) · [Option checks](../plugins/oauthprovider/extension_auth_test.go)

After verifying the signature, a strategy should bind the audience, bound the lifetime and refuse a replayed `jti` ([RFC 7523 §3](https://datatracker.ietf.org/doc/html/rfc7523#section-3)). `in.ConsumeClientAssertion(ctx, namespace, payload)` does all three with the verified JSON payload, under the provider's `Assertions.MaxLifetime` and `ClockTolerance`:

- `aud`, a string or an array, must include `ExpectedAudience`;
- `exp` must be a number, unexpired and at most the lifetime away; `iat`, when a number, must be at most the lifetime old;
- `nbf`, when a number, must not be in the future; another runtime leaves this check to the strategy;
- `jti` must be a non-empty string, spent once under the namespace until `exp` plus the tolerance.

Each refusal is 400 `invalid_client` with another runtime's description, and a replay is "client assertion jti has already been used". Name the namespace after the method and the client, such as `"workload_identity:" + id`, so the same `jti` may recur under another method or client but never within one; `private_key_jwt` spends under `"private_key_jwt:" + clientID` in the same table. The store must implement `oauthprovider.ClientAssertionReplayStore`, which the SQL adapter does with one insert into `oauthClientAssertion`, shared by every instance on the database; otherwise the call returns 501 `OAUTH_ASSERTION_STORE_UNAVAILABLE`. [Claim checks](../plugins/oauthprovider/client_assertion_test.go) · [Replay test](../adapters/sqlstore/oauth_extension_auth_test.go)
