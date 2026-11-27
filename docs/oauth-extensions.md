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

`New` refuses a method that is empty, one of the built-in ones, without `Authenticate`, or defined twice, and an assertion type that is not an absolute URI, is the JWT bearer type or is claimed twice. Clients register the method like any other and get no secret. Discovery lists extension methods after the built-in ones for the token, introspection and revocation endpoints, in extension order and sorted within one extension, since a Go map has no order, and `IssuerMetadataOptions.TokenAuthMethods` may name them. A form `client_id` that differs from the proven client is refused with 400 `invalid_client`, as for `private_key_jwt`, where another runtime takes the strategy's value. The callback gets a copy of the request headers rather than the whole request. A `Confirmation` it returns is kept for grants that forward it; the built-in grants ignore it, as in another runtime. [Extension authentication tests](../adapters/sqlstore/oauth_extension_auth_test.go) · [Option checks](../plugins/oauthprovider/extension_auth_test.go)

After verifying the signature, a strategy should bind the audience, bound the lifetime and refuse a replayed `jti` ([RFC 7523 §3](https://datatracker.ietf.org/doc/html/rfc7523#section-3)). `in.ConsumeClientAssertion(ctx, namespace, payload)` does all three with the verified JSON payload, under the provider's `Assertions.MaxLifetime` and `ClockTolerance`:

- `aud`, a string or an array, must include `ExpectedAudience`;
- `exp` must be a number, unexpired and at most the lifetime away; `iat`, when a number, must be at most the lifetime old;
- `nbf`, when a number, must not be in the future; another runtime leaves this check to the strategy;
- `jti` must be a non-empty string, spent once under the namespace until `exp` plus the tolerance.

Each refusal is 400 `invalid_client` with another runtime's description, and a replay is "client assertion jti has already been used". Name the namespace after the method and the client, such as `"workload_identity:" + id`, so the same `jti` may recur under another method or client but never within one; an empty namespace is refused as a server error, where another runtime spends it as `":" + jti`, so one client's `jti` cannot block another's; `private_key_jwt` spends under `"private_key_jwt:" + clientID` in the same table. The store must implement `oauthprovider.ClientAssertionReplayStore`, which the SQL adapter does with one insert into `oauthClientAssertion`, shared by every instance on the database; otherwise the call returns 501 `OAUTH_ASSERTION_STORE_UNAVAILABLE`. [Claim checks](../plugins/oauthprovider/client_assertion_test.go) · [Replay test](../adapters/sqlstore/oauth_extension_auth_test.go)

## Add a grant

An extension's `Grants` adds token endpoint grant types, keyed by absolute URI, such as `urn:ietf:params:oauth:grant-type:token-exchange`. A token request for one is handed to its `GrantHandler` after the form, `grant_type` and `resource` checks and before any credential is read, with `Cache-Control: no-store` already set. The handler runs in the endpoint, outside store transactions. Its `TokenResponse` is the answer: `Fields` adds members but never replaces `access_token`, `token_type`, `expires_in`, `expires_at`, `scope`, `refresh_token` or `id_token`, and an empty refresh or ID token is left out. An `*plainauth.OAuthError` it returns is the error answer, with `WWW-Authenticate` for a 401 `invalid_client`.

```go
extension := oauthprovider.Extension{Grants: map[string]oauthprovider.GrantHandler{
    "urn:example:grant": func(in oauthprovider.GrantInput) (oauthprovider.TokenResponse, error) {
        client, err := in.Provider.AuthenticateClient(oauthprovider.ClientAuthenticationRequest{Scopes: strings.Fields(in.Form.Get("scope"))})
        if err != nil {
            return oauthprovider.TokenResponse{}, err
        }
        return mintFor(in.Endpoint.Request.Context(), client, in.Form)
    },
}}
```

`in.Provider` is bound to the request and its grant type:

- `AuthenticateClient` reads the client's credentials as the built-in grants do, with the token endpoint as an assertion's audience, so a secret, `private_key_jwt` or an extension assertion works. It refuses a request without `client_id` (400 `invalid_request` "Missing required client_id") or without credentials (400 `invalid_client` "Missing required client credentials"), unless `AllowPublic` accepts a client registered for `none`. It then checks `Scopes` against the client's registered scopes (`invalid_scope` "client does not allow scope X"), where a client without registered scopes allows any, and requires the grant in the client's grant types (`unauthorized_client`), where none registered means `authorization_code` only.
- `Client(id)` returns a registered client, or nil when there is none.
- `HashToken(token, kind)` returns the stored form of a token the provider issued, so a handler can find or revoke one by its value.

`New` refuses a grant type that is not an absolute URI, has no handler, or is defined by two extensions; the built-in grant names are not URIs, so they cannot be replaced. Discovery's `grant_types_supported` and the token endpoint's OpenAPI `grant_type` list the extension grants after the configured ones, and client registration accepts them; `redirect_uris` stay required only with `authorization_code`. The provider API exists only inside a dispatched grant, where another runtime also offers it to other endpoints, since a Go plugin cannot reach another plugin's options at request time; `AllowPublic` is the Go form of turning `requireCredentials` off, and a handler closes over the options it needs rather than receiving them. [Grant tests](../adapters/sqlstore/oauth_extension_grant_test.go) · [Option checks](../plugins/oauthprovider/extension_auth_test.go)

### Issue client tokens

`in.Provider.IssueTokens` mints the access token for a client, as another runtime's `issueTokens` does without a user. It applies the resources' policy and checks the registration again, outside any host code, but does not check that `Scopes` were approved: the handler authorizes them, for example by passing them to `AuthenticateClient`.

```go
return in.Provider.IssueTokens(oauthprovider.TokenIssueParams{
    ClientID:  client.ClientID,
    Scopes:    strings.Fields(in.Form.Get("scope")),
    Resources: in.Form["resource"],
})
```

- The token has the client credentials lifetime and scope lifetimes. Without `Resources` it is opaque and stored, so introspection and revocation work as for `client_credentials`. With `Resources`, each must be registered, enabled and linked to the client unless `Tokens.AllowUnlinkedResources` is set; their allowed scopes narrow `Scopes`, their lifetimes cap the token's, and with the jwt plugin, unless `Tokens.OpaqueResourceTokens` or `DisableJWTPlugin` is set, the token is a signed `at+jwt` for them and, for `openid`, UserInfo. An unknown resource answers 400 `invalid_target` "requested resource X is not configured".
- `AccessTokenClaims` appear only in a signed token, above the extensions' `AccessTokenClaims` and below `Tokens.CustomAccessTokenClaims` and the resources' claims; the issuer's own claims, such as `client_id` and `cnf`, are never replaced. `TokenResponse` adds response members above `Tokens.CustomTokenResponseFields`, which sees the extension grant type.
- `Confirmation` binds the token and must name exactly one key: `JKT` makes it a DPoP token, and `X5TS256` keeps a certificate thumbprint as `cnf`. Without one, a DPoP proof on the request binds it. A client or resource that requires DPoP needs a DPoP key, from the confirmation or a proof, where another runtime accepts any confirmation.
- The client must still be enabled and registered for the grant, and when the handler called `AuthenticateClient`, its credentials must be unchanged; otherwise no token is stored.

A store without `oauthprovider.ResourceMachineTokenStore` answers 501. [Client token tests](../adapters/sqlstore/oauth_extension_grant_test.go)

### Issue user tokens

With `UserID`, `IssueTokens` issues the user's tokens as a code exchange does without a code, the handler having authenticated the user itself:

- The access token has the delegated lifetime and scope lifetimes and is stored with the user, `ReferenceID` and `RequestedUserInfoClaims`, kept for `openid` when the provider supports each claim. With `Resources` it follows the resources' policy, read outside the store's transaction, and with the jwt plugin it is a signed `at+jwt` for them and UserInfo.
- `SessionID`, when set, binds the tokens to that session, which must be the user's and live; `AuthTime` defaults to its start. Without a session the tokens outlive any sign-in.
- `openid` adds an ID token with the user's subject, pairwise for a pairwise client, `Nonce`, `AuthTime`, and `sid` for a client with logout enabled. `IDTokenClaims` are added where the token has none, above the extensions' `IDTokenClaims`; standard and profile claims are never set.
- `offline_access` adds a refresh token when the client's grant types allow refresh, `authorization_code` or `refresh_token`. It rotates through the `refresh_token` grant like any other.
- With `DisableJWTPlugin`, the ID token is keyed with the issued client's own secret: the one the handler authenticated that client with, or else its stored secret read back, `Registration.SecretPrefix` included. A client without a readable secret gets no ID token.
- The same bindings apply as for client tokens, on both tokens.
- `TokenIssueParams` leaves out the parent refresh token, code and stored code value that another runtime's built-in grants pass to the same call, which no extension grant needs.

The store must implement `oauthprovider.GrantTokenStore`, which the SQL adapter does; otherwise the call answers 501 `OAUTH_GRANT_TOKEN_STORE_UNAVAILABLE`. It reads the client, the user and any session in a transaction, makes the refresh token, ID token, signed access token and host fields outside it, and stores the tokens only if nothing changed meanwhile. A missing user answers 400 `invalid_user`, a session that is not the user's or has ended 400 `invalid_request` "session no longer exists", and a change during issuance 400 `invalid_request` "grant changed during issuance, retry the request". [User token tests](../adapters/sqlstore/oauth_extension_grant_test.go)

### Validate access tokens

`in.Provider.ValidateAccessToken(token, clientID)` returns an access token's introspection payload, which may be inactive, as another runtime's `validateAccessToken` does. With a `clientID` the token is seen as that client sees it at `/oauth2/introspect`, without authenticating it: active for the issuing client or a client linked to one of the token's resources, and inactive for any other, a client that is not registered included. Without one it is seen as the issuer sees it, through the lookup UserInfo uses. Opaque and signed tokens both work; `sub` is the account ID, not the pairwise subject introspection presents, as in another runtime, and a DPoP token's key is in `cnf`. A refresh token is never active, and an unknown token is inactive, where another runtime refuses it.

`in.Provider.RequireActiveAccessToken` returns an active token's payload and refuses any other with 401 `invalid_token` "Invalid access token" and `WWW-Authenticate: Bearer error="invalid_token", error_description="Invalid access token"`, exposed to browser clients. It checks the token, not the request: for a DPoP token, check the request's proof against `cnf.jkt` too. [Validation tests](../adapters/sqlstore/oauth_extension_grant_test.go)

## Resolve clients through a discovery

`Extension.ClientDiscoveries` resolve clients the provider has not registered, as another runtime's client discoveries do; the cimd package provides one for client ID metadata documents. Each discovery has an `ID`, stored on every client it saves, a `Matches` function and a `Resolve` function. `New` refuses an empty or repeated ID, across all extensions, and a discovery without `Matches` or `Resolve`; the store must be a `DiscoveredClientStore`.

When a request names a client ID that a discovery matches, the provider reads the stored row first. A local row is used as is, so a local client never reaches a discovery. A row a discovery owns goes back to that discovery's `Resolve`, with the row in `Existing`; when that discovery is no longer configured, no longer matches the ID or resolves nothing, the client stays hidden. An unknown ID goes to each matching discovery in order until one resolves it. `Resolve` stores the client through `req.Register`, under the document rules below, and an error it returns is the endpoint's. This happens at the token endpoint for every grant, at introspection and revocation, at authorize, consent and continue, at `/oauth2/public-client`, `/oauth2/get-client` and the prelogin route, in an extension grant's `ProviderAPI`, at end-session, at the owner routes that update, delete or rotate a client, and in `ClientManager.UpdateClient` and `SetClientCredentialsScopes`; a client resolved once in a request is not resolved again. A discovered client has no owner, so the owner routes answer 401. `/oauth2/client/rotate-keys` refuses it, since its keys belong to its published metadata, and setting its machine scopes leaves `updatedAt` alone, so an admin edit cannot extend how long its stored document is served.

The provider marks the resolved client in the request's context, which a store reads with `oauthprovider.ResolvedDiscovery`, where another runtime hands its stores the resolved record: Go stores re-read and lock the client in their own transactions. A store serves a row a discovery owns only when the context names that discovery, so a custom store that ignores the marker serves no discovered client. Some reads reach a client through a token or a consent, so the request never named it: opaque and signed introspection, UserInfo and `/oauth2/update-consent`. There the store answers `*oauthprovider.UnresolvedClientError` for a discovered client the request has not resolved; the provider resolves it outside the store's transaction and repeats the read once. A client still unresolved makes the token inactive, UserInfo answer `invalid_token` and the consent update answer 404 `client not found`, which is also what consent management without the provider answers, since the error matches `ErrClientNotFound`. There is no trusted-client cache before the database read; operator-managed clients are `ImmutableClientIDs`.

Each discovery's `Metadata` adds fields to the issuer documents under the provider's own, a later discovery winning, as another runtime merges them. A field the provider's document declares stays the provider's even when it is absent, except `client_id_metadata_document_supported`, which only a discovery publishes; an extension's `Metadata` cannot replace a discovery's field and sees them in `MetadataInput.Discovery`. Discovered clients are public, so `none` is advertised in `token_endpoint_auth_methods_supported` unless `Metadata.TokenAuthMethods` is set. Another runtime adds extensions from a companion plugin's init through `extendOAuthProvider`; in Go the host places them in `Options.Extensions`. [Discovery tests](../adapters/sqlstore/oauth_client_discovery_test.go) · [Metadata tests](../plugins/oauthprovider/issuer_metadata_test.go)

## Read client metadata documents

`oauthprovider.ParseClientMetadataDocument` reads a client's metadata as a client discovery publishes it, such as a client ID metadata document, as another runtime's `oauthClientMetadataSchema` does. The registration request rules apply, with the same error codes, except that `skip_consent` is kept as an ordinary member. `client_id` must be a nonempty string, `client_secret` a string, and `client_secret_expires_at` and `client_id_issued_at` non-negative integers; anything but a JSON object is refused with `metadata document is not a JSON object`. Members outside the vocabulary are kept raw in `Extensions`, and `MarshalJSON` writes them back without letting one replace a typed member. Type errors use the registration wording, such as `invalid value for client_uri`, not the other runtime's schema library text.

`oauthprovider.IsForbiddenMetadataDocumentField` reports the 36 server-owned names, in wire and storage spellings, that a client ID metadata document must not carry, matched exactly and case-sensitively. [Document tests](../plugins/oauthprovider/client_metadata_document_test.go)

A client discovery registers the documents it resolves under the registration rules, with these changes, as another runtime does. A document cannot name a back-channel logout target or use a shared secret, so `token_endpoint_auth_method` must be `none`, the default, or `private_key_jwt`, and no secret is issued. An omitted `application_type` stays empty, and the redirect URIs may then take any web or native form. One mutual grant is enough and the whole declared list is stored, since one document serves every issuer the client uses. The client gets the registration scopes and `Registration.DefaultResources`, never resources the document names. A `jwks_uri` must be on an explicitly trusted origin, on the client ID's origin, or allowed by the discovery's `AllowCrossOriginJWKSURI`; a hook error refuses it and is logged. That origin rule runs after the other checks, so the hook is asked only about an otherwise valid document. [Registration tests](../plugins/oauthprovider/client_discovery_test.go)
