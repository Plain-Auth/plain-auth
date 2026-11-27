# Protect your API

A resource server is the API that receives the access tokens your OAuth clients obtain. `oauthprovider.NewAccessTokenVerifier` checks the signed access tokens the provider issues for a resource, with the issuer's published keys, in your API or in another service. [Discovery](oauth-resource-discovery.md) · [Resources](oauth-resource-management.md) · [Feature checklist](parity/plugins/oauth-provider.md)

## Verify a bearer access token

```go
verifier, err := oauthprovider.NewAccessTokenVerifier(oauthprovider.AccessTokenVerifierOptions{
    Issuer:         "https://auth.example.com/api/auth",
    Audience:       []string{"https://api.example.com"},
    JWKSURL:        "https://auth.example.com/api/auth/jwks",
    RequiredClaims: []string{"azp"},
})
// For each request:
claims, err := verifier.VerifyBearer(r.Context(), token, "read:post")
```

Build one verifier per API and share it across routes; it caches the issuer's keys. `NewAccessTokenVerifier` checks its options once: an issuer, at least one audience, a JWKS URL over HTTPS or HTTP on loopback, and no empty required claim name.

`VerifyBearer` returns the token's claims, with `azp` copied to `client_id`, as another runtime's `verifyBearerToken` does. A token must be a JWS signed with an asymmetric algorithm by a key in the issuer's set; carry a `typ` header of `at+jwt`, compared as a media type, or the `Type` you set; and have `iss` equal to `Issuer`, an `aud` naming one of `Audience`, every `RequiredClaims` name and a numeric `exp`. `nbf`, when present, must have passed, and `iat` must be a number. An expired token answers `token expired`, any other failure `invalid access token`, both as a `*ResourceFailure` with status 401 and code `invalid_token`. A value that is not a JWS, such as an opaque token, answers `no token payload`, and an empty token 401 `missing authorization header` without a code.

`typ` defaults to `at+jwt` and `exp` is required, where another runtime checks the type only when asked and accepts a token without `exp`: otherwise a session JWT signed with the same key would pass whenever its `iss` and `aud` match. `RequiredClaims: []string{"azp"}` additionally rejects any JWT not issued to an OAuth client. A DPoP-bound token, one whose `cnf` names a `jkt`, is refused with `invalid_token`, since only the request can prove the client holds the key: use `VerifyRequest`.

## An API in the same process

Pass the auth instance as `Auth` when the API runs beside it, as another runtime's resource client does. `Issuer` defaults to the issuer the instance signs with, its configured JWT issuer or else its public auth URL. With the jwt plugin keeping its own keys, the verifier reads them in process, with no request to `/jwks`, under the same caching windows, so a rotated key is seen once the refetch window passes; `Auth.LocalJWKS` reports this case. With a `RemoteJWKSURL`, keys are fetched from it. `Remote.IntrospectionURL` defaults to the instance's `/oauth2/introspect`. Without the jwt plugin and without `Remote`, `NewAccessTokenVerifier` refuses, since opaque tokens need introspection.

```go
verifier, err := oauthprovider.NewAccessTokenVerifier(oauthprovider.AccessTokenVerifierOptions{
    Auth:           auth,
    Audience:       []string{"https://api.example.com"},
    RequiredClaims: []string{"azp"},
})
```

`Audience` is never defaulted, where another runtime defaults it to the auth base URL: a token must name your API, so a session JWT for the auth server itself cannot pass. [Defaults test](../conformance/goapi/resource_verifier_test.go) · [Three-database test](../adapters/sqlstore/oauth_resource_verifier_test.go)

## Verify a request

`VerifyRequest` checks a request rather than a raw token, as another runtime's `verifyAccessTokenRequest` does, and is the entry point to use when clients may send DPoP-bound tokens:

```go
claims, err := verifier.VerifyRequest(r.Context(), oauthprovider.ResourceRequestFrom(r, "https://api.example.com"), "read:post")
```

`ResourceRequestFrom` reads the `Authorization` and `DPoP` headers, joining repeated values with ", " as a fetch request does so two proofs fail as one malformed proof, and the method, and joins your API's public origin with the request URI, so a proxy in front of the API does not change the URL a proof must name. The `Authorization` scheme is `Bearer` or `DPoP`, matched without regard to case; an empty header answers 401 `missing authorization header` without a code, and any other scheme, or a token without one, `invalid_token` "authorization scheme must be Bearer or DPoP".

The token is then checked as `VerifyBearer` checks it, scopes included, so a missing scope is answered before the binding. A token whose `cnf` names a key must be sent with the `DPoP` scheme and a `DPoP` proof signed by that key for this method, URL and token, each proof spent once; a token without one must not use the `DPoP` scheme. A refused binding is 401 `invalid_token` or `invalid_dpop_proof` with the same descriptions as another runtime, and a replay store failure is a server error. `DPoP` in the options sets the proof age, the signing algorithms and the replay store, which defaults to memory for this verifier; pass the SQL store or a Redis store so every instance of the API spends a proof only once. [Request tests](../plugins/oauthprovider/access_token_verifier_test.go) · [Shared replay test](../adapters/sqlstore/oauth_resource_verifier_test.go)

## Protect a route

`Handler` wraps a route with `VerifyRequest` and its required scopes, and answers each failure with the challenge another runtime's resource client throws:

```go
protected, err := verifier.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    claims, _ := oauthprovider.AccessTokenClaims(r.Context())
    fmt.Fprintf(w, "hello %v", claims["sub"])
}), "read:post")
mux.Handle("GET /posts", protected)
```

| Failure | Response |
| --- | --- |
| No token | 401 with a `Bearer` challenge naming each audience's `resource_metadata`, without an error code |
| A presented token that fails | 401 `invalid_token` with its description, in the scheme the client used |
| A DPoP proof failure, or a bound token sent as `Bearer` | 401 with a `DPoP` challenge listing the accepted algorithms |
| Missing scopes | 403 `insufficient_scope` naming them, in the presented scheme |
| Any other error | logged, then 500 with `introspection failed` or `access token verification failed` |

Every challenge also sets `Access-Control-Expose-Headers: WWW-Authenticate` and a JSON body with the message, error and description, so a browser client can read it. A verified request reaches the route with its claims, read with `AccessTokenClaims`. Proofs are checked against `Origin`, the API's public origin, which defaults to the origin of the first HTTP or HTTPS audience and never comes from the request's `Host`. An audience that is not a URL needs an entry in `MetadataMappings` pointing at its metadata document. `Handler` refuses an invalid scope, an unmapped audience or a missing origin when it is built, where another runtime fails each request. [Handler tests](../plugins/oauthprovider/access_token_handler_test.go) · [Cross-runtime test](../conformance/resource-verifier.mjs)

## Scopes

Pass the scopes a route needs after the token. A token whose `scope` claim is not a list of scope tokens separated by single spaces, `null` included, answers `invalid_token` "access token scope claim is invalid"; an absent claim grants none. When scopes are missing, `VerifyBearer` answers 403 `insufficient_scope` naming all of them at once in `MissingScopes` and in the description "access token is missing required scope: …", so the client can request them together. A required scope that is not a valid scope token is a configuration error, returned before the token is read.

Scopes describe what a client may request; permissions are what your API enforces. Map one scope to one permission, or set `ScopeSatisfied` to decide when the granted scopes, given as a set, satisfy one required scope, for example a hierarchy where `files` satisfies `files:read`.

## JWT or opaque tokens

The provider issues a signed access token when the request names a `resource` and the jwt plugin is enabled, and an opaque one otherwise. A verifier with `JWKSURL` checks signed tokens locally, with no call to the issuer, but cannot see that a session ended: a signed token passes until it expires. An opaque token answers `no token payload` unless the verifier also introspects.

To accept opaque tokens, or to see ended sessions, set `Remote`:

```go
verifier, err := oauthprovider.NewAccessTokenVerifier(oauthprovider.AccessTokenVerifierOptions{
    Issuer:   "https://auth.example.com/api/auth",
    Audience: []string{"https://api.example.com"},
    JWKSURL:  "https://auth.example.com/api/auth/jwks",
    Remote: &oauthprovider.RemoteVerification{
        IntrospectionURL: "https://auth.example.com/api/auth/oauth2/introspect",
        ClientID:         apiClientID,
        ClientSecret:     apiClientSecret,
    },
})
```

Register the API as a client with `client_secret_post`, since the credentials travel in the form, and [link it to its resource](oauth-resource-management.md) so introspection answers for tokens issued to other clients. With `Remote`, every token is introspected after the local check, as another runtime's `remoteVerify` does: the form carries `client_id`, `client_secret`, the token and `token_type_hint=access_token`. The response replaces the local claims; `active` must be JSON `true`, where another runtime accepts any truthy value, or the token answers `invalid_token` "token inactive". Its `iss`, `aud` and required claims are checked as a local token's are, without `typ`, which an introspection response cannot carry, and with `exp` optional, as RFC 7662 allows. A response without `aud` is refused unless `AllowMissingAudience` is set; a mismatched `aud` is always refused. `Force` skips the local check, and so the `typ` check; keep it off so a session JWT signed with the same key still fails. A failed call, a status outside 2xx or a response that is not a JSON object of at most 64 KiB is a server error, which keeps the status but never the secret. `IntrospectionURL` must use HTTPS, or HTTP on loopback, since the request carries the API's secret. `JWKSURL` may be left empty to introspect every token. [Remote tests](../plugins/oauthprovider/access_token_verifier_test.go) · [Three-database test](../adapters/sqlstore/oauth_resource_verifier_test.go)

## Key caching

The verifier keeps the issuer's key set as another runtime does. A set is trusted for five minutes. A token naming a key the set lacks refetches it at most every 30 seconds, so made-up key IDs cannot make the verifier fetch on every request, and a newly published key verifies once that window passes. Concurrent requests share one fetch, each waiting at most five seconds. When a refetch fails, an expired set keeps serving tokens it can verify for up to ten minutes after it was fetched; past that, or for a key it lacks, verification fails with an error that is not a `*ResourceFailure`, which your API should answer as a server error. A key set must be a JSON document of at most 64 KiB, fetched without redirects; keys that cannot verify are skipped. An answer that is not a usable set, without a `keys` array or with private key members, is cached like a set and fails tokens as an outage, as another runtime caches what the issuer answered, rather than letting an expired set keep serving. A request whose context ends while it waits for a refetch gets the context's error rather than the expired set. A token whose `kid` header is empty names no key and is refused. The cache belongs to the verifier rather than to the process. [Verifier tests](../plugins/oauthprovider/access_token_verifier_test.go) · [Cache tests](../plugins/oauthprovider/resource_keys_test.go) · [Cross-runtime test](../conformance/resource-verifier.mjs)
