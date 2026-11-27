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

## Verify a request

`VerifyRequest` checks a request rather than a raw token, as another runtime's `verifyAccessTokenRequest` does, and is the entry point to use when clients may send DPoP-bound tokens:

```go
claims, err := verifier.VerifyRequest(r.Context(), oauthprovider.ResourceRequestFrom(r, "https://api.example.com"), "read:post")
```

`ResourceRequestFrom` reads the first `Authorization` and `DPoP` headers and the method, and joins your API's public origin with the request URI, so a proxy in front of the API does not change the URL a proof must name. The `Authorization` scheme is `Bearer` or `DPoP`, matched without regard to case; an empty header answers 401 `missing authorization header` without a code, and any other scheme, or a token without one, `invalid_token` "authorization scheme must be Bearer or DPoP".

The token is then checked as `VerifyBearer` checks it, scopes included, so a missing scope is answered before the binding. A token whose `cnf` names a key must be sent with the `DPoP` scheme and a `DPoP` proof signed by that key for this method, URL and token, each proof spent once; a token without one must not use the `DPoP` scheme. A refused binding is 401 `invalid_token` or `invalid_dpop_proof` with the same descriptions as another runtime, and a replay store failure is a server error. `DPoP` in the options sets the proof age, the signing algorithms and the replay store, which defaults to memory for this verifier; pass the SQL store or a Redis store so every instance of the API spends a proof only once. [Request tests](../plugins/oauthprovider/access_token_verifier_test.go) · [Shared replay test](../adapters/sqlstore/oauth_resource_verifier_test.go)

## Scopes

Pass the scopes a route needs after the token. A token whose `scope` claim is not a list of scope tokens separated by single spaces answers `invalid_token` "access token scope claim is invalid"; an absent claim grants none. When scopes are missing, `VerifyBearer` answers 403 `insufficient_scope` naming all of them at once in `MissingScopes` and in the description "access token is missing required scope: …", so the client can request them together. A required scope that is not a valid scope token is a configuration error, returned before the token is read.

Scopes describe what a client may request; permissions are what your API enforces. Map one scope to one permission, or set `ScopeSatisfied` to decide when the granted scopes, given as a set, satisfy one required scope, for example a hierarchy where `files` satisfies `files:read`.

## Key caching

The verifier keeps the issuer's key set as another runtime does. A set is trusted for five minutes. A token naming a key the set lacks refetches it at most every 30 seconds, so made-up key IDs cannot make the verifier fetch on every request, and a newly published key verifies once that window passes. Concurrent requests share one fetch, each waiting at most five seconds. When a refetch fails, an expired set keeps serving tokens it can verify for up to ten minutes after it was fetched; past that, or for a key it lacks, verification fails with an error that is not a `*ResourceFailure`, which your API should answer as a server error. A key set must be a JSON document of at most 64 KiB, fetched without redirects; one carrying private key members is refused, and keys that cannot verify are skipped. The cache belongs to the verifier rather than to the process. [Verifier tests](../plugins/oauthprovider/access_token_verifier_test.go) · [Cache tests](../plugins/oauthprovider/resource_keys_test.go) · [Cross-runtime test](../conformance/resource-verifier.mjs)
