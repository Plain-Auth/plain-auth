# OpenID Connect UserInfo

Clients can read a user's current profile at `GET /api/auth/oauth2/userinfo` or `POST /api/auth/oauth2/userinfo`. Supply an access token granted the `openid` scope. The endpoint works with signed and opaque access tokens. It checks the issuing registration, the grant's audiences and any bound session before releasing claims. The returned `sub` identifies the user for that client. An OpenID Connect client should compare it with the subject of its validated ID token. [Issue and verify an ID token](oauth-authorization-code.md#receive-and-verify-an-openid-connect-id-token) · [OpenID Connect Core §5.3](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)

## Enable the endpoint

Apply the `oauth-provider` schema profile and install the provider plugin on your existing auth handler. For signed access tokens, also configure the JWT plugin with the issuer's public verification keys. A custom auth mount replaces `/api/auth` in both endpoint paths and proof targets. [Schema setup](schema.md) · [Signed and opaque access tokens](machine-tokens.md#check-whether-a-token-is-active)

## Call from Go

The Go client accepts the auth mount, the access token and an optional sender proof. Standard and extension claim values are returned as `json.RawMessage`. With an ordinary bearer token, pass an empty proof.

```go
api, err := client.New("https://auth.example.com/api/auth", nil)
if err != nil {
    return err
}
claims, headers, err := api.OAuthUserInfo(ctx, accessToken, "")
if err != nil {
    log.Printf("UserInfo challenge %q", headers.Get("WWW-Authenticate"))
    return err
}
var subject string
if err := json.Unmarshal(claims["sub"], &subject); err != nil {
    return err
}
if subject != verifiedIDTokenSubject {
    return errors.New("UserInfo subject differs from the ID token subject")
}
```

With `net/http` or another client, send `Authorization: Bearer <access_token>`. A POST also accepts `access_token` in an `application/x-www-form-urlencoded` body. Use one transport per request. For a key-bound token, send `Authorization: DPoP <access_token>` and a fresh `DPoP` header signed for the actual HTTP method and public UserInfo URL. Include the hash of the literal access token in `ath`. Pass that compact proof as the last argument to `OAuthUserInfo` when using the Go client. [Sender proof verification](oauth-resource-discovery.md#verify-a-sender-bound-access-token-on-a-protected-route)

## Choose profile claims

| Grant | Claims returned |
| --- | --- |
| `openid` | `sub`, including the issuer's pairwise identifier for a pairwise registration |
| `profile` | `name`, `picture`, `given_name`, `family_name` when defined |
| `email` | `email` and the boolean `email_verified` |

A stored opaque grant can also request individual claim names. For example, a grant with `openid` and a stored request for `email_verified` returns the subject and verification status. Signed grants select claims by scope. The profile is read when the endpoint is called. A single-word name has no derived given or family name. A missing picture is omitted. An empty stored name is returned as an empty string. [Cross-runtime tests](../conformance/oauth-userinfo.mjs)

Use `UserInfo.Extensions` for additive claims. The first extension to contribute a name wins. Use `UserInfo.CustomClaims` for operator-controlled overrides. Both hooks receive the account profile, the issuing registration, scopes, validated token claims and requested claim names. The endpoint always controls the final subject. An error from a hook prevents the profile from being released.

```go
provider, err := oauthprovider.New(oauthprovider.Options{
    PairwiseSecret: pairwiseSecret,
    UserInfo: oauthprovider.UserInfoOptions{
        CustomClaims: func(ctx context.Context, in oauthprovider.UserInfoInput) (map[string]any, error) {
            claims := map[string]any{}
            if slices.Contains(in.RequestedClaims, "locale") {
                if locale, ok := in.User.AdditionalField("locale"); ok {
                    claims["locale"] = locale
                }
            }
            return claims, nil
        },
    },
})
```

## Handle errors

| HTTP status | Meaning |
| --- | --- |
| 400 | Conflicting token transports, missing `openid` scope or a grant without a matching user |
| 401 | Missing, expired, revoked or inactive access token, or a missing or invalid sender proof |
| 415 | A POST supplied an unsupported request body media type |
| 429 | The configured UserInfo rate limit was exceeded |

Every 401 exposes `WWW-Authenticate` to browser JavaScript. A request without credentials receives both Bearer and DPoP challenges. A bound token presented as Bearer receives a DPoP challenge. When a request already uses DPoP, an invalid token also receives a DPoP challenge listing the accepted proof algorithms. Access-token validation runs before proof validation, and backend errors return a service failure. Successful responses use `Cache-Control: no-store`.

The default limit is 60 requests per minute when rate limiting is enabled. Set `UserInfo.RateLimit` to a custom rule, or supply an empty rule to select the host's global limit. [Claim and storage tests](../adapters/sqlstore/oauth_userinfo_test.go) · [Rate-limit tests](../adapters/sqlstore/oauth_introspection_test.go)
