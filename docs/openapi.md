# OpenAPI reference

Install `plugins/openapi` to publish an OpenAPI 3.1.1 document for your configured Plain Auth handler. The document and reference page are public GET endpoints. Mount them behind application middleware if your deployment requires a private reference.

```go
import (
    "github.com/Plain-Org/plain-auth"
    "github.com/Plain-Org/plain-auth/plugins/openapi"
)

// Start with the application's configured store, secret, public URL and plugins.
func withReference(options plainauth.Options) (*plainauth.Auth, error) {
    reference, err := openapi.New(openapi.Options{Path: "/manual", Theme: "solarized"})
    if err != nil {
        return nil, err
    }
    options.Plugins = append(options.Plugins, reference)
    return plainauth.New(options)
}
```

Under the default mount, the schema is at `/api/auth/open-api/generate-schema` and the default page is at `/api/auth/reference`. The example serves its page at `/api/auth/manual`. A custom `BasePath` changes both URLs. The document's `servers[0].url` uses the configured public origin and mount. An application can also call `openapi.Generate(auth)` to obtain a fresh document or supply the schema URL as a source in an existing documentation site.

## What the document describes

Only installed HTTP operations appear. The inventory reflects configuration such as email/password signup, deferred session refresh, social providers, username display fields, team management, and separately enabled billing routes. Registered OAuth callbacks use `/callback/{id}`. Email credentials accept JSON and form data, and OAuth form callbacks accept `application/x-www-form-urlencoded`.

Each operation carries one tag. Built-in operations use `Default`, and plugin operations use the plugin ID with its first letter capitalized, such as `Two-factor`; the document's `tags` list describes the `Default` group. [Tag tests](../plugins/openapi/openapi_test.go)

The `User`, `Session` and linked `Account` models describe public Go response fields. Dates use the `date-time` format. Enabled model sets include organization, team, passkey, API-key and subscription records. The common error response requires a message and allows an optional code. Custom session projections and provider-specific or otherwise unconstrained results have an open response schema.

The organization and team selection operations return the selected model or JSON `null`. Omitting the selector uses the session's current choice. Supplying a null ID clears the choice. When the host enables the OAuth post-login selection policy, these operations also describe the signed `oauth_query` input, the JSON destination, and a 302 for browser navigation. [Organization and team selection](organizations.md#switch-organizations-and-teams-from-any-client)

The document declares the actual session cookie name, including its configured prefix. The bearer plugin adds bearer tokens as an alternative on session-protected operations. Public signup and login have no session credential requirement. Stripe webhooks declare the signature header. Application-specific authorization rules, roles, scoped API keys and conditional second-factor challenges still apply at runtime.

With enterprise OIDC installed, the reference describes registration, list, lookup, deletion and browser sign-in. The registration request marks the client secret as write-only. Its confidential administration response can echo the submitted OIDC credentials. The public schema lists safe response fields, and the list and lookup handlers return the masked client ID. Sign-in returns an authorization URL. The provider-specific and shared callbacks document the browser binding cookie, query parameters and HTTP 302 destination. [Enterprise provider management](sso.md)

When enterprise DNS verification is enabled, both management operations require a JSON body containing `providerId` and a direct session belonging to the personal directory creator or a current organization owner or administrator. Requesting a challenge returns HTTP 201 with a `domainVerificationToken` string. Successful verification returns HTTP 204 with an empty body. [Enterprise DNS verification](sso.md#verify-directory-domains-with-dns)

## Configured profile fields

The public `User` schema lists the logical names of returned fields. Server-owned values are read-only. A hidden field that accepts input appears as write-only in the request schema. Physical column names, private defaults and host-only hidden fields stay private.

Email signup requires each writable field marked `Required` that has no default. Owner updates accept partial changes. For administrative creation the same registration fields belong in `data`. Email OTP sign-in and phone verification describe these inputs only when they can register a new account. Returning users can sign in with their proof alone. A field named `otp` or `code` keeps its credential meaning on its verification route. Use JSON to supply integer, boolean or null values. [Configure profile fields](user-fields.md)

## Custom operations

Attach JSON OpenAPI operation metadata to a `plainauth.Endpoint`. It can declare `parameters`, `requestBody`, `responses`, `security`, tags and an operation ID; tags in the metadata replace the plugin tag. Supply a unique operation ID and valid OpenAPI metadata. Root-relative `$ref` values may name public models included in the document. These declarations describe the handler. The handler implements validation and authorization. The generated success response uses `Endpoint.SuccessStatus`, which defaults to 200. A 204 response has no content schema. Explicit `responses` metadata replaces the generated response map.

```go
endpoint := plainauth.Endpoint{
    Method: http.MethodGet,
    Path:   "/service-status",
    OpenAPI: json.RawMessage(`{
        "operationId": "getServiceStatus",
        "responses": {
            "200": {
                "description": "Current service availability",
                "content": {"application/json": {"schema": {"type": "boolean"}}}
            }
        }
    }`),
    Handler: func(plainauth.EndpointContext) (any, error) { return true, nil },
}
```

## Reference page

| Option | Effect |
| --- | --- |
| `Path` | Changes the page path relative to the auth mount. Defaults to `/reference`. |
| `DisableDefaultReference` | Serves the JSON schema alone. |
| `Theme` | Selects `default`, `alternate`, `moon`, `purple`, `solarized`, `bluePlanet`, `saturn`, `kepler`, `mars`, `deepSpace`, `laserwave` or `none`. Defaults to `default`. |
| `Nonce` | Sets the CSP nonce on the page's script and style. The default generates a fresh random nonce for each response. |

The self-contained page filters operations by method or path and expands each operation's JSON. A link such as `/api/auth/reference?q=sign-in` opens a filtered view. All assets are local. The response applies a nonce-based content security policy that allows connections only to the page's own origin, blocks embedding and escapes operation metadata as text.

Each operation also has a request panel. Edit the path to fill in path parameters or add a query string, edit the JSON body, and select **Send request**. The page sends the request to its own origin with the viewer's cookies and shows the status and response body. It sends nothing until a button is selected and never takes request values from its URL. The panel takes a raw path and JSON body instead of generated parameter forms, and it reports a redirect instead of following it. [Browser request test](../conformance/openapi-reference-page.mjs)

With the phone-number plugin installed, the document includes the five public phone operations and the two nullable phone profile fields. Verification accepts signed-out requests and documents the direct-session requirement for account linking. The user update schema accepts a null phone number to remove it. Password and code inputs are write-only. Installing two-factor authentication adds its challenge response to phone login and verification. [Phone-number guide](phone-number.md)
