# OpenAPI

[Feature index](../README.md)

## Interfaces

- [ ] OpenAPI endpoints, types and options
  - `FieldSchema` — *not applicable: TypeScript type*
  - `OpenAPIModelSchema` — *not applicable: TypeScript type*
  - `Path` — *not applicable: TypeScript type*
  - [ ] `generator`
  - `OpenAPISchema` — *not applicable: TypeScript type*
  - `OpenAPIParameter` — *not applicable: TypeScript type*
  - [x] `GET /open-api/generate-schema` ([test](../../../plugins/openapi/openapi_test.go#L88))
    - [x] Describe the optional signed social login field and the callback’s JSON, navigation and popup responses for the installed configuration ([test](../../../plugins/openapi/profile_test.go#L23))
    - [x] Describe enterprise provider management, redacted reads, browser sign-in and both bound callback routes against the configured SQL handler ([test](../../../plugins/openapi/sso_directory_test.go#L24))
    - [x] Describe the enabled enterprise DNS management inputs, outputs and session credentials ([test](../../../plugins/openapi/sso_domain_test.go#L28))
    - [x] Publish declared success codes, empty 204 responses and explicit operation overrides while preserving redirects ([test](../../../plugins/openapi/endpoint_status_test.go#L12))
    - [x] Serve the mounted versioned JSON document and match required fields for core and username operations ([test](../../../conformance/openapi-contract.mjs#L48))
    - [x] Expose the actual response fields, cookie name, optional bearer scheme and custom operation metadata ([test](../../../plugins/openapi/openapi_test.go#L76))
    - [x] Resolve every local schema reference and suppress unavailable routes for a configured SQL-backed instance ([test](../../../plugins/openapi/profile_test.go#L192))
    - [x] Describe the public user model and writable registration fields across owner updates, administrative creation and first OTP sign-in ([test](../../../plugins/openapi/user_fields_test.go#L21))
    - [x] Compare both live schema endpoints and verify required signup inputs, partial profile updates and hidden response fields ([test](../../../conformance/openapi-contract.mjs#L64))
    - [x] Describe date-time fields in public models, JSON input and email signup form input ([test](../../../plugins/openapi/user_fields_test.go#L178))
    - [x] GET /open-api/generate-schema answers 200 application/json with OpenAPI 3.1.1 and the mounted server URL, lists installed routes and leaves disabled ones out ([test](../../../plugins/openapi/openapi_test.go#L88))
  - [x] `GET /reference (configurable)` ([test](../../../plugins/openapi/openapi_test.go#L172))
    - [x] Filter a local interactive reference in headless Chrome under its nonce policy ([test](../../../plugins/openapi/openapi_test.go#L231))
    - [x] Serve an HTML page at a configured path with the chosen theme, nonce and CSP, answer 404 at /reference when the page is disabled, and keep serving the JSON schema ([test](../../../plugins/openapi/openapi_test.go#L172))
    - [x] Leave /reference and /open-api/generate-schema out of the generated document's paths ([test](../../../plugins/openapi/openapi_test.go#L92))
    - [x] With default options, serve the API reference page at /reference beneath the auth mount ([test](../../../plugins/openapi/sso_domain_test.go#L76))
  - [ ] `OpenAPIOptions`
    - [x] `path` ([test](../../../plugins/openapi/sso_domain_test.go#L76))
      - [x] Serve the page at an application-selected path beneath the configured auth mount ([test](../../../plugins/openapi/openapi_test.go#L177))
      - [x] With no path configured, serve the API reference page at /reference beneath the auth mount ([test](../../../plugins/openapi/sso_domain_test.go#L76))
    - [x] `disableDefaultReference` ([test](../../../plugins/openapi/sso_domain_test.go#L76))
      - [x] Disable the reference page while continuing to serve its JSON schema ([test](../../../plugins/openapi/openapi_test.go#L184))
      - [x] Serve the API reference page when DisableDefaultReference is left unset ([test](../../../plugins/openapi/sso_domain_test.go#L76))
    - [ ] `theme`
      - [x] Apply a configured theme in the rendered browser page ([test](../../../plugins/openapi/openapi_test.go#L231))
    - [x] `nonce` ([test](../../../plugins/openapi/openapi_test.go#L231))
      - [x] Apply the configured nonce to inline scripts and styles and send the matching CSP ([test](../../../plugins/openapi/openapi_test.go#L177))
      - [x] With no nonce configured, headless Chrome still runs the served page's inline filter script and hides the operations that do not match the query ([test](../../../plugins/openapi/openapi_test.go#L231))
  - [x] `openAPI` ([test](../../../plugins/openapi/openapi_test.go#L172))
    - [x] openapi.New installs the JSON schema route and an HTML page at the configured path, omits the page when disabled, and refuses an invalid path, nonce or theme ([test](../../../plugins/openapi/openapi_test.go#L172))
    - [x] With default options, openapi.New serves the page at /reference beneath the auth mount ([test](../../../plugins/openapi/sso_domain_test.go#L76))

## Open API

- [ ] Open API
  - [ ] Usage
    - [x] Generated Schema ([test](../../../plugins/openapi/openapi_test.go#L194))
      - [x] Return the public document from its mounted HTTP endpoint ([test](../../../conformance/openapi-contract.mjs#L28))
      - [x] openapi.Generate returns the document for a configured instance directly from Go, and each concurrent caller gets its own copy ([test](../../../plugins/openapi/openapi_test.go#L194))
    - [x] Using Scalar with Multiple Sources ([test](../../../plugins/openapi/organization_role_fields_test.go#L50))
      - [x] GET /api/auth/open-api/generate-schema under the default mount answers 200 with a JSON document ([test](../../../plugins/openapi/organization_role_fields_test.go#L50))
  - [ ] Configuration
    - [x] `path` ([test](../../../plugins/openapi/sso_domain_test.go#L76))
      - [x] With no path configured, serve the API reference page at /reference beneath the auth mount ([test](../../../plugins/openapi/sso_domain_test.go#L76))
      - [x] Serve the API reference page at a configured path beneath the configured auth mount ([test](../../../plugins/openapi/openapi_test.go#L177))
    - [x] `disableDefaultReference` ([test](../../../plugins/openapi/openapi_test.go#L184))
      - [x] With DisableDefaultReference set, answer 404 at /reference while the JSON schema stays available ([test](../../../plugins/openapi/openapi_test.go#L184))
      - [x] Serve the API reference page when DisableDefaultReference is left unset ([test](../../../plugins/openapi/sso_domain_test.go#L76))
    - [ ] `theme`
    - [x] `nonce` ([test](../../../plugins/openapi/openapi_test.go#L177))
      - [x] Put a configured nonce attribute in the served page and send a Content-Security-Policy header that names the same nonce ([test](../../../plugins/openapi/openapi_test.go#L177))
      - [x] With no nonce configured, headless Chrome still runs the served page's inline filter script and hides the operations that do not match the query ([test](../../../plugins/openapi/openapi_test.go#L231))
